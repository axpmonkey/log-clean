package pipeline

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sas-log-sanitize/internal/archive"
	ioenc "sas-log-sanitize/internal/io"
	"sas-log-sanitize/internal/runlog"
)

// DefaultMaxExtractBytes caps the total bytes extracted from archives in one
// run (a guard against decompression bombs) when RunOptions leaves it 0.
const DefaultMaxExtractBytes int64 = 20 << 30 // 20 GiB

// inputFile is one file to sanitize.
type inputFile struct {
	// src is where the bytes are read from: the input file itself, or its
	// extracted copy in the run's temporary directory.
	src string
	// rel is the output path relative to the output directory. A file from
	// an archive lives under a folder named after the archive
	// ("bundle.zip" -> "bundle/logs/catalina.out").
	rel string
	// gz marks a gzip-compressed file: read decompressed, written back
	// gzip-compressed under the same name.
	gz bool
	// har is set by Pass 1 when the file parsed as a HAR, so Pass 2 streams
	// it through the HAR handler too.
	har bool
	// masks is Pass 1's detector-mask sidecar for Pass 2 ("" = none; Pass
	// 2 then runs every detector on every line).
	masks string
}

// discovery walks the input and collects files to process.
type discovery struct {
	root    string
	single  bool
	log     *runlog.Logger
	tmpDir  func() (string, error)
	budget  int64
	files   []inputFile
	skipped []SkippedFile
}

// discoverFiles walks root (a directory, or a single file), returning the
// files to sanitize sorted by output path (Decision 1: deterministic order
// for stable token numbering) and the files skipped, with reasons.
//
// Binary files are skipped by extension or content sniffing (Decision 9).
// *.gz files are kept and read transparently. .zip / .tar / .tar.gz / .tgz
// archives are extracted into tmpDir() and their entries processed under a
// folder named after the archive; unsafe or nested-archive entries are
// skipped (see package archive).
func discoverFiles(root string, tmpDir func() (string, error), maxExtract int64, log *runlog.Logger) ([]inputFile, []SkippedFile, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	if maxExtract <= 0 {
		maxExtract = DefaultMaxExtractBytes
	}
	d := &discovery{root: root, single: !info.IsDir(), log: log, tmpDir: tmpDir, budget: maxExtract}
	err = filepath.WalkDir(root, func(path string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		rel, _ := relFor(root, path, d.single)
		return d.add(path, rel, true)
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Slice(d.files, func(i, j int) bool { return d.files[i].rel < d.files[j].rel })
	sort.SliceStable(d.skipped, func(i, j int) bool { return d.skipped[i].RelPath < d.skipped[j].RelPath })
	return d.files, d.skipped, nil
}

func (d *discovery) skip(rel, reason string) {
	d.skipped = append(d.skipped, SkippedFile{RelPath: rel, Reason: reason})
	d.log.Info("skipped %s: %s", rel, reason)
}

// add classifies one file. topLevel is false for files extracted from an
// archive (nested archives were already refused by the extractor).
func (d *discovery) add(path, rel string, topLevel bool) error {
	kind := archive.KindOf(path)
	switch {
	case kind.IsArchive() && topLevel:
		return d.extract(path, rel, kind)
	case kind == archive.Gzip:
		head, err := gzipHead(path)
		if err != nil {
			d.skip(rel, fmt.Sprintf("unreadable gzip file: %v", err))
			return nil
		}
		if looksBinary(head) {
			d.skip(rel, "binary content detected (inside gzip)")
			return nil
		}
		d.files = append(d.files, inputFile{src: path, rel: rel, gz: true})
		return nil
	}

	if ioenc.IsSkippedExtension(path) {
		d.skip(rel, "binary file extension")
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	f.Close()
	if looksBinary(buf[:n]) {
		d.skip(rel, "binary content detected")
		return nil
	}
	d.files = append(d.files, inputFile{src: path, rel: rel})
	return nil
}

// looksBinary applies the binary-content heuristic. A UTF-16 BOM
// unambiguously signals text: UTF-16-encoded ASCII is roughly half NUL bytes
// and would otherwise trip IsBinary, skipping Windows SAS logs (Decision 8).
func looksBinary(head []byte) bool {
	enc, _ := ioenc.DetectBOM(head)
	if enc == ioenc.UTF16LE || enc == ioenc.UTF16BE {
		return false
	}
	return ioenc.IsBinary(head)
}

// gzipHead returns up to 512 decompressed bytes of a gzip file.
func gzipHead(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(bufio.NewReader(f))
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	n, err := io.ReadFull(zr, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, err
	}
	return buf[:n], nil
}

// extract unpacks an archive and adds its entries under
// "<archive path without extension>/". If the input already has a file or
// folder by that name, "_extracted" is appended so outputs can't collide.
func (d *discovery) extract(path, rel string, kind archive.Kind) error {
	base := archive.TrimExt(rel)
	if !d.single {
		if _, err := os.Stat(filepath.Join(d.root, base)); err == nil {
			base += "_extracted"
		}
	}
	tmp, err := d.tmpDir()
	if err != nil {
		return err
	}
	dest := filepath.Join(tmp, base)
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	before := dirSize(tmp)
	skipped, err := archive.Extract(path, kind, dest, d.budget)
	if err == archive.ErrTooLarge {
		return fmt.Errorf("extracting %s: %w (limit %d bytes)", rel, err, d.budget)
	}
	if err != nil {
		d.skip(rel, fmt.Sprintf("unreadable archive: %v", err))
		return nil
	}
	d.budget -= dirSize(tmp) - before
	for _, s := range skipped {
		d.skip(base+string(filepath.Separator)+filepath.FromSlash(s.Name), s.Reason)
	}
	d.log.Info("extracted %s (%d entries skipped)", rel, len(skipped))
	return filepath.WalkDir(dest, func(p string, e os.DirEntry, err error) error {
		if err != nil || e.IsDir() {
			return err
		}
		sub, err := filepath.Rel(dest, p)
		if err != nil {
			return err
		}
		return d.add(p, filepath.Join(base, sub), false)
	})
}

// dirSize sums regular-file sizes under dir.
func dirSize(dir string) int64 {
	var n int64
	filepath.WalkDir(dir, func(_ string, e os.DirEntry, err error) error {
		if err == nil && !e.IsDir() {
			if info, err := e.Info(); err == nil {
				n += info.Size()
			}
		}
		return nil
	})
	return n
}

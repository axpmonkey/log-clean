// Package archive classifies and safely extracts the compressed inputs that
// support bundles routinely contain: rotated *.gz logs (read transparently by
// the pipeline, not extracted here) and .zip / .tar / .tar.gz / .tgz
// archives (extracted to a temporary directory and sanitized like any other
// files).
//
// Extraction is defensive: entries with absolute paths, ".." traversal,
// drive letters, or anything other than a regular file or directory
// (symlinks, hard links, devices) are never written -- they are returned as
// skipped, with a reason, so the run can report them. Nested archives
// (.zip/.tar inside an archive) are skipped too; nested *.gz files are
// extracted and then read transparently like any other rotated log. A cap
// on total extracted bytes guards against decompression bombs.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Kind is the compressed-input kind of a file, decided by its name.
type Kind int

const (
	None  Kind = iota
	Gzip       // a single gzip-compressed file (catalina.2026-11-09.log.gz)
	Zip        // .zip
	Tar        // .tar
	TarGz      // .tar.gz / .tgz
)

// KindOf classifies path by its (case-insensitive) suffix.
func KindOf(p string) Kind {
	n := strings.ToLower(p)
	switch {
	case strings.HasSuffix(n, ".tar.gz"), strings.HasSuffix(n, ".tgz"):
		return TarGz
	case strings.HasSuffix(n, ".tar"):
		return Tar
	case strings.HasSuffix(n, ".zip"):
		return Zip
	case strings.HasSuffix(n, ".gz"):
		return Gzip
	}
	return None
}

// IsArchive reports whether k is a multi-file archive (extracted), as
// opposed to a single gzip-compressed file (read in place) or neither.
func (k Kind) IsArchive() bool { return k == Zip || k == Tar || k == TarGz }

// TrimExt strips the archive extension from name ("bundle.zip" -> "bundle",
// "logs.tar.gz" -> "logs").
func TrimExt(name string) string {
	n := strings.ToLower(name)
	for _, ext := range []string{".tar.gz", ".tgz", ".tar", ".zip"} {
		if strings.HasSuffix(n, ext) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

// Skipped is an archive entry that was not extracted.
type Skipped struct {
	Name   string // the entry name exactly as stored in the archive
	Reason string
}

// ErrTooLarge is returned when extraction would exceed the byte cap.
var ErrTooLarge = errors.New("archive extraction exceeds the size limit")

// Extract writes the regular-file entries of the archive at src (of kind k)
// under dest, which must exist. maxBytes caps the total bytes written.
func Extract(src string, k Kind, dest string, maxBytes int64) ([]Skipped, error) {
	x := &extractor{dest: dest, remaining: maxBytes}
	var err error
	switch k {
	case Zip:
		err = x.zip(src)
	case Tar, TarGz:
		err = x.tar(src, k == TarGz)
	default:
		return nil, fmt.Errorf("%s is not an archive", src)
	}
	return x.skipped, err
}

type extractor struct {
	dest      string
	remaining int64
	skipped   []Skipped
}

func (x *extractor) skip(name, reason string) {
	x.skipped = append(x.skipped, Skipped{Name: name, Reason: reason})
}

// target returns where entry name may be written, or "" (and records the
// skip) when the name is unsafe.
func (x *extractor) target(name string) string {
	n := strings.ReplaceAll(name, `\`, "/")
	clean := path.Clean(n)
	switch {
	case n == "" || strings.HasPrefix(n, "/") || filepath.IsAbs(n) || filepath.VolumeName(n) != "" ||
		(len(n) >= 2 && n[1] == ':'):
		x.skip(name, "archive entry with an absolute path (not extracted)")
		return ""
	case clean == ".." || strings.HasPrefix(clean, "../"):
		x.skip(name, "archive entry escaping the archive with '..' (not extracted)")
		return ""
	}
	t := filepath.Join(x.dest, filepath.FromSlash(clean))
	if t != x.dest && !strings.HasPrefix(t, x.dest+string(filepath.Separator)) {
		x.skip(name, "archive entry escaping the archive (not extracted)")
		return ""
	}
	return t
}

// write copies one regular-file entry to its target.
func (x *extractor) write(name string, r io.Reader) error {
	t := x.target(name)
	if t == "" {
		return nil
	}
	if KindOf(name).IsArchive() {
		x.skip(name, "nested archive (not extracted)")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(t), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(t, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(f, io.LimitReader(r, x.remaining+1))
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("extracting %s: %w", name, err)
	}
	if n > x.remaining {
		return ErrTooLarge
	}
	x.remaining -= n
	return nil
}

func (x *extractor) zip(src string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("opening %s: %w", src, err)
	}
	defer zr.Close()
	for _, f := range zr.File {
		mode := f.Mode()
		switch {
		case mode.IsDir():
			continue
		case !mode.IsRegular():
			x.skip(f.Name, "not a regular file (not extracted)")
			continue
		}
		rc, err := f.Open()
		if err != nil {
			x.skip(f.Name, fmt.Sprintf("unreadable archive entry: %v", err))
			continue
		}
		err = x.write(f.Name, rc)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (x *extractor) tar(src string, gz bool) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("opening %s: %w", src, err)
	}
	defer f.Close()
	var r io.Reader = bufio.NewReader(f)
	if gz {
		zr, err := gzip.NewReader(r)
		if err != nil {
			return fmt.Errorf("reading %s: %w", src, err)
		}
		defer zr.Close()
		r = zr
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading %s: %w", src, err)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
			if err := x.write(h.Name, tr); err != nil {
				return err
			}
		default:
			x.skip(h.Name, "not a regular file (not extracted)")
		}
	}
}

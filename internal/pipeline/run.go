package pipeline

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sas-log-sanitize/internal/audit"
	ioenc "sas-log-sanitize/internal/io"
	"sas-log-sanitize/internal/runlog"
	"sas-log-sanitize/internal/tokenize"
)

// RunOptions configures a full directory-to-directory sanitization run. The
// detector chain itself lives on the *Pipeline passed to Run, not here --
// RunOptions only carries the things that are about the run, not about what
// gets detected.
type RunOptions struct {
	InputDir     string
	OutputDir    string
	AuditEnabled bool
	DryRun       bool
	ToolVersion  string
}

// RunResult summarizes a completed run.
type RunResult struct {
	FilesProcessed    int
	FilesSkipped      []SkippedFile
	BytesProcessed    int64
	AuditFindings     []audit.Finding
	Mapping           tokenize.MappingFile
	ReplacementCounts map[string]int
}

// SkippedFile records a file that was not processed, and why.
type SkippedFile struct {
	RelPath string
	Reason  string
}

type loadedFile struct {
	relPath string
	enc     ioenc.Encoding
	hadBOM  bool
	ending  ioenc.LineEnding
	lines   []string
}

// Run discovers every file under opts.InputDir (in deterministic,
// alphabetical-by-path order per plan Decision 1), then performs the
// two-pass sanitization: Pass 1 (ScanLine) over every line of every file
// builds the token registry, Pass 2 (ReplaceLine) writes sanitized output
// (mirroring the input's relative directory structure under opts.OutputDir)
// and re-scans it with the audit package. In --dry-run mode, nothing is
// written to disk, but both passes still run so the caller gets accurate
// stats and audit findings.
//
// opts.InputDir may itself be a single file rather than a directory (e.g. a
// lone log file instead of a whole bundle) -- in that case the sole
// "relative path" is just the file's own base name, since
// filepath.Rel(file, file) would otherwise yield "." and collide with
// opts.OutputDir itself when building the output path.
func Run(p *Pipeline, opts RunOptions, log *runlog.Logger) (RunResult, error) {
	inputInfo, err := os.Stat(opts.InputDir)
	if err != nil {
		return RunResult{}, fmt.Errorf("statting %s: %w", opts.InputDir, err)
	}
	singleFile := !inputInfo.IsDir()

	paths, skipped, err := discoverFiles(opts.InputDir, log)
	if err != nil {
		return RunResult{}, fmt.Errorf("discovering files in %s: %w", opts.InputDir, err)
	}

	var loaded []loadedFile
	var bytesProcessed int64
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return RunResult{}, fmt.Errorf("reading %s: %w", path, err)
		}
		bytesProcessed += int64(len(data))

		enc, skip := ioenc.DetectBOM(data)
		hadBOM := skip > 0
		if !hadBOM {
			enc = ioenc.DetectNoBOM(data)
		}

		lr := ioenc.NewLineReader(bytes.NewReader(data[skip:]), enc)
		var lines []string
		var ending ioenc.LineEnding
		for {
			line, le, err := lr.ReadLine()
			if err == io.EOF {
				break
			}
			if err != nil {
				return RunResult{}, fmt.Errorf("reading lines from %s: %w", path, err)
			}
			lines = append(lines, line)
			ending = le
		}

		var rel string
		if singleFile {
			rel = filepath.Base(path)
		} else {
			rel, err = filepath.Rel(opts.InputDir, path)
			if err != nil {
				return RunResult{}, fmt.Errorf("computing relative path for %s: %w", path, err)
			}
		}
		loaded = append(loaded, loadedFile{relPath: rel, enc: enc, hadBOM: hadBOM, ending: ending, lines: lines})

		for _, line := range lines {
			p.ScanLine(line)
		}
		log.Verbose("scanned %s: %d lines, encoding %s", rel, len(lines), enc)
	}
	log.Info("pass 1 complete: %d files scanned, %d bytes", len(loaded), bytesProcessed)

	scanner := audit.NewScanner()
	scanner.Ignore = p.Ignore
	var findings []audit.Finding
	for _, lf := range loaded {
		if err := replaceAndWriteFile(p, lf, opts, scanner, &findings, log); err != nil {
			return RunResult{}, err
		}
	}
	log.Info("pass 2 complete: %d files written", len(loaded))

	mf := p.Registry.ToMappingFile(opts.ToolVersion, opts.InputDir, tokenize.Stats{
		FilesProcessed:         len(loaded),
		BytesProcessed:         bytesProcessed,
		ReplacementsByCategory: p.ReplacementCounts(),
	})

	return RunResult{
		FilesProcessed:    len(loaded),
		FilesSkipped:      skipped,
		BytesProcessed:    bytesProcessed,
		AuditFindings:     findings,
		Mapping:           mf,
		ReplacementCounts: p.ReplacementCounts(),
	}, nil
}

func replaceAndWriteFile(p *Pipeline, lf loadedFile, opts RunOptions, scanner *audit.Scanner, findings *[]audit.Finding, log *runlog.Logger) error {
	var lw *ioenc.LineWriter
	var f *os.File
	if !opts.DryRun {
		outPath := filepath.Join(opts.OutputDir, lf.relPath)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("creating output directory for %s: %w", outPath, err)
		}
		var err error
		f, err = os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", outPath, err)
		}
		defer f.Close()
		lw = ioenc.NewLineWriter(f, lf.enc, lf.ending)
		if lf.hadBOM {
			if err := lw.WriteBOM(); err != nil {
				return fmt.Errorf("writing BOM for %s: %w", lf.relPath, err)
			}
		}
	}

	for i, line := range lf.lines {
		sanitized := p.ReplaceLine(line)
		if lw != nil {
			if err := lw.WriteLine(sanitized); err != nil {
				return fmt.Errorf("writing %s: %w", lf.relPath, err)
			}
		}
		if opts.AuditEnabled {
			*findings = append(*findings, scanner.ScanLine(lf.relPath, i+1, sanitized)...)
		}
	}
	if lw != nil {
		if err := lw.Flush(); err != nil {
			return fmt.Errorf("flushing %s: %w", lf.relPath, err)
		}
	}
	log.Verbose("replaced %s", lf.relPath)
	return nil
}

// discoverFiles walks root recursively, skipping binary files (by extension
// or content sniffing, per Decision 9), and returns the remaining file paths
// sorted alphabetically (Decision 1: pass 1 must process files in
// deterministic order for stable token numbering).
func discoverFiles(root string, log *runlog.Logger) ([]string, []SkippedFile, error) {
	var files []string
	var skipped []SkippedFile

	rootInfo, err := os.Stat(root)
	if err != nil {
		return nil, nil, err
	}
	singleFile := !rootInfo.IsDir()

	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		var rel string
		if singleFile {
			rel = filepath.Base(path)
		} else {
			var relErr error
			rel, relErr = filepath.Rel(root, path)
			if relErr != nil {
				rel = path
			}
		}

		if ioenc.IsSkippedExtension(path) {
			skipped = append(skipped, SkippedFile{RelPath: rel, Reason: "binary file extension"})
			log.Info("skipped %s: binary file extension", rel)
			return nil
		}

		f, openErr := os.Open(path)
		if openErr != nil {
			return fmt.Errorf("opening %s: %w", path, openErr)
		}
		buf := make([]byte, 512)
		n, _ := f.Read(buf)
		f.Close()

		// A UTF-16 BOM unambiguously signals text, not binary -- but
		// UTF-16-encoded ASCII is roughly half NUL bytes (the high byte of
		// each LE/BE code unit), which would otherwise trip IsBinary's
		// non-printable-ratio heuristic and cause Windows SAS logs (the
		// exact case Decision 8 calls out as "common for Windows SAS logs")
		// to be misdetected as binary and skipped entirely. Trust the BOM
		// and skip the heuristic check in that case.
		enc, _ := ioenc.DetectBOM(buf[:n])
		isUTF16 := enc == ioenc.UTF16LE || enc == ioenc.UTF16BE
		if !isUTF16 && ioenc.IsBinary(buf[:n]) {
			skipped = append(skipped, SkippedFile{RelPath: rel, Reason: "binary content detected"})
			log.Info("skipped %s: binary content detected", rel)
			return nil
		}

		files = append(files, path)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	sort.Strings(files)
	return files, skipped, nil
}

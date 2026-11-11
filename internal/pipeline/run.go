package pipeline

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"sas-log-sanitize/internal/audit"
	"sas-log-sanitize/internal/detect"
	"sas-log-sanitize/internal/har"
	ioenc "sas-log-sanitize/internal/io"
	"sas-log-sanitize/internal/runlog"
	"sas-log-sanitize/internal/tokenize"
)

// pemBlockRedactor tracks whether the current line falls inside a multi-line
// PEM/SSH private-key block. No single-line detector can see a key body (each
// Detect call gets one line in isolation), so the file-level scan/replace
// loops consult one of these -- fresh per file, so state can never leak
// across files -- to redact every line from the BEGIN marker through the END
// marker inclusive.
//
// It fails closed: a BEGIN with no matching END (a truncated log) leaves the
// redactor in-block through end of file, over-redacting rather than leaking
// the tail of a key.
type pemBlockRedactor struct{ inBlock bool }

// redacts reports whether line must be wholesale redacted -- either it is
// already inside an open key block, or it opens one -- and advances the
// state. A line that both opens and closes a block (a single-line key) is
// redacted and leaves the redactor closed.
func (r *pemBlockRedactor) redacts(line string) bool {
	if r.inBlock || detect.IsSSHPrivateKeyBegin(line) {
		r.inBlock = !detect.IsSSHPrivateKeyEnd(line)
		return true
	}
	return false
}

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
	// KeepHARBodies keeps (and scans) HAR response bodies instead of
	// dropping them.
	KeepHARBodies bool
	// Workers is how many files each pass processes in parallel (0 = one
	// per CPU). Output and token numbering don't depend on it.
	Workers int
	// Progress, if set, receives per-pass progress lines.
	Progress io.Writer
	// MaxExtractBytes caps the total bytes extracted from archives (0 =
	// DefaultMaxExtractBytes).
	MaxExtractBytes int64
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

// Run discovers every file under opts.InputDir (in deterministic,
// alphabetical-by-path order per plan Decision 1), then performs the
// two-pass sanitization: Pass 1 (ScanLine) over every line of every file
// builds the token registry, Pass 2 (ReplaceLine) writes sanitized output
// (mirroring the input's relative directory structure under opts.OutputDir)
// and re-scans it with the audit package. In --dry-run mode, nothing is
// written to disk, but both passes still run so the caller gets accurate
// stats and audit findings.
//
// The two passes each re-read the files from disk rather than caching every
// decoded line in memory between them: token numbering is stable because
// both passes visit files (and lines) in the same order, and re-reading
// keeps peak memory bounded by the single largest file instead of the whole
// bundle's combined size.
//
// opts.InputDir may itself be a single file rather than a directory (e.g. a
// lone log file instead of a whole bundle) -- in that case the sole
// "relative path" is just the file's own base name, since
// filepath.Rel(file, file) would otherwise yield "." and collide with
// opts.OutputDir itself when building the output path.
func Run(p *Pipeline, opts RunOptions, log *runlog.Logger) (RunResult, error) {
	if _, err := os.Stat(opts.InputDir); err != nil {
		return RunResult{}, fmt.Errorf("statting %s: %w", opts.InputDir, err)
	}

	// Archives are extracted into a private temporary directory, removed
	// when the run ends -- it holds unsanitized data.
	var tmp string
	defer func() {
		if tmp != "" {
			os.RemoveAll(tmp)
		}
	}()
	tmpDir := func() (string, error) {
		if tmp == "" {
			var err error
			if tmp, err = os.MkdirTemp("", "sas-log-sanitize-*"); err != nil {
				return "", fmt.Errorf("creating temporary directory for archives: %w", err)
			}
		}
		return tmp, nil
	}
	files, skipped, err := discoverFiles(opts.InputDir, tmpDir, opts.MaxExtractBytes, log)
	if err != nil {
		return RunResult{}, fmt.Errorf("discovering files in %s: %w", opts.InputDir, err)
	}

	var totalBytes int64
	for _, f := range files {
		if st, err := os.Stat(f.src); err == nil {
			totalBytes += st.Size()
		}
	}
	workers := workerCount(opts.Workers)
	env := newRunEnv(opts, log)

	// Pass 1: scan every file (in parallel) into its own registry, then
	// merge the registries in sorted-path order -- the same token numbering
	// a sequential scan would produce.
	locals := make([]*Pipeline, len(files))
	sizes := make([]int64, len(files))
	env.prog = startProgress(opts.Progress, 1, len(files), totalBytes)
	err = forEachFile(len(files), workers, func(i int) error {
		locals[i] = p.forkForScan()
		n, err := scanFile(locals[i], &files[i], env)
		sizes[i] = n
		env.prog.fileDone()
		return err
	})
	env.prog.finish()
	if err != nil {
		return RunResult{}, err
	}
	var bytesProcessed int64
	for i := range locals {
		p.Registry.Merge(locals[i].Registry)
		bytesProcessed += sizes[i]
	}
	log.Info("pass 1 complete: %d files scanned, %d bytes, %d workers", len(files), bytesProcessed, workers)

	// The registry is now complete: sweep every known USER/HOST value (and
	// each host's short name) out of the whole bundle in Pass 2.
	swept := p.EnableKnownValuesSweep()
	log.Info("known-values sweep: %d values", len(swept))

	// Pass 2: re-read each file, replace tokens, write output, and audit.
	scanner := audit.NewScanner()
	scanner.Ignore = p.Ignore
	scanner.IPv4SkipRanges = p.IPv4SkipRanges
	scanner.Known = detect.NewKnownValuesDetector(detect.AuditValues(tokenize.OrderedValues(p.Registry.Mapping())))
	// Pass 2: every file in parallel against the now read-only registry;
	// findings and counts are collected per file and combined in path
	// order, so they don't depend on scheduling either.
	perFile := make([][]audit.Finding, len(files))
	forks := make([]*Pipeline, len(files))
	env.prog = startProgress(opts.Progress, 2, len(files), totalBytes)
	err = forEachFile(len(files), workers, func(i int) error {
		forks[i] = p.forkForReplace()
		err := replaceFile(forks[i], &files[i], env, scanner, &perFile[i])
		env.prog.fileDone()
		return err
	})
	env.prog.finish()
	if err != nil {
		return RunResult{}, err
	}
	var findings []audit.Finding
	for i := range files {
		findings = append(findings, perFile[i]...)
		p.mergeCounts(forks[i])
	}
	log.Info("pass 2 complete: %d files written", len(files))

	mf := p.Registry.ToMappingFile(opts.ToolVersion, opts.InputDir, tokenize.Stats{
		FilesProcessed:         len(files),
		BytesProcessed:         bytesProcessed,
		ReplacementsByCategory: p.ReplacementCounts(),
	})

	return RunResult{
		FilesProcessed:    len(files),
		FilesSkipped:      skipped,
		BytesProcessed:    bytesProcessed,
		AuditFindings:     findings,
		Mapping:           mf,
		ReplacementCounts: p.ReplacementCounts(),
	}, nil
}

// relFor returns the output-relative path for an input file: its base name
// when the input is a single file, otherwise its path relative to the input
// directory root.
func relFor(root, path string, singleFile bool) (string, error) {
	if singleFile {
		return filepath.Base(path), nil
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("computing relative path for %s: %w", path, err)
	}
	return rel, nil
}

// encodingSampleSize is how much of a file is read up front to detect its
// encoding/BOM before streaming the rest.
const encodingSampleSize = 64 * 1024

// decodedFile is an open input file streaming through a LineReader.
type decodedFile struct {
	lr     *ioenc.LineReader
	enc    ioenc.Encoding
	hadBOM bool
	size   int64
	close  func() error
}

// openDecoded opens path, detects its encoding/BOM from the first 64 KB,
// and returns a LineReader over the whole file, streamed from the file
// handle -- peak memory no longer grows with file size. Bytes read are fed
// to prog.
//
// Encoding is now decided from the sample rather than the whole file: a
// file whose first non-UTF-8 byte lies past 64 KB is read as UTF-8, not
// Windows-1252. Output bytes are unchanged either way (invalid bytes pass
// through a UTF-8 Go string untouched); only how such bytes look to the
// detectors differs.
//
// A gzip-compressed file (gz) is decompressed as it streams; progress counts
// compressed bytes, matching the file sizes the total was computed from.
func openDecoded(path string, gz bool, prog *progress) (*decodedFile, error) {
	src, size, closeFn, err := openInput(path, gz, prog)
	if err != nil {
		return nil, err
	}
	head := make([]byte, encodingSampleSize)
	n, err := io.ReadFull(src, head)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		closeFn()
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	head = head[:n]
	enc, skip := ioenc.DetectBOM(head)
	hadBOM := skip > 0
	if !hadBOM {
		enc = ioenc.DetectSample(head, n == encodingSampleSize)
	}
	r := io.MultiReader(bytes.NewReader(head[skip:]), src)
	return &decodedFile{lr: ioenc.NewLineReader(r, enc), enc: enc, hadBOM: hadBOM, size: size, close: closeFn}, nil
}

// openInput opens path for streaming, decompressing a gzip file (gz) on
// the fly. Progress counts raw (compressed) bytes, matching the file sizes
// the progress total was computed from. size is the on-disk size.
func openInput(path string, gz bool, prog *progress) (r io.Reader, size int64, closeFn func() error, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("opening %s: %w", path, err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, nil, fmt.Errorf("statting %s: %w", path, err)
	}
	r = countingReader{r: f, pr: prog}
	if gz {
		zr, err := gzip.NewReader(bufio.NewReader(r))
		if err != nil {
			f.Close()
			return nil, 0, nil, fmt.Errorf("reading gzip %s: %w", path, err)
		}
		r = zr
	}
	return r, st.Size(), f.Close, nil
}

// harCandidate reports whether in should be tried as a HAR: a .har / .json
// name (optionally .gz) whose content (decompressed) looks like one.
func harCandidate(in *inputFile) (bool, error) {
	name := strings.TrimSuffix(strings.ToLower(in.rel), ".gz")
	if ext := filepath.Ext(name); ext != ".har" && ext != ".json" {
		return false, nil
	}
	r, _, closeFn, err := openInput(in.src, in.gz, nil)
	if err != nil {
		return false, err
	}
	defer closeFn()
	head := make([]byte, 4096)
	n, _ := io.ReadFull(r, head)
	return har.Looks(in.rel, head[:n]), nil
}

// streamHAR streams in through the HAR handler into w, with scan applied
// to string values.
func streamHAR(in *inputFile, w io.Writer, env *runEnv, scan func(string) string) (redactions int, err error) {
	r, _, closeFn, err := openInput(in.src, in.gz, env.prog)
	if err != nil {
		return 0, err
	}
	defer closeFn()
	return har.TransformStream(r, w, har.Options{KeepBodies: env.opts.KeepHARBodies}, scan)
}

// scanFile runs Pass 1 over a single file into p's registry, returning the
// file's byte size. Text files are scanned in parallel chunks.
//
// A HAR is streamed into a scratch registry first; only if the whole
// document parses is it merged and in.har set, which tells Pass 2 to stream
// it as a HAR too. A HAR that doesn't parse (e.g. truncated) falls back to
// line-based processing in both passes, so Pass 2 never writes half a JSON
// document.
func scanFile(p *Pipeline, in *inputFile, env *runEnv) (int64, error) {
	path, rel := in.src, in.rel
	if cand, err := harCandidate(in); err != nil {
		return 0, err
	} else if cand {
		scratch := p.forkForScan()
		_, err := streamHAR(in, io.Discard, env, func(s string) string { scratch.ScanText(s); return s })
		if err == nil {
			p.Registry.Merge(scratch.Registry)
			in.har = true
			env.log.Verbose("scanned %s as HAR", rel)
			st, _ := os.Stat(path)
			return st.Size(), nil
		}
		env.log.Warn("%s: not processed as HAR (%v); falling back to line-based sanitization", rel, err)
	}
	df, err := openDecoded(path, in.gz, env.prog)
	if err != nil {
		return 0, err
	}
	defer df.close()

	lineCount, err := processChunks(df.lr, env,
		func(c *chunk) {
			f := p.forkForScan()
			for _, it := range c.lines {
				// Lines inside a PEM key block are wholesale-redacted in
				// Pass 2, so their contents are never scanned into the
				// registry.
				if !it.pem {
					f.ScanLine(it.text)
				}
			}
			c.reg = f.Registry
		},
		func(c *chunk) error {
			p.Registry.Merge(c.reg)
			return nil
		})
	if err != nil {
		return 0, fmt.Errorf("reading lines from %s: %w", path, err)
	}
	env.log.Verbose("scanned %s: %d lines, encoding %s", rel, lineCount, df.enc)
	return df.size, nil
}

// replaceFile runs Pass 2 over a single file: re-read, replace, write (unless
// dry-run), and audit, in parallel chunks emitted in order. Each line is
// written with its own original terminator (LineWriter.WriteLine), so mixed
// CRLF/LF endings and a missing final newline are reproduced exactly rather
// than normalized.
func replaceFile(p *Pipeline, in *inputFile, env *runEnv, scanner *audit.Scanner, findings *[]audit.Finding) error {
	path, rel := in.src, in.rel
	opts := env.opts
	if in.har {
		return replaceHAR(p, in, env, scanner, findings)
	}
	df, err := openDecoded(path, in.gz, env.prog)
	if err != nil {
		return err
	}
	defer df.close()

	var lw *ioenc.LineWriter
	if !opts.DryRun {
		outPath := filepath.Join(opts.OutputDir, rel)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("creating output directory for %s: %w", outPath, err)
		}
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", outPath, err)
		}
		defer f.Close()
		var w io.Writer = f
		if in.gz {
			// Rotated logs go back out gzip-compressed, under the same name.
			zw := gzip.NewWriter(f)
			defer zw.Close()
			w = zw
		}
		lw = ioenc.NewLineWriter(w, df.enc)
		if df.hadBOM {
			if err := lw.WriteBOM(); err != nil {
				return fmt.Errorf("writing BOM for %s: %w", rel, err)
			}
		}
	}

	_, err = processChunks(df.lr, env,
		func(c *chunk) {
			f := p.forkForReplace()
			c.out = make([]string, len(c.lines))
			for i, it := range c.lines {
				// A line inside a PEM key block is redacted whole -- the
				// multi-line key body is invisible to the per-line
				// detectors. One SECRET_REDACTED per body line keeps line
				// numbers aligned with the original.
				if it.pem {
					c.out[i] = SecretPlaceholder
					f.CountLineRedaction()
				} else {
					c.out[i] = f.ReplaceLine(it.text)
				}
				if opts.AuditEnabled {
					c.findings = append(c.findings, scanner.ScanLine(rel, c.start+i, c.out[i])...)
				}
			}
			c.fork = f
		},
		func(c *chunk) error {
			if lw != nil {
				for i, s := range c.out {
					if err := lw.WriteLine(s, c.lines[i].ending); err != nil {
						return fmt.Errorf("writing %s: %w", rel, err)
					}
				}
			}
			*findings = append(*findings, c.findings...)
			p.mergeCounts(c.fork)
			return nil
		})
	if err != nil {
		return fmt.Errorf("processing %s: %w", path, err)
	}
	if lw != nil {
		if err := lw.Flush(); err != nil {
			return fmt.Errorf("flushing %s: %w", rel, err)
		}
	}
	env.log.Verbose("replaced %s", rel)
	return nil
}

// replaceHAR streams a HAR (one Pass 1 parsed) through the HAR handler,
// writing the output (gzipped again if the input was) and auditing it line
// by line as it is written.
func replaceHAR(p *Pipeline, in *inputFile, env *runEnv, scanner *audit.Scanner, findings *[]audit.Finding) error {
	var sinks []io.Writer
	var closers []func() error
	if !env.opts.DryRun {
		outPath := filepath.Join(env.opts.OutputDir, in.rel)
		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("creating output directory for %s: %w", outPath, err)
		}
		f, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("creating %s: %w", outPath, err)
		}
		defer f.Close()
		var w io.Writer = f
		if in.gz {
			zw := gzip.NewWriter(f)
			closers = append(closers, zw.Close)
			w = zw
		}
		sinks = append(sinks, w)
	}
	var aw *auditWriter
	if env.opts.AuditEnabled {
		aw = &auditWriter{scanner: scanner, rel: in.rel, findings: findings}
		sinks = append(sinks, aw)
	}
	redactions, err := streamHAR(in, io.MultiWriter(sinks...), env, p.ReplaceText)
	if err != nil {
		return fmt.Errorf("processing HAR %s: %w", in.src, err)
	}
	if aw != nil {
		aw.flush()
	}
	for _, c := range closers {
		if err := c(); err != nil {
			return fmt.Errorf("writing %s: %w", in.rel, err)
		}
	}
	for i := 0; i < redactions; i++ {
		p.CountLineRedaction()
	}
	env.log.Verbose("replaced %s as HAR", in.rel)
	return nil
}

// auditWriter audits text line by line as it is written.
type auditWriter struct {
	scanner  *audit.Scanner
	rel      string
	findings *[]audit.Finding
	buf      []byte
	line     int
}

func (a *auditWriter) Write(b []byte) (int, error) {
	a.buf = append(a.buf, b...)
	for {
		i := bytes.IndexByte(a.buf, '\n')
		if i < 0 {
			break
		}
		a.scan(string(a.buf[:i]))
		a.buf = a.buf[i+1:]
	}
	return len(b), nil
}

func (a *auditWriter) scan(line string) {
	a.line++
	*a.findings = append(*a.findings, a.scanner.ScanLine(a.rel, a.line, line)...)
}

func (a *auditWriter) flush() {
	if len(a.buf) > 0 {
		a.scan(string(a.buf))
		a.buf = nil
	}
}

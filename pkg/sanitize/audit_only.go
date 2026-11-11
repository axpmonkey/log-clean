package sanitize

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sas-log-sanitize/internal/archive"
	"sas-log-sanitize/internal/audit"
	"sas-log-sanitize/internal/detect"
	ioenc "sas-log-sanitize/internal/io"
	"sas-log-sanitize/internal/tokenize"
)

// ownArtifactNames are the files Sanitize itself writes to an output
// directory; AuditDirectory skips them since they aren't sanitized log
// content (the mapping file in particular must never be content-scanned and
// reported on, since doing so could otherwise tempt someone into treating
// _mapping.json as just another input file).
var ownArtifactNames = map[string]bool{
	"_mapping.json": true,
	"_audit.txt":    true,
	"_summary.txt":  true,
	"_summary.json": true,
	"_runlog.txt":   true,
}

// AuditDirectory re-scans every file in an already-sanitized directory for
// patterns that look like residual PII, for the --audit-only CLI mode. It
// applies the same binary-file skipping and encoding detection as a normal
// sanitize run. ignorelistPath and ipv4SkipRanges, if set, are honored the
// same way as a normal run's --ignorelist and detectors.ipv4.skip_ranges, so
// hostnames/addresses the original run deliberately left untouched aren't
// re-flagged here as unredacted PII.
//
// mappingPath, if set, names the run's mapping file; every original value in
// it is then searched for as well (High known-original-value findings). If
// empty, the default mapping location for dir is used when that file exists
// (see defaultAuditMappingPaths); otherwise that rule is skipped.
func AuditDirectory(dir string, ignorelistPath string, ipv4SkipRanges []string, mappingPath string) ([]audit.Finding, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, inputErrorf("audit directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, inputErrorf("audit path %s is not a directory", dir)
	}

	ignoreList, err := loadIgnoreList(ignorelistPath)
	if err != nil {
		return nil, err
	}
	skipRanges, err := parseSkipRanges(ipv4SkipRanges)
	if err != nil {
		return nil, err
	}

	known, err := loadKnownValues(dir, mappingPath)
	if err != nil {
		return nil, err
	}

	var paths []string
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ownArtifactNames[d.Name()] {
			return nil
		}
		// Rotated logs are written back gzipped, so they are audited
		// decompressed; anything else binary-shaped is skipped.
		if archive.KindOf(path) != archive.Gzip && ioenc.IsSkippedExtension(path) {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		return nil, processingErrorf("walking %s: %w", dir, err)
	}
	sort.Strings(paths)

	scanner := audit.NewScanner()
	scanner.Ignore = ignoreList
	scanner.IPv4SkipRanges = skipRanges
	scanner.Known = known
	var findings []audit.Finding
	for _, path := range paths {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		data, err := readMaybeGzip(path)
		if err != nil {
			return nil, processingErrorf("reading %s: %w", path, err)
		}

		enc, skip := ioenc.DetectBOM(data)
		// A UTF-16 BOM unambiguously signals text; skip the binary-content
		// heuristic in that case, since UTF-16-encoded ASCII is roughly half
		// NUL bytes and would otherwise trip it (see the identical fix and
		// explanation in internal/pipeline/run.go's discoverFiles).
		isUTF16 := enc == ioenc.UTF16LE || enc == ioenc.UTF16BE
		if !isUTF16 && ioenc.IsBinary(data) {
			continue
		}
		if skip == 0 {
			enc = ioenc.DetectNoBOM(data)
		}

		lr := ioenc.NewLineReader(bytes.NewReader(data[skip:]), enc)
		lineNum := 0
		for {
			line, _, err := lr.ReadLine()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, processingErrorf("reading lines from %s: %w", path, err)
			}
			lineNum++
			findings = append(findings, scanner.ScanLine(rel, lineNum, line)...)
		}
	}
	return findings, nil
}

// defaultAuditMappingPaths are where --audit-only looks for the mapping when
// none is given: the default location a sanitize run writes it to, then the
// pre-0.1 default inside the output directory.
func defaultAuditMappingPaths(dir string) []string {
	return []string{DefaultMappingPath(dir), filepath.Join(dir, "_mapping.json")}
}

// loadKnownValues builds the known-original-value matcher from the mapping
// file. An explicitly named mapping that can't be read is an input error; a
// missing default one just disables the rule.
func loadKnownValues(dir, mappingPath string) (*detect.KnownValuesDetector, error) {
	if mappingPath == "" {
		for _, candidate := range defaultAuditMappingPaths(dir) {
			if _, err := os.Stat(candidate); err == nil {
				mappingPath = candidate
				break
			}
		}
		if mappingPath == "" {
			return nil, nil
		}
	}
	mf, err := tokenize.LoadMappingFile(mappingPath)
	if err != nil {
		return nil, inputErrorf("audit mapping: %w", err)
	}
	return detect.NewKnownValuesDetector(detect.AuditValues(tokenize.OrderedValues(mf.Categories))), nil
}

// readMaybeGzip reads a file, decompressing it when it is a *.gz.
func readMaybeGzip(path string) ([]byte, error) {
	if archive.KindOf(path) != archive.Gzip {
		return os.ReadFile(path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(zr)
}

package sanitize

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sas-log-sanitize/internal/audit"
	ioenc "sas-log-sanitize/internal/io"
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
	"_runlog.txt":   true,
}

// AuditDirectory re-scans every file in an already-sanitized directory for
// patterns that look like residual PII, for the --audit-only CLI mode. It
// applies the same binary-file skipping and encoding detection as a normal
// sanitize run. ignorelistPath, if set, is loaded the same way as a normal
// run's --ignorelist, so hostnames the original run deliberately left
// untouched (e.g. "*.sas.com") aren't re-flagged here as unredacted PII.
func AuditDirectory(dir string, ignorelistPath string) ([]audit.Finding, error) {
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

	var paths []string
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if ownArtifactNames[d.Name()] || ioenc.IsSkippedExtension(path) {
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
	var findings []audit.Finding
	for _, path := range paths {
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			rel = path
		}
		data, err := os.ReadFile(path)
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

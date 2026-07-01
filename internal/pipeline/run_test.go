package pipeline

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	ioenc "sas-log-sanitize/internal/io"
	"sas-log-sanitize/internal/runlog"
)

func writeTestFile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	full := filepath.Join(dir, relPath)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

func TestRunSanitizesFilesAndWritesOutput(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()

	writeTestFile(t, inputDir, "app.log", "connecting to db-prod-01.acme.internal as user=jdoe\n")
	writeTestFile(t, inputDir, "sub/other.log", "again db-prod-01.acme.internal\n")

	p := New(identityDetectors())
	var logBuf bytes.Buffer
	result, err := Run(p, RunOptions{
		InputDir:     inputDir,
		OutputDir:    outputDir,
		AuditEnabled: true,
		ToolVersion:  "test",
	}, runlog.New(&logBuf, true))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if result.FilesProcessed != 2 {
		t.Errorf("FilesProcessed = %d, want 2", result.FilesProcessed)
	}

	gotTop, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading sanitized app.log: %v", err)
	}
	if string(gotTop) != "connecting to HOST_001 as user=USER_001\n" {
		t.Errorf("app.log content = %q", gotTop)
	}

	gotSub, err := os.ReadFile(filepath.Join(outputDir, "sub/other.log"))
	if err != nil {
		t.Fatalf("reading sanitized sub/other.log: %v", err)
	}
	if string(gotSub) != "again HOST_001\n" {
		t.Errorf("sub/other.log content = %q, want same HOST_001 token reused across files", gotSub)
	}

	if result.Mapping.Categories["HOST"]["HOST_001"] != "db-prod-01.acme.internal" {
		t.Errorf("mapping HOST_001 = %q", result.Mapping.Categories["HOST"]["HOST_001"])
	}
}

func TestRunSkipsBinaryFilesByExtension(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "hello jdoe\n")
	writeTestFile(t, inputDir, "heap.hprof", "not real binary content but skipped by extension\n")

	p := New(identityDetectors())
	result, err := Run(p, RunOptions{InputDir: inputDir, OutputDir: outputDir, ToolVersion: "test"}, runlog.New(&bytes.Buffer{}, false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("FilesProcessed = %d, want 1", result.FilesProcessed)
	}
	if len(result.FilesSkipped) != 1 || result.FilesSkipped[0].RelPath != "heap.hprof" {
		t.Errorf("FilesSkipped = %+v", result.FilesSkipped)
	}
	if _, err := os.Stat(filepath.Join(outputDir, "heap.hprof")); !os.IsNotExist(err) {
		t.Error("heap.hprof should not have been written to output")
	}
}

func TestRunDryRunWritesNoFiles(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "connecting to db-prod-01.acme.internal\n")

	p := New(identityDetectors())
	result, err := Run(p, RunOptions{
		InputDir: inputDir, OutputDir: outputDir, DryRun: true, AuditEnabled: true, ToolVersion: "test",
	}, runlog.New(&bytes.Buffer{}, false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("FilesProcessed = %d, want 1", result.FilesProcessed)
	}
	if result.Mapping.Categories["HOST"]["HOST_001"] != "db-prod-01.acme.internal" {
		t.Error("dry run should still populate stats/mapping in-memory")
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("dry run wrote files to output dir: %v", entries)
	}
}

func TestRunPreservesUTF16LEEncodingAndBOM(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()

	var raw []byte
	raw = append(raw, 0xFF, 0xFE) // UTF-16 LE BOM
	raw = append(raw, ioenc.EncodeUTF16("hostname: db-prod-01.acme.internal\r\n", false)...)
	if err := os.MkdirAll(inputDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "windows.log"), raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	p := New(identityDetectors())
	_, err := Run(p, RunOptions{InputDir: inputDir, OutputDir: outputDir, ToolVersion: "test"}, runlog.New(&bytes.Buffer{}, false))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	out, err := os.ReadFile(filepath.Join(outputDir, "windows.log"))
	if err != nil {
		t.Fatalf("reading sanitized windows.log: %v", err)
	}
	if len(out) < 2 || out[0] != 0xFF || out[1] != 0xFE {
		t.Errorf("output missing UTF-16 LE BOM: %v", out[:min(4, len(out))])
	}
}

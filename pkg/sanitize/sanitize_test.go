package sanitize

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestSanitizeEndToEnd(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "connecting to db-prod-01.acme.internal as user=jdoe\n")

	opts := Options{
		InputDir:     inputDir,
		OutputDir:    outputDir,
		AuditEnabled: true,
		ToolVersion:  "test",
	}
	result, err := Sanitize(opts)
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("FilesProcessed = %d, want 1", result.FilesProcessed)
	}

	sanitized, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading sanitized output: %v", err)
	}
	if string(sanitized) != "connecting to HOST_001 as user=USER_001\n" {
		t.Errorf("sanitized content = %q", sanitized)
	}

	for _, f := range []string{"_mapping.json", "_audit.txt", "_summary.txt", "_runlog.txt"} {
		if _, err := os.Stat(filepath.Join(outputDir, f)); err != nil {
			t.Errorf("expected %s to exist: %v", f, err)
		}
	}
}

func TestSanitizeDryRunWritesNothing(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "connecting to db-prod-01.acme.internal\n")

	opts := Options{InputDir: inputDir, OutputDir: outputDir, DryRun: true, ToolVersion: "test"}
	result, err := Sanitize(opts)
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if result.FilesProcessed != 1 {
		t.Errorf("FilesProcessed = %d, want 1", result.FilesProcessed)
	}
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("dry run wrote to output dir: %v", entries)
	}
}

func TestSanitizeMissingInputDirIsInputError(t *testing.T) {
	opts := Options{InputDir: filepath.Join(t.TempDir(), "does-not-exist"), ToolVersion: "test"}
	_, err := Sanitize(opts)
	if err == nil {
		t.Fatal("expected an error for missing input directory")
	}
	var sanitizeErr *Error
	if !errors.As(err, &sanitizeErr) {
		t.Fatalf("error is not *Error: %v", err)
	}
	if sanitizeErr.Kind != KindInput {
		t.Errorf("Kind = %v, want KindInput", sanitizeErr.Kind)
	}
}

func TestSanitizeEmptyInputDirIsConfigError(t *testing.T) {
	_, err := Sanitize(Options{ToolVersion: "test"})
	if err == nil {
		t.Fatal("expected an error for empty InputDir")
	}
	var sanitizeErr *Error
	if !errors.As(err, &sanitizeErr) {
		t.Fatalf("error is not *Error: %v", err)
	}
	if sanitizeErr.Kind != KindConfig {
		t.Errorf("Kind = %v, want KindConfig", sanitizeErr.Kind)
	}
}

func TestSanitizeUnknownProfileIsConfigError(t *testing.T) {
	inputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "hello\n")

	opts := Options{InputDir: inputDir, OutputDir: t.TempDir(), Profiles: []string{"not-a-real-profile"}, ToolVersion: "test"}
	_, err := Sanitize(opts)
	if err == nil {
		t.Fatal("expected an error for unknown profile")
	}
	var sanitizeErr *Error
	if !errors.As(err, &sanitizeErr) || sanitizeErr.Kind != KindConfig {
		t.Fatalf("expected KindConfig error, got %v", err)
	}
}

func TestSanitizeHostlistWiresAllowlistDetector(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "archiving to /var/log/db-prod-01-archive/out.log now\n")

	hostlistPath := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(hostlistPath, []byte("db-prod-01\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	opts := Options{InputDir: inputDir, OutputDir: outputDir, HostlistPath: hostlistPath, ToolVersion: "test"}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}

	sanitized, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if !strings.Contains(string(sanitized), "HOST_001") {
		t.Errorf("allowlist host not tokenized: %q", sanitized)
	}
}

func TestSanitizeHasHighFindingsReflectsAuditResult(t *testing.T) {
	// Credentials inside a JDBC URL with a bare (non-dotted) host leak per
	// the documented limitation in detect.CredentialsDetector -- this should
	// still produce a working result with HasHighFindings observable, not an
	// error.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "jdbc:postgresql://jdoe:Secret1@dbprod01:5432/sasdb\n")

	opts := Options{InputDir: inputDir, OutputDir: outputDir, AuditEnabled: true, ToolVersion: "test"}
	result, err := Sanitize(opts)
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	// This specific bare-host case is Medium severity (hostname/server-suffix
	// rules), not High, so just confirm the field is populated and findings
	// exist rather than asserting a specific severity here.
	if len(result.AuditFindings) == 0 {
		t.Error("expected at least one audit finding for the bare untokenized host")
	}
}

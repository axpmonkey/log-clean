package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var goldenRoot = filepath.Join("..", "..", "testdata", "golden")

// runCLI invokes the CLI entry point and returns its exit code and output.
func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// P0.8 (golden fixture 7): the audit must look for the original values the
// mapping says are sensitive, not only for PII-shaped text. A hand-inserted
// original value -- one no shape rule would flag -- is a High finding, so
// --audit-only --strict exits 1.
func TestAuditOnlyStrictFlagsKnownOriginalValue(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "out")
	mapping := filepath.Join(t.TempDir(), "case.mapping.json")

	if code, _, stderr := runCLI(t, "-q", "-i", in, "-o", out, "-m", mapping); code != exitOK && code != exitFindingsWarning {
		t.Fatalf("sanitize exit %d: %s", code, stderr)
	}

	// Clean output: no known-value findings.
	_, stdout, _ := runCLI(t, "--audit-only", "--strict", "-m", mapping, out)
	if strings.Contains(stdout, "known-original-value") {
		t.Fatalf("clean output already has known-value findings:\n%s", stdout)
	}

	// Hand-insert originals that only the known-values rule can catch: a bare
	// username and a host's short name in a different case.
	f, err := os.OpenFile(filepath.Join(out, "b.log"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("later jdoe reconnected via SasMid01\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()

	code, stdout, stderr := runCLI(t, "--audit-only", "--strict", "-m", mapping, out)
	if code != exitFindingsWarning {
		t.Errorf("exit code = %d, want %d", code, exitFindingsWarning)
	}
	if !strings.Contains(stderr, "High-severity audit findings present") {
		t.Errorf("stderr lacks the High-findings message: %q", stderr)
	}
	for _, want := range []string{`[High] b.log:6: known-original-value ("jdoe")`, `[High] b.log:6: known-original-value ("SasMid01")`} {
		if !strings.Contains(stdout, want) {
			t.Errorf("audit report lacks %q:\n%s", want, stdout)
		}
	}
}

// P0.9: -m inside -o exits 4 (config error) unless --allow-mapping-in-output.
func TestMappingInsideOutputExitCode(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "out")
	m := filepath.Join(out, "_mapping.json")

	if code, _, stderr := runCLI(t, "-q", "-i", in, "-o", out, "-m", m); code != exitConfigError {
		t.Errorf("exit = %d, want %d (stderr %q)", code, exitConfigError, stderr)
	}
	if code, _, stderr := runCLI(t, "-q", "--allow-mapping-in-output", "-i", in, "-o", out, "-m", m); code != exitOK && code != exitFindingsWarning {
		t.Errorf("with --allow-mapping-in-output: exit = %d (stderr %q)", code, stderr)
	}
}

// P0.9: --audit-only finds the default (sibling) mapping without -m.
func TestAuditOnlyFindsDefaultMapping(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "out")
	if code, _, stderr := runCLI(t, "-q", "-i", in, "-o", out); code != exitOK && code != exitFindingsWarning {
		t.Fatalf("sanitize exit %d: %s", code, stderr)
	}
	if err := os.WriteFile(filepath.Join(out, "leak.log"), []byte("jdoe was here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stdout, _ := runCLI(t, "--audit-only", out)
	if !strings.Contains(stdout, `known-original-value ("jdoe")`) {
		t.Errorf("audit-only without -m did not use the default mapping:\n%s", stdout)
	}
}

// P1.4: skipped files are listed in the CLI's exit summary, not only in the
// runlog.
func TestCLIListsSkippedFiles(t *testing.T) {
	in := t.TempDir()
	os.WriteFile(filepath.Join(in, "app.log"), []byte("hello\n"), 0o644)
	os.WriteFile(filepath.Join(in, "heap.hprof"), []byte{0, 1, 2, 3}, 0o644)
	out := filepath.Join(t.TempDir(), "out")
	_, stdout, _ := runCLI(t, "-i", in, "-o", out)
	if !strings.Contains(stdout, "Skipped files:") || !strings.Contains(stdout, "heap.hprof: binary file extension") {
		t.Errorf("CLI summary lacks the skipped file list:\n%s", stdout)
	}
}

// Exit codes: 1 only for High findings; --strict also exits 1 on Medium.
func TestExitCodesHighOnly(t *testing.T) {
	in := t.TempDir()
	os.WriteFile(filepath.Join(in, "app.log"), []byte("connecting to sasapp01 now\n"), 0o644) // Medium only
	out := filepath.Join(t.TempDir(), "out")
	if code, stdout, _ := runCLI(t, "-i", in, "-o", out); code != exitOK || !strings.Contains(stdout, "Audit: 1 findings") {
		t.Errorf("Medium-only run: exit %d, want %d; stdout:\n%s", code, exitOK, stdout)
	}
	if code, _, stderr := runCLI(t, "--strict", "-i", in, "-o", filepath.Join(t.TempDir(), "o2")); code != exitFindingsWarning || !strings.Contains(stderr, "--strict") {
		t.Errorf("--strict Medium-only run: exit %d, want %d; stderr %q", code, exitFindingsWarning, stderr)
	}
	if code, _, _ := runCLI(t, "--audit-only", out); code != exitOK {
		t.Errorf("--audit-only Medium-only: exit %d, want %d", code, exitOK)
	}
	if code, _, _ := runCLI(t, "--audit-only", "--strict", out); code != exitFindingsWarning {
		t.Errorf("--audit-only --strict Medium-only: exit %d, want %d", code, exitFindingsWarning)
	}
	os.WriteFile(filepath.Join(out, "leak.log"), []byte("resolved db9.corp.example.com\n"), 0o644) // High
	if code, _, _ := runCLI(t, "--audit-only", out); code != exitFindingsWarning {
		t.Errorf("--audit-only with High: exit %d, want %d", code, exitFindingsWarning)
	}
}

// Flags after a positional argument are parsed, not silently taken as more
// positional arguments: `--audit-only out --strict` must honor --strict.
func TestFlagsAfterPositionalArgs(t *testing.T) {
	in := t.TempDir()
	os.WriteFile(filepath.Join(in, "app.log"), []byte("connecting to sasapp01 now\n"), 0o644) // Medium only
	out := filepath.Join(t.TempDir(), "out")

	// Sanitize with the input as a positional argument and flags after it.
	if code, stdout, stderr := runCLI(t, in, "-o", out, "--strict", "-q"); code != exitFindingsWarning || stdout != "" {
		t.Fatalf("sanitize <in> -o out --strict -q: exit %d, want %d; stdout %q; stderr %q", code, exitFindingsWarning, stdout, stderr)
	}
	if code, _, _ := runCLI(t, "--audit-only", out, "--strict"); code != exitFindingsWarning {
		t.Errorf("--audit-only <dir> --strict: exit %d, want %d", code, exitFindingsWarning)
	}
	// "--" still ends flag parsing: "--strict" after it is not a flag, so
	// it is a second positional argument and the Medium finding passes.
	if code, _, _ := runCLI(t, "--audit-only", "--", out, "--strict"); code != exitOK {
		t.Errorf("--audit-only -- <dir> --strict: exit %d, want %d", code, exitOK)
	}
	if code, _, stderr := runCLI(t, "--audit-only", out, "--no-such-flag"); code != exitConfigError {
		t.Errorf("unknown trailing flag: exit %d, want %d; stderr %q", code, exitConfigError, stderr)
	}
}

// Reverse mode keeps everything after the first positional argument
// literal, so the text to reverse may start with "-".
func TestReverseTextStartingWithDash(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "out")
	mapping := filepath.Join(t.TempDir(), "case.mapping.json")
	if code, _, stderr := runCLI(t, "-q", "-i", in, "-o", out, "-m", mapping); code != exitOK && code != exitFindingsWarning {
		t.Fatalf("sanitize exit %d: %s", code, stderr)
	}
	code, stdout, stderr := runCLI(t, "--reverse", mapping, "-HOST_001 is down")
	if code != exitOK || strings.TrimSpace(stdout) != "-pghost01.corp.example.com is down" {
		t.Errorf("reverse: exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
}

// --max-extract-mb caps archive extraction (decompression-bomb guard).
func TestMaxExtractFlag(t *testing.T) {
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	w, _ := zw.Create("big.log")
	w.Write(bytes.Repeat([]byte("x"), 2<<20))
	zw.Close()
	in := filepath.Join(t.TempDir(), "bundle.zip")
	os.WriteFile(in, b.Bytes(), 0o644)
	code, _, stderr := runCLI(t, "-q", "--max-extract-mb", "1", "-i", in, "-o", filepath.Join(t.TempDir(), "out"))
	if code != exitProcessingError || !strings.Contains(stderr, "size limit") {
		t.Errorf("exit %d, stderr %q; want %d and a size-limit message", code, stderr, exitProcessingError)
	}
}

// --no-color was removed: the tool never prints color, so the flag did
// nothing. It is now an unknown flag (config error).
func TestNoColorFlagRemoved(t *testing.T) {
	if code, _, _ := runCLI(t, "--no-color", "--version"); code != exitConfigError {
		t.Errorf("--no-color: exit %d, want %d (unknown flag)", code, exitConfigError)
	}
}

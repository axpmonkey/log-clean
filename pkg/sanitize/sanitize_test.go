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

func TestSanitizeSingleFileInput(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "connecting to db-prod-01.acme.internal as user=jdoe\n")

	opts := Options{
		InputDir:     filepath.Join(inputDir, "app.log"),
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

func TestSanitizeIgnorelistDoesNotLeakEmailAtIgnoredDomain(t *testing.T) {
	// Regression: an ignore entry like "*.sas.com" must only suppress
	// host-shaped matches, not an email address whose text merely ends in
	// the ignored domain -- otherwise the username in "jdoe@internal.sas.com"
	// would leak into the output unredacted.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "login jdoe@internal.sas.com from host db1.sas.com\n")

	ignorePath := filepath.Join(t.TempDir(), "ignore.txt")
	if err := os.WriteFile(ignorePath, []byte("*.sas.com\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	opts := Options{InputDir: inputDir, OutputDir: outputDir, IgnorelistPath: ignorePath, ToolVersion: "test"}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	out := string(got)
	if strings.Contains(out, "jdoe") {
		t.Errorf("email username leaked despite being at an ignored domain: %q", out)
	}
	if !strings.Contains(out, "EMAIL_001") {
		t.Errorf("email at ignored domain should still be tokenized: %q", out)
	}
	// The bare host itself is what the ignore list is for -- it must pass through.
	if !strings.Contains(out, "db1.sas.com") {
		t.Errorf("ignored host should pass through untouched: %q", out)
	}
}

func TestSanitizePreservesMissingFinalNewline(t *testing.T) {
	// Regression: output must be byte-faithful to the input's line endings --
	// a file with no trailing newline must not gain one.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "host db-prod-01.acme.internal") // no trailing "\n"

	opts := Options{InputDir: inputDir, OutputDir: outputDir, ToolVersion: "test"}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if want := "host HOST_001"; string(got) != want {
		t.Errorf("output = %q, want %q (no added trailing newline)", got, want)
	}
}

func TestSanitizeRedactsMultiLinePEMPrivateKeyBody(t *testing.T) {
	// Regression: the base64 body lines between the BEGIN/END markers of an
	// SSH/PEM private key must be redacted, not just the marker lines. A
	// per-line detector can't see the body, so the pipeline's file-level
	// block redactor handles it.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "2026-06-30 INFO -----BEGIN RSA PRIVATE KEY-----\n"+
		"MIIEpAIBAAKCAQEA1c7BODYLINEsecretmaterial0001\n"+
		"mCLdMLYX0mMoreSecretKeyMaterialHere0002\n"+
		"-----END RSA PRIVATE KEY-----\n"+
		"2026-06-30 INFO login jdoe@acme.internal ok\n")

	opts := Options{InputDir: inputDir, OutputDir: outputDir, ToolVersion: "test"}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	out := string(got)
	for _, leak := range []string{"BODYLINEsecretmaterial", "MoreSecretKeyMaterial"} {
		if strings.Contains(out, leak) {
			t.Errorf("key body leaked into output (%q):\n%s", leak, out)
		}
	}
	// The block is four SECRET_REDACTED lines (markers + body), preserving the
	// original line count, and normal detection resumes after the block.
	wantLine := "2026-06-30 INFO login EMAIL_001 ok"
	if !strings.Contains(out, wantLine) {
		t.Errorf("detection did not resume after key block; output:\n%s", out)
	}
	if n := strings.Count(out, "SECRET_REDACTED"); n != 4 {
		t.Errorf("got %d SECRET_REDACTED lines, want 4 (2 markers + 2 body):\n%s", n, out)
	}
}

func TestSanitizeUnterminatedPEMKeyFailsClosed(t *testing.T) {
	// A BEGIN marker with no matching END (truncated log) must redact through
	// end of file rather than leak the remaining key material.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "-----BEGIN OPENSSH PRIVATE KEY-----\n"+
		"b3BlbnNzaC1rZXktSECRETtail0001\n"+
		"b3BlbnNzaC1rZXktSECRETtail0002\n")

	opts := Options{InputDir: inputDir, OutputDir: outputDir, ToolVersion: "test"}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	if strings.Contains(string(got), "SECRETtail") {
		t.Errorf("unterminated key body leaked (should fail closed):\n%s", got)
	}
}

func TestSanitizeIPv4SkipRangesLeavesAddressesAndNoAuditFinding(t *testing.T) {
	// Addresses in a configured skip range are left untokenized, and the
	// audit pass must not then flag them as unredacted-ipv4 (High) -- the
	// scanner shares the skip ranges with the detector.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "internal 10.20.30.40 talking to public 8.8.8.8\n")

	opts := Options{
		InputDir: inputDir, OutputDir: outputDir, AuditEnabled: true,
		IPv4SkipRanges: []string{"10.0.0.0/8"}, ToolVersion: "test",
	}
	result, err := Sanitize(opts)
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	out := string(got)
	if !strings.Contains(out, "10.20.30.40") {
		t.Errorf("skipped IP should pass through untouched: %q", out)
	}
	if strings.Contains(out, "8.8.8.8") {
		t.Errorf("non-skipped public IP should be tokenized: %q", out)
	}
	for _, f := range result.AuditFindings {
		if f.Pattern == "unredacted-ipv4" {
			t.Errorf("skipped IP wrongly flagged by audit: %+v", f)
		}
	}
}

func TestSanitizeInvalidSkipRangeIsConfigError(t *testing.T) {
	inputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "hello\n")
	opts := Options{InputDir: inputDir, OutputDir: t.TempDir(), IPv4SkipRanges: []string{"not-a-cidr"}, ToolVersion: "test"}
	_, err := Sanitize(opts)
	var sanitizeErr *Error
	if !errors.As(err, &sanitizeErr) || sanitizeErr.Kind != KindConfig {
		t.Fatalf("expected KindConfig error for bad CIDR, got %v", err)
	}
}

func TestSanitizeConfigExtraInternalTLDs(t *testing.T) {
	// A host under a custom pseudo-TLD ("acmecorp") isn't a valid FQDN by
	// default, so it passes through untouched -- until the config's
	// detectors.fqdn.extra_internal_tlds names that TLD, at which point the
	// FQDN detector tokenizes it.
	const line = "connecting to db01.acmecorp now\n"

	t.Run("without extra TLD, untouched", func(t *testing.T) {
		inputDir, outputDir := t.TempDir(), t.TempDir()
		writeTestFile(t, inputDir, "app.log", line)
		if _, err := Sanitize(Options{InputDir: inputDir, OutputDir: outputDir, ToolVersion: "test"}); err != nil {
			t.Fatalf("Sanitize: %v", err)
		}
		got, _ := os.ReadFile(filepath.Join(outputDir, "app.log"))
		if !strings.Contains(string(got), "db01.acmecorp") {
			t.Errorf("host under unknown TLD should pass through: %q", got)
		}
	})

	t.Run("with extra TLD, tokenized", func(t *testing.T) {
		inputDir, outputDir := t.TempDir(), t.TempDir()
		writeTestFile(t, inputDir, "app.log", line)
		opts := Options{
			InputDir: inputDir, OutputDir: outputDir,
			ExtraInternalTLDs: []string{"acmecorp"}, ToolVersion: "test",
		}
		if _, err := Sanitize(opts); err != nil {
			t.Fatalf("Sanitize: %v", err)
		}
		got, _ := os.ReadFile(filepath.Join(outputDir, "app.log"))
		out := string(got)
		if strings.Contains(out, "db01.acmecorp") {
			t.Errorf("host under configured extra TLD should be tokenized: %q", out)
		}
		if !strings.Contains(out, "HOST_001") {
			t.Errorf("expected HOST_001 token: %q", out)
		}
	})
}

func TestSanitizeAllowlistCaseInsensitive(t *testing.T) {
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "archiving to /var/log/DB-PROD-01-archive/out.log\n")

	hostlistPath := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(hostlistPath, []byte("db-prod-01\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	opts := Options{
		InputDir: inputDir, OutputDir: outputDir, HostlistPath: hostlistPath,
		AllowlistCaseInsensitive: true, ToolVersion: "test",
	}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	out := string(got)
	if strings.Contains(out, "DB-PROD-01") {
		t.Errorf("case-insensitive allowlist should have tokenized DB-PROD-01: %q", out)
	}
	if !strings.Contains(out, "HOST_001") {
		t.Errorf("expected HOST_001 token: %q", out)
	}
}

func TestSanitizeAuditFindingsAreReported(t *testing.T) {
	// A bare, environment-suffixed hostname-shaped word ("app-prod01") isn't
	// caught by any detector (no dot, not an IP, not a user= form), so it
	// survives into the output where the audit pass's hostname-shaped-bare-word
	// rule flags it. This exercises the audit -> Result wiring.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "starting worker on app-prod01 now\n")

	opts := Options{InputDir: inputDir, OutputDir: outputDir, AuditEnabled: true, ToolVersion: "test"}
	result, err := Sanitize(opts)
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if len(result.AuditFindings) == 0 {
		t.Error("expected at least one audit finding for the residual bare hostname-shaped word")
	}
}

func TestSanitizeJDBCBareHostNoLongerLeaks(t *testing.T) {
	// The bare host in a JDBC connection string with embedded credentials is
	// now tokenized (previously a documented leak). End-to-end confirmation.
	inputDir := t.TempDir()
	outputDir := t.TempDir()
	writeTestFile(t, inputDir, "app.log", "jdbc:postgresql://jdoe:Secret1@dbprod01:5432/sasdb\n")

	opts := Options{InputDir: inputDir, OutputDir: outputDir, AuditEnabled: true, ToolVersion: "test"}
	if _, err := Sanitize(opts); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(outputDir, "app.log"))
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}
	out := string(got)
	for _, leak := range []string{"dbprod01", "Secret1"} {
		if strings.Contains(out, leak) {
			t.Errorf("%q leaked into output: %q", leak, out)
		}
	}
	if !strings.Contains(out, "HOST_001") {
		t.Errorf("bare JDBC host not tokenized: %q", out)
	}
}

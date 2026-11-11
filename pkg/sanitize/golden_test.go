package sanitize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sas-log-sanitize/internal/audit"
)

// goldenRoot holds the golden fixtures from the improvement plan
// (work-tools/12-log-clean-improvements.md, "Golden fixtures to add"). Each
// fixture is a directory with an input/ tree that is sanitized as one bundle
// and an expected/ tree holding the exact sanitized output for every file.
var goldenRoot = filepath.Join("..", "..", "testdata", "golden")

// goldenRun is the result of sanitizing one golden fixture.
type goldenRun struct {
	outDir      string
	mappingPath string
	result      Result
}

// runGolden sanitizes testdata/golden/<name>/input into a temp directory,
// writing the mapping file to a separate temp directory, and fails the test
// for every output file that differs from testdata/golden/<name>/expected.
func runGolden(t *testing.T, name string) goldenRun {
	t.Helper()
	inDir := filepath.Join(goldenRoot, name, "input")
	expDir := filepath.Join(goldenRoot, name, "expected")
	outDir := t.TempDir()
	mappingPath := filepath.Join(t.TempDir(), "mapping.json")

	result, err := Sanitize(Options{
		InputDir:     inDir,
		OutputDir:    outDir,
		MappingPath:  mappingPath,
		AuditEnabled: true,
		ToolVersion:  "test",
	})
	if err != nil {
		t.Fatalf("Sanitize(%s): %v", name, err)
	}

	err = filepath.WalkDir(expDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(expDir, path)
		want, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := os.ReadFile(filepath.Join(outDir, rel))
		if err != nil {
			t.Errorf("%s: missing output file %s: %v", name, rel, err)
			return nil
		}
		if string(got) != string(want) {
			t.Errorf("%s/%s output mismatch\n%s", name, rel, lineDiff(string(want), string(got)))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", expDir, err)
	}
	return goldenRun{outDir: outDir, mappingPath: mappingPath, result: result}
}

// lineDiff renders the differing lines of want/got side by side.
func lineDiff(want, got string) string {
	w, g := strings.Split(want, "\n"), strings.Split(got, "\n")
	n := len(w)
	if len(g) > n {
		n = len(g)
	}
	var sb strings.Builder
	for i := 0; i < n; i++ {
		var wl, gl string
		if i < len(w) {
			wl = w[i]
		}
		if i < len(g) {
			gl = g[i]
		}
		if wl != gl {
			sb.WriteString("  line " + itoa(i+1) + ":\n    want: " + wl + "\n    got:  " + gl + "\n")
		}
	}
	return sb.String()
}

func itoa(i int) string {
	const digits = "0123456789"
	if i < 10 {
		return digits[i : i+1]
	}
	return itoa(i/10) + digits[i%10:i%10+1]
}

// assertNotInFile fails for every needle found in the file at path.
func assertNotInFile(t *testing.T, path string, needles ...string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	for _, n := range needles {
		if strings.Contains(string(data), n) {
			t.Errorf("%s contains %q", filepath.Base(path), n)
		}
	}
}

// highFindings returns the High-severity findings from a run.
func highFindings(r Result) []audit.Finding {
	var out []audit.Finding
	for _, f := range r.AuditFindings {
		if f.Severity == audit.SeverityHigh {
			out = append(out, f)
		}
	}
	return out
}

// P0.1: an IPv4 address near the word "SAS" (or "release") must still be
// tokenized; only a dotted quad immediately after a version keyword is a
// version string.
func TestGoldenIPv4SASContext(t *testing.T) {
	runGolden(t, "ipv4_sas_context")
}

// P0.2: a DN whose values contain spaces, periods, hyphens, apostrophes or
// escaped commas is one DN token, with no fragment of the name left behind.
func TestGoldenDNSpaces(t *testing.T) {
	run := runGolden(t, "dn_spaces")
	assertNotInFile(t, filepath.Join(run.outDir, "dn_spaces.log"),
		"John", "Doe", "Jane", "Smith", "Mary-Ann", "O'Brien", "Service Accounts")
}

// P0.3 / P0.4: Authorization / Proxy-Authorization values are redacted for
// every scheme (the scheme name is kept), and cookie values are redacted
// while cookie names and Set-Cookie attributes are kept.
func TestGoldenHTTPAuthAndCookies(t *testing.T) {
	run := runGolden(t, "http_auth_and_cookies")
	assertNotInFile(t, filepath.Join(run.outDir, "http_auth_and_cookies.log"),
		"c2FzZGVtbzpQYXNzd29yZDE", "YIIGhgYGKwYBBQUC", "TlRMTVNTUAAB", "sasdemo", "6629fae4",
		"8F3A2B1C9D0E7F6A", "6c1f0e2dab", "ab12cd34")
}

// P0.5: SAS00x / SASENC / AES encoded passwords are reversible, so they are
// redacted whatever key (if any) precedes them, and the audit no longer flags
// the "SAS002" prefix as a bare word.
func TestGoldenSASEncodedPasswords(t *testing.T) {
	run := runGolden(t, "sas_encoded_pw")
	assertNotInFile(t, filepath.Join(run.outDir, "sas_encoded_pw.log"),
		"{SAS0", "{AES", "{sasenc}", "1D579339", "8A1B2C3D", "AABBCCDD", "Zm9vYmFy", "0123ABCD")
	for _, f := range run.result.AuditFindings {
		if strings.Contains(f.Match, "SAS00") {
			t.Errorf("audit still flags SAS-encoding prefix: %+v", f)
		}
	}
}

// P0.6: logon tickets, OAuth codes/tokens and SAML values in query strings,
// form bodies and HAR queryString arrays are redacted -- and never reach the
// mapping file, which must never contain a secret.
func TestGoldenOAuthURLs(t *testing.T) {
	run := runGolden(t, "oauth_urls")
	secrets := []string{"Xy9abcDEF123", "qwerty", "ST-12345-abc", "ST-67890", "s3cr3tval",
		"tokval1", "idtok2", "rt3&", "rs4", "PHNhbWw", "fZJNT8MwDIbvSPyHKvc1", "rsABC", "Orion123"}
	assertNotInFile(t, filepath.Join(run.outDir, "oauth_urls.log"), secrets...)
	assertNotInFile(t, run.mappingPath, secrets...)
}

// P0.7: a USER or HOST value found anywhere in the bundle (and a host's short
// name) is replaced everywhere, with the same token -- including in other
// files and on lines no detector would have matched on its own. Common words
// ("support", a first label of a registered FQDN) are not swept.
func TestGoldenKnownValuesSweep(t *testing.T) {
	run := runGolden(t, "known_values_sweep")
	for _, f := range []string{"a.log", "b.log"} {
		assertNotInFile(t, filepath.Join(run.outDir, f), "jdoe", "pghost01", "sasmid01", "SASMID01")
	}
	if high := highFindings(run.result); len(high) != 0 {
		t.Errorf("expected no High audit findings, got %+v", high)
	}
}

// P0.9: the mapping file must not land in the output directory by default
// (the folder that gets zipped and attached), and a mapping path inside the
// output directory is refused unless explicitly allowed.
func TestMappingDefaultsOutsideOutputDir(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "case-sanitized")

	result, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true})
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if want := out + ".mapping.json"; result.MappingPath != want {
		t.Errorf("MappingPath = %q, want %q", result.MappingPath, want)
	}
	if _, err := os.Stat(out + ".mapping.json"); err != nil {
		t.Errorf("sibling mapping file missing: %v", err)
	}
	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		if strings.Contains(e.Name(), "mapping") {
			t.Errorf("output directory contains %s", e.Name())
		}
	}
}

func TestMappingInsideOutputDirRefused(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "out")
	for _, m := range []string{
		filepath.Join(out, "_mapping.json"),
		filepath.Join(out, "nested", "m.json"),
		filepath.Join(out, "..", filepath.Base(out), "m.json"),
	} {
		_, err := Sanitize(Options{InputDir: in, OutputDir: out, MappingPath: m})
		var se *Error
		if !errorsAs(err, &se) || se.Kind != KindConfig {
			t.Errorf("mapping %s: err = %v, want a config error", m, err)
		}
	}
	m := filepath.Join(out, "_mapping.json")
	if _, err := Sanitize(Options{InputDir: in, OutputDir: out, MappingPath: m, AllowMappingInOutput: true}); err != nil {
		t.Errorf("AllowMappingInOutput: %v", err)
	}
}

// P0.9: _runlog.txt sits in the output directory, so it must never contain an
// original value -- including hostlist entries quoted in warnings.
func TestRunlogHasNoOriginalValues(t *testing.T) {
	in := filepath.Join(goldenRoot, "known_values_sweep", "input")
	out := filepath.Join(t.TempDir(), "out")
	hostlist := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(hostlist, []byte("pgh\npghost01\nsasmid01.corp.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Sanitize(Options{InputDir: in, OutputDir: out, HostlistPath: hostlist, Verbose: true, AuditEnabled: true}); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	assertNotInFile(t, filepath.Join(out, "_runlog.txt"), "pgh", "sasmid01", "jdoe", "example.com")
}

// P1.1: URLs keep scheme, port, path and parameter names; only userinfo and
// host are tokenized, so the mapping has no URL category at all (which also
// keeps secrets in query strings out of it by construction).
func TestGoldenURLHostOnly(t *testing.T) {
	run := runGolden(t, "url_host_only")
	data, err := os.ReadFile(run.mappingPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), `"URL"`) {
		t.Errorf("mapping still has a URL category:\n%s", data)
	}
	assertNotInFile(t, run.mappingPath, "ST-12345", "://", ":8080")
}

// A credential whose value is a UUID is redacted; a UUID used as an ordinary
// identifier (session/job IDs) is still left alone.
func TestGoldenUUIDSecrets(t *testing.T) {
	runGolden(t, "uuid_secrets")
}

// Oracle thin JDBC URLs and TNS descriptors don't use "scheme://", so the
// URL detector never saw their hosts; a short host name leaked.
func TestGoldenOracleJDBC(t *testing.T) {
	run := runGolden(t, "oracle_jdbc")
	assertNotInFile(t, filepath.Join(run.outDir, "oracle_jdbc.log"), "orahost", "scott", "Tiger123")
}

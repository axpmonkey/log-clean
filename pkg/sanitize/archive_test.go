package sanitize

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const archiveLog = "2026-11-09 INFO user=jdoe connected to pghost01.corp.example.com from 10.20.30.40\n"
const archiveLogSanitized = "2026-11-09 INFO user=USER_001 connected to HOST_001 from IPV4_001\n"

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := gzip.NewWriter(&b)
	zw.Write([]byte(s))
	zw.Close()
	return b.Bytes()
}

func gunzipFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("%s is not gzip: %v", path, err)
	}
	data, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type zipEntry struct {
	name string
	data []byte
}

func zipBytes(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(e.data)
	}
	zw.Close()
	return b.Bytes()
}

func readOut(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("missing output %s: %v", path, err)
	}
	return string(data)
}

// P1.4: rotated *.gz logs are read transparently and written back gzipped.
func TestGzipLogSanitizedAndRecompressed(t *testing.T) {
	in := t.TempDir()
	os.WriteFile(filepath.Join(in, "catalina.2026-11-09.log.gz"), gzipBytes(t, archiveLog), 0o644)
	out := filepath.Join(t.TempDir(), "out")
	result, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.FilesSkipped) != 0 || result.FilesProcessed != 1 {
		t.Fatalf("processed %d, skipped %+v", result.FilesProcessed, result.FilesSkipped)
	}
	if got := gunzipFile(t, filepath.Join(out, "catalina.2026-11-09.log.gz")); got != archiveLogSanitized {
		t.Errorf("gz output = %q, want %q", got, archiveLogSanitized)
	}

	// --audit-only reads .gz output too: a leak inside a gz is found.
	os.WriteFile(filepath.Join(out, "leak.log.gz"), gzipBytes(t, "jdoe again at 10.20.30.40\n"), 0o644)
	findings, err := AuditDirectory(out, "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	var inLeak int
	for _, f := range findings {
		if f.File == "leak.log.gz" {
			inLeak++
		}
	}
	if inLeak == 0 {
		t.Errorf("audit-only did not scan inside leak.log.gz: %+v", findings)
	}
}

// P1.4: a .zip given as the input is extracted and sanitized; entries keep
// their paths under a folder named after the archive; nested .gz entries are
// handled, and unsafe entries are skipped and listed, never written.
func TestZipInputExtractedSafely(t *testing.T) {
	src := t.TempDir()
	zipPath := filepath.Join(src, "bundle.zip")
	os.WriteFile(zipPath, zipBytes(t,
		zipEntry{"logs/catalina.out", []byte(archiveLog)},
		zipEntry{"logs/catalina.1.log.gz", gzipBytes(t, archiveLog)},
		zipEntry{"../evil.log", []byte(archiveLog)},
		zipEntry{"/abs/evil.log", []byte(archiveLog)},
		zipEntry{"inner/nested.zip", zipBytes(t, zipEntry{"x.log", []byte(archiveLog)})},
	), 0o644)

	root := t.TempDir()
	out := filepath.Join(root, "out")
	result, err := Sanitize(Options{InputDir: zipPath, OutputDir: out, AuditEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := readOut(t, filepath.Join(out, "bundle", "logs", "catalina.out")); got != archiveLogSanitized {
		t.Errorf("catalina.out = %q", got)
	}
	if got := gunzipFile(t, filepath.Join(out, "bundle", "logs", "catalina.1.log.gz")); got != archiveLogSanitized {
		t.Errorf("catalina.1.log.gz = %q", got)
	}
	for _, p := range []string{filepath.Join(root, "evil.log"), filepath.Join(out, "evil.log"), "/abs/evil.log"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("unsafe archive entry written to %s", p)
		}
	}
	skipped := map[string]string{}
	for _, s := range result.FilesSkipped {
		skipped[s.RelPath] = s.Reason
	}
	for _, want := range []string{"bundle/../evil.log", "bundle//abs/evil.log", "bundle/inner/nested.zip"} {
		if _, ok := skipped[filepath.FromSlash(want)]; !ok {
			t.Errorf("%s not listed as skipped; skipped = %v", want, skipped)
		}
	}

	// Skipped files are listed at the top of _summary.txt.
	summary := readOut(t, filepath.Join(out, "_summary.txt"))
	if !strings.HasPrefix(summary, "Skipped files (") {
		t.Errorf("_summary.txt does not start with the skipped list:\n%s", summary)
	}
}

// P1.4: archives inside a bundle directory (.zip, .tar.gz) are extracted in
// place; tar symlinks are skipped.
func TestArchivesInsideBundle(t *testing.T) {
	in := t.TempDir()
	os.WriteFile(filepath.Join(in, "support.zip"), zipBytes(t, zipEntry{"a.log", []byte(archiveLog)}), 0o644)

	var tb bytes.Buffer
	zw := gzip.NewWriter(&tb)
	tw := tar.NewWriter(zw)
	tw.WriteHeader(&tar.Header{Name: "web/access.log", Mode: 0o644, Size: int64(len(archiveLog)), Typeflag: tar.TypeReg})
	tw.Write([]byte(archiveLog))
	tw.WriteHeader(&tar.Header{Name: "web/link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
	tw.Close()
	zw.Close()
	os.WriteFile(filepath.Join(in, "httpd.tar.gz"), tb.Bytes(), 0o644)

	out := filepath.Join(t.TempDir(), "out")
	result, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := readOut(t, filepath.Join(out, "support", "a.log")); got != archiveLogSanitized {
		t.Errorf("support/a.log = %q", got)
	}
	if got := readOut(t, filepath.Join(out, "httpd", "web", "access.log")); got != archiveLogSanitized {
		t.Errorf("httpd/web/access.log = %q", got)
	}
	found := false
	for _, s := range result.FilesSkipped {
		if s.RelPath == filepath.Join("httpd", "web", "link") {
			found = true
		}
	}
	if !found {
		t.Errorf("tar symlink not listed as skipped: %+v", result.FilesSkipped)
	}
}

package sanitize

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"sas-log-sanitize/internal/tokenize"
)

// writeScaleBundle writes a multi-file bundle whose files share values in
// different first-seen orders, so token numbering depends on processing
// order -- the property parallel Pass 1 must preserve.
func writeScaleBundle(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for f := 0; f < 12; f++ {
		var sb strings.Builder
		for i := 0; i < 200; i++ {
			k := (f*7 + i*3) % 37
			fmt.Fprintf(&sb, "2026-11-10 INFO user=u%02d from 10.0.%d.%d to https://web%02d.corp.example.com:8443/app?code=c%d\n", k, f, i%250, k%9, i)
			fmt.Fprintf(&sb, "2026-11-10 WARN host db%02d.corp.example.com via CN=User %d,OU=Users,DC=corp,DC=com later u%02d\n", (k+f)%11, k, (k+5)%37)
		}
		writeTestFile(t, dir, fmt.Sprintf("sub%d/app%02d.log", f%3, f), sb.String())
	}
	return dir
}

type scaleRun struct {
	files   map[string]string
	mapping map[string]map[string]string
	result  Result
}

func runScale(t *testing.T, in string, workers int, progress *bytes.Buffer) scaleRun {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	opts := Options{InputDir: in, OutputDir: out, AuditEnabled: true, Workers: workers}
	if progress != nil {
		opts.Progress = progress
	}
	result, err := Sanitize(opts)
	if err != nil {
		t.Fatalf("Sanitize(workers=%d): %v", workers, err)
	}
	files := map[string]string{}
	filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && !strings.HasPrefix(d.Name(), "_") {
			data, _ := os.ReadFile(p)
			rel, _ := filepath.Rel(out, p)
			files[rel] = string(data)
		}
		return nil
	})
	mf, err := tokenize.LoadMappingFile(result.MappingPath)
	if err != nil {
		t.Fatal(err)
	}
	return scaleRun{files: files, mapping: mf.Categories, result: result}
}

// P1.3: Pass 1 and Pass 2 run per file in parallel, yet token numbering,
// output, counts and audit findings are identical to a sequential run.
func TestParallelRunMatchesSequential(t *testing.T) {
	in := writeScaleBundle(t)
	seq := runScale(t, in, 1, nil)
	for _, workers := range []int{4, 16} {
		par := runScale(t, in, workers, nil)
		if !reflect.DeepEqual(seq.mapping, par.mapping) {
			t.Errorf("workers=%d: mapping differs from sequential run", workers)
		}
		if !reflect.DeepEqual(seq.files, par.files) {
			t.Errorf("workers=%d: sanitized output differs from sequential run", workers)
		}
		if !reflect.DeepEqual(seq.result.ReplacementCounts, par.result.ReplacementCounts) {
			t.Errorf("workers=%d: replacement counts %v, sequential %v", workers, par.result.ReplacementCounts, seq.result.ReplacementCounts)
		}
		if !reflect.DeepEqual(seq.result.AuditFindings, par.result.AuditFindings) {
			t.Errorf("workers=%d: audit findings differ from sequential run", workers)
		}
	}
	if len(seq.files) != 12 || len(seq.mapping["USER"]) == 0 {
		t.Fatalf("bundle not exercised: %d files, %d users", len(seq.files), len(seq.mapping["USER"]))
	}
}

// P1.3: progress (files, MB, MB/s, ETA) is reported for both passes.
func TestProgressReported(t *testing.T) {
	var buf bytes.Buffer
	runScale(t, writeScaleBundle(t), 4, &buf)
	for _, want := range []string{"pass 1: 12/12 files", "pass 2: 12/12 files", "MB/s"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("progress output lacks %q:\n%s", want, buf.String())
		}
	}
}

// P1.3: a single large file is processed in parallel chunks; the result must
// still equal a sequential run, including a PEM block that straddles a
// chunk boundary and line numbers in audit findings.
func TestChunkedSingleFileMatchesSequential(t *testing.T) {
	dir := t.TempDir()
	var sb strings.Builder
	for i := 0; i < 5000; i++ {
		if i == 1020 {
			sb.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")
			for j := 0; j < 10; j++ {
				sb.WriteString("MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n")
			}
			sb.WriteString("-----END RSA PRIVATE KEY-----\n")
		}
		fmt.Fprintf(&sb, "line %d user=u%03d host db%02d.corp.example.com ip 10.9.%d.%d app%02d\r\n", i, (i*7)%301, i%17, i%200, i%250, i%13)
	}
	writeTestFile(t, dir, "catalina.out", sb.String())
	seq := runScale(t, dir, 1, nil)
	par := runScale(t, dir, 12, nil)
	if !reflect.DeepEqual(seq.files, par.files) || !reflect.DeepEqual(seq.mapping, par.mapping) ||
		!reflect.DeepEqual(seq.result.AuditFindings, par.result.AuditFindings) ||
		!reflect.DeepEqual(seq.result.ReplacementCounts, par.result.ReplacementCounts) {
		t.Fatal("chunked parallel run differs from sequential run")
	}
	out := seq.files["catalina.out"]
	if strings.Contains(out, "MIIEow") || strings.Count(out, "SECRET_REDACTED\n") != 12 {
		t.Errorf("PEM block across a chunk boundary not fully redacted")
	}
	if !strings.Contains(out, "\r\n") {
		t.Errorf("CRLF line endings not preserved")
	}
}

// Encoding is detected from the first 64 KB. A Windows-1252 byte appearing
// later (in a file the sample says is UTF-8) must neither corrupt output
// bytes nor hide a value from the detectors -- e.g. an accented name in a DN.
func TestLateWindows1252BytesRoundTrip(t *testing.T) {
	in := t.TempDir()
	head := strings.Repeat("2026-11-10 INFO plain ascii line for the encoding sample\n", 2000) // > 64 KB
	late := "bind CN=Jos\xe9 Garc\xeda,OU=Users,DC=corp,DC=com from db01.corp.example.com\n"
	utf8Line := "café served by db01.corp.example.com\n"
	writeTestFile(t, in, "mixed.log", head+late+utf8Line)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := Sanitize(Options{InputDir: in, OutputDir: out}); err != nil {
		t.Fatal(err)
	}
	got := readOut(t, filepath.Join(out, "mixed.log"))
	want := head + "bind DN_001 from HOST_001\n" + "café served by HOST_001\n"
	if got != want {
		t.Errorf("tail of output:\n got  %q\n want %q", got[len(head):], want[len(head):])
	}
}

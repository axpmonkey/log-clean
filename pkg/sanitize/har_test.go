package sanitize

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// harDoc is the subset of a HAR file the P1.2 assertions look at.
type harDoc struct {
	Log struct {
		Entries []struct {
			Time    float64        `json:"time"`
			Timings map[string]any `json:"timings"`
			Request struct {
				Method      string                         `json:"method"`
				URL         string                         `json:"url"`
				HeadersSize int                            `json:"headersSize"`
				BodySize    int                            `json:"bodySize"`
				Headers     []struct{ Name, Value string } `json:"headers"`
				Cookies     []struct{ Name, Value string } `json:"cookies"`
				QueryString []struct{ Name, Value string } `json:"queryString"`
				PostData    *struct {
					Text   string                         `json:"text"`
					Params []struct{ Name, Value string } `json:"params"`
				} `json:"postData"`
			} `json:"request"`
			Response struct {
				Status      int                            `json:"status"`
				RedirectURL string                         `json:"redirectURL"`
				BodySize    int                            `json:"bodySize"`
				Headers     []struct{ Name, Value string } `json:"headers"`
				Cookies     []struct{ Name, Value string } `json:"cookies"`
				Content     map[string]any                 `json:"content"`
			} `json:"response"`
			ServerIPAddress string `json:"serverIPAddress"`
		} `json:"entries"`
	} `json:"log"`
}

func readHAR(t *testing.T, path string) (harDoc, []byte) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatalf("%s is not valid JSON:\n%s", path, data)
	}
	var h harDoc
	if err := json.Unmarshal(data, &h); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return h, data
}

// endpoints is how har-analyze groups requests: method + URL path (host,
// port and query values excluded).
func endpoints(t *testing.T, h harDoc) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, e := range h.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil {
			t.Fatalf("unparseable request URL %q: %v", e.Request.URL, err)
		}
		out[e.Request.Method+" "+u.Path] = true
	}
	return out
}

func sanitizeHAR(t *testing.T, keepBodies bool) (in, out harDoc, raw []byte) {
	t.Helper()
	inPath := filepath.Join(goldenRoot, "sample_har", "input", "sample.har")
	outDir := filepath.Join(t.TempDir(), "out")
	if _, err := Sanitize(Options{InputDir: filepath.Dir(inPath), OutputDir: outDir, AuditEnabled: true, KeepHARBodies: keepBodies}); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	in, _ = readHAR(t, inPath)
	out, raw = readHAR(t, filepath.Join(outDir, "sample.har"))
	return in, out, raw
}

// P1.2 (golden fixture 9): a HAR is processed as JSON, not as text lines.
func TestHARSanitizedAsJSON(t *testing.T) {
	in, out, raw := sanitizeHAR(t, false)

	if len(out.Log.Entries) != len(in.Log.Entries) {
		t.Fatalf("entries: got %d, want %d", len(out.Log.Entries), len(in.Log.Entries))
	}
	for i := range in.Log.Entries {
		ie, oe := in.Log.Entries[i], out.Log.Entries[i]
		// Timings, sizes, status, method untouched.
		if ie.Time != oe.Time || !reflect.DeepEqual(ie.Timings, oe.Timings) {
			t.Errorf("entry %d: timings changed: %v/%v -> %v/%v", i, ie.Time, ie.Timings, oe.Time, oe.Timings)
		}
		if ie.Request.Method != oe.Request.Method || ie.Response.Status != oe.Response.Status ||
			ie.Request.HeadersSize != oe.Request.HeadersSize || ie.Request.BodySize != oe.Request.BodySize ||
			ie.Response.BodySize != oe.Response.BodySize {
			t.Errorf("entry %d: method/status/sizes changed", i)
		}
		// Header names kept, in order.
		for j, h := range ie.Request.Headers {
			if oe.Request.Headers[j].Name != h.Name {
				t.Errorf("entry %d: header name %q became %q", i, h.Name, oe.Request.Headers[j].Name)
			}
		}
		// Cookie values redacted, names kept.
		for _, c := range append(oe.Request.Cookies, oe.Response.Cookies...) {
			if c.Name != "JSESSIONID" || c.Value != "SECRET_REDACTED" {
				t.Errorf("entry %d: cookie not redacted: %+v", i, c)
			}
		}
		// Credential headers redacted entirely.
		for _, h := range append(oe.Request.Headers, oe.Response.Headers...) {
			switch strings.ToLower(h.Name) {
			case "cookie", "set-cookie", "authorization", "proxy-authorization", "x-csrf-token":
				if h.Value != "SECRET_REDACTED" {
					t.Errorf("entry %d: %s header = %q", i, h.Name, h.Value)
				}
			}
		}
		// Response bodies dropped by default.
		if _, ok := oe.Response.Content["text"]; ok {
			t.Errorf("entry %d: response body kept without --keep-har-bodies", i)
		}
		if oe.Response.Content["size"] != ie.Response.Content["size"] {
			t.Errorf("entry %d: content size changed", i)
		}
	}

	// URLs host-tokenized, with path and port kept and ticket redacted.
	e0 := out.Log.Entries[0]
	if want := "https://HOST_001:8343/SASLogon/login?ticket=SECRET_REDACTED&service=x"; e0.Request.URL != want {
		t.Errorf("request.url = %q, want %q", e0.Request.URL, want)
	}
	if want := "https://HOST_001:8343/SASDrive/"; e0.Response.RedirectURL != want {
		t.Errorf("redirectURL = %q, want %q", e0.Response.RedirectURL, want)
	}
	if e0.Request.QueryString[0].Value != "SECRET_REDACTED" || e0.Request.QueryString[1].Value != "x" {
		t.Errorf("queryString = %+v", e0.Request.QueryString)
	}
	if !strings.HasPrefix(e0.ServerIPAddress, "IPV4_") {
		t.Errorf("serverIPAddress = %q", e0.ServerIPAddress)
	}
	pd := out.Log.Entries[1].Request.PostData
	if pd == nil || pd.Params[2].Value != "SECRET_REDACTED" || strings.Contains(pd.Text, "Secret1") {
		t.Errorf("postData not sanitized: %+v", pd)
	}

	// Same endpoint set (modulo hostnames) before and after.
	if a, b := endpoints(t, in), endpoints(t, out); !reflect.DeepEqual(a, b) {
		t.Errorf("endpoints changed:\n in:  %v\n out: %v", a, b)
	}

	for _, leak := range []string{"sasprd03", "jdoe", "Secret1", "ST-1-abc", "10.20.30.4", "8F3A2B1C", "1122334455667788",
		"c2FzZGVtbzpQYXNzd29yZDE", "YIIGhgYG", "6c1f0e2d", "eyJhbGciOi", "Welcome back"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("sanitized HAR contains %q", leak)
		}
	}
}

// P1.2: --keep-har-bodies keeps response bodies, but scans them.
func TestHARKeepBodies(t *testing.T) {
	_, out, raw := sanitizeHAR(t, true)
	text, _ := out.Log.Entries[0].Response.Content["text"].(string)
	if !strings.Contains(text, "Welcome back") {
		t.Errorf("body not kept: %q", text)
	}
	for _, leak := range []string{"jdoe", "eyJhbGciOi"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("kept body leaks %q", leak)
		}
	}
}

// A gzipped HAR is handled as a HAR and written back gzipped.
func TestHARGzip(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(goldenRoot, "sample_har", "input", "sample.har"))
	if err != nil {
		t.Fatal(err)
	}
	in := t.TempDir()
	os.WriteFile(filepath.Join(in, "sample.har.gz"), gzipBytes(t, string(raw)), 0o644)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true}); err != nil {
		t.Fatal(err)
	}
	got := gunzipFile(t, filepath.Join(out, "sample.har.gz"))
	if !json.Valid([]byte(got)) {
		t.Fatalf("output is not valid JSON:\n%s", got)
	}
	var h harDoc
	json.Unmarshal([]byte(got), &h)
	if c := h.Log.Entries[0].Request.Cookies[0]; c.Value != "SECRET_REDACTED" {
		t.Errorf("cookie not redacted: %+v", c)
	}
	for _, leak := range []string{"sasprd03", "jdoe", "Welcome back"} {
		if strings.Contains(got, leak) {
			t.Errorf("leaks %q", leak)
		}
	}
}

// A truncated HAR can't be parsed: both passes fall back to line-based
// sanitization, so the output is the text-sanitized file, never half a
// JSON document.
func TestTruncatedHARFallsBack(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join(goldenRoot, "sample_har", "input", "sample.har"))
	in := t.TempDir()
	cut := string(raw[:len(raw)/2])
	writeTestFile(t, in, "cut.har", cut)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true, Verbose: true}); err != nil {
		t.Fatal(err)
	}
	got := readOut(t, filepath.Join(out, "cut.har"))
	if strings.Count(got, "\n") > 1 || strings.Contains(got, "sasprd03") || !strings.Contains(got, "HOST_001") {
		t.Errorf("not text-sanitized as one line:\n%.300s", got)
	}
	if log := readOut(t, filepath.Join(out, "_runlog.txt")); !strings.Contains(log, "falling back to line-based") {
		t.Errorf("runlog lacks the fallback note")
	}
}

package har

import (
	"io"
	"strings"
	"testing"
	"time"
)

func identity(s string) string { return s }

// Key order and number text survive a round trip, so sanitized HARs diff
// cleanly against the input (output is always indented, one value per line,
// so audit lines stay short).
func TestTransformPreservesOrderAndNumbers(t *testing.T) {
	in := `{"log":{"version":"1.2","entries":[{"time":245.310,"zeta":1e3,"alpha":-0.0,"empty":{},"none":[],"request":{"method":"GET","url":"x"}}]}}`
	want := `{
  "log": {
    "version": "1.2",
    "entries": [
      {
        "time": 245.310,
        "zeta": 1e3,
        "alpha": -0.0,
        "empty": {},
        "none": [],
        "request": {
          "method": "GET",
          "url": "x"
        }
      }
    ]
  }
}
`
	out, n, err := Transform([]byte(in), Options{}, identity)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != want || n != 0 {
		t.Errorf("round trip (n=%d):\n%s\nwant:\n%s", n, out, want)
	}
}

func TestTransformRejectsNonHAR(t *testing.T) {
	for name, in := range map[string]string{
		"truncated":  `{"log":{"entries":[{"time":1`,
		"no log key": `{"entries":[]}`,
		"not object": `[1,2]`,
		"trailing":   `{"log":{}} {"log":{}}`,
	} {
		if _, _, err := Transform([]byte(in), Options{}, identity); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLooks(t *testing.T) {
	if !Looks("x.har", []byte("garbage")) {
		t.Error(".har should always be handled as HAR")
	}
	if !Looks("x.json", []byte("\xEF\xBB\xBF  {\n \"log\": {")) {
		t.Error("HAR-shaped .json with BOM not recognized")
	}
	if Looks("x.json", []byte(`{"name":"other"}`)) || Looks("x.log", []byte(`{"log":{}}`)) {
		t.Error("non-HAR recognized as HAR")
	}
}

// The HAR is streamed: an entry's output is written before later entries
// have even been read, so memory is bounded by the largest single entry, not
// the file.
func TestTransformStreams(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		_, err := TransformStream(inR, outW, Options{}, func(s string) string { return strings.ToUpper(s) })
		outW.CloseWithError(err)
	}()
	go func() {
		io.WriteString(inW, `{"log":{"entries":[{"request":{"url":"first-entry"}},`)
		// The second entry is only written once the first one's output has
		// been seen (signalled via the channel below).
		<-firstSeen
		io.WriteString(inW, `{"request":{"url":"second"}}]}}`)
		inW.Close()
	}()
	// Read until the first entry's output shows up, in a goroutine so a
	// non-streaming implementation fails the deadline instead of hanging.
	got := make(chan string, 1)
	go func() {
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 256)
		for !strings.Contains(string(buf), "FIRST-ENTRY") {
			n, err := outR.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if err != nil {
				break
			}
		}
		got <- string(buf)
	}()
	select {
	case buf := <-got:
		if !strings.Contains(buf, "FIRST-ENTRY") {
			t.Fatalf("output ended before the first entry: %q", buf)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first entry not written before the rest of the input arrived (not streaming)")
	}
	close(firstSeen)
	rest, err := io.ReadAll(outR)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rest), "SECOND") {
		t.Errorf("second entry missing: %q", rest)
	}
}

var firstSeen = make(chan struct{})

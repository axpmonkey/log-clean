package pipeline

import (
	"bufio"
	"hash/maphash"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goldenLines returns every line of every golden fixture input (plus a few
// hand-picked lines that exercise claim-only spans and SAS internal
// accounts).
func goldenLines(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob("../../testdata/golden/*/input/*")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no golden inputs: %v", err)
	}
	lines := []string{
		"user=jdoe connected as sastrust@saspw from sas01.corp.example.com",
		"id 550e8400-e29b-41d4-a716-446655440000 host jdoe.corp.example.com user jdoe",
		"",
	}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 1<<24)
		for sc.Scan() {
			lines = append(lines, sc.Text())
		}
		f.Close()
	}
	return lines
}

// Running only a line's Pass 1 detectors (plus the sweep) must give exactly
// the full walk's output, with and without an allowlist detector.
func TestMaskedReplaceMatchesFullWalk(t *testing.T) {
	for _, opts := range []ChainOptions{{}, {Allowlist: []string{"sas01", "pghost"}}, {URLMode: URLModeWhole}} {
		p := New(DefaultDetectorChain(opts))
		lines := goldenLines(t)
		masks := make([]DetectorMask, len(lines))
		for i, line := range lines {
			masks[i] = p.ScanLineMask(line)
		}
		p.EnableKnownValuesSweep()
		for i, line := range lines {
			if got, want := p.ReplaceLineMasked(line, masks[i]), p.ReplaceLine(line); got != want {
				t.Errorf("opts %+v line %q:\n masked %q\n full   %q", opts, line, got, want)
			}
		}
		// A fork must carry the sweep boundary too.
		f := p.forkForReplace()
		for i, line := range lines {
			if got, want := f.ReplaceLineMasked(line, masks[i]), p.ReplaceLine(line); got != want {
				t.Errorf("fork: line %q:\n masked %q\n full   %q", line, got, want)
			}
		}
	}
}

// With the sweep enabled, a zero mask must still run the sweep.
func TestZeroMaskStillRunsSweep(t *testing.T) {
	p := New(DefaultDetectorChain(ChainOptions{}))
	p.ScanLine("user=jdoe")
	p.EnableKnownValuesSweep()
	if got := p.ReplaceLineMasked("jdoe logged in", 0); strings.Contains(got, "jdoe") {
		t.Errorf("sweep skipped under a zero mask: %q", got)
	}
}

func testChunk(lines ...string) *chunk {
	c := &chunk{}
	for _, l := range lines {
		c.lines = append(c.lines, lineItem{text: l})
	}
	return c
}

func TestMaskSidecarRoundTripAndFallback(t *testing.T) {
	seed := maphash.MakeSeed()
	w, err := newMaskWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := testChunk("one", "two")
	a.masks = []DetectorMask{0, 1 << 20}
	a.hash = chunkHash(seed, a)
	b := testChunk("three")
	b.masks = []DetectorMask{5}
	b.hash = chunkHash(seed, b)
	w.writeChunk(a)
	w.writeChunk(b)
	path, err := w.close()
	if err != nil {
		t.Fatal(err)
	}

	r, err := openMaskReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	ra := testChunk("one", "two")
	r.readChunk(ra)
	if len(ra.masks) != 2 || ra.masks[1] != 1<<20 || ra.wantHash != chunkHash(seed, ra) {
		t.Fatalf("round trip: masks %v wantHash ok=%v", ra.masks, ra.wantHash == chunkHash(seed, ra))
	}
	// Same line count, different text: masks are read, but the hash check
	// the worker does rejects them.
	rb := testChunk("THREE")
	r.readChunk(rb)
	if rb.masks == nil || rb.wantHash == chunkHash(seed, rb) {
		t.Fatal("changed chunk text not caught by the hash")
	}
	// Past the end: no masks, and the reader stays dead.
	rc := testChunk("x")
	r.readChunk(rc)
	if rc.masks != nil || !r.dead {
		t.Fatal("expected no masks past the end of the sidecar")
	}
}

func TestMaskSidecarLineCountMismatchKillsReader(t *testing.T) {
	w, err := newMaskWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := testChunk("one", "two")
	a.masks = []DetectorMask{1, 2}
	w.writeChunk(a)
	w.writeChunk(a)
	path, _ := w.close()
	r, _ := openMaskReader(path)
	defer r.close()
	c := testChunk("one")
	r.readChunk(c)
	d := testChunk("one", "two")
	r.readChunk(d)
	if c.masks != nil || d.masks != nil {
		t.Fatal("masks used after a line-count mismatch")
	}
}

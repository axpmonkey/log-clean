package detect

import "testing"

func TestLineStateNoOverlapInitially(t *testing.T) {
	ls := NewLineState()
	if ls.IsProtected(0, 5) {
		t.Error("fresh LineState reports a span as protected")
	}
}

func TestLineStateExactOverlap(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if !ls.IsProtected(10, 20) {
		t.Error("identical span not detected as protected")
	}
}

func TestLineStatePartialOverlapLeft(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if !ls.IsProtected(5, 15) {
		t.Error("left-overlapping span not detected as protected")
	}
}

func TestLineStatePartialOverlapRight(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if !ls.IsProtected(15, 25) {
		t.Error("right-overlapping span not detected as protected")
	}
}

func TestLineStateContainedWithin(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if !ls.IsProtected(12, 18) {
		t.Error("span fully contained within a claimed span not detected as protected")
	}
}

func TestLineStateContains(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if !ls.IsProtected(5, 25) {
		t.Error("span fully containing a claimed span not detected as protected")
	}
}

func TestLineStateSingleCharOverlap(t *testing.T) {
	// Per Decision 3, even a one-character overlap counts as protected --
	// there is no "matching around" a claimed sub-span.
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if !ls.IsProtected(19, 21) {
		t.Error("one-character overlap not detected as protected")
	}
}

func TestLineStateAdjacentNotOverlapping(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if ls.IsProtected(0, 10) {
		t.Error("span ending exactly where claimed span starts reported as protected")
	}
	if ls.IsProtected(20, 30) {
		t.Error("span starting exactly where claimed span ends reported as protected")
	}
}

func TestLineStateDisjointNotOverlapping(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{10, 20})
	if ls.IsProtected(30, 40) {
		t.Error("disjoint span reported as protected")
	}
}

func TestLineStateMultipleClaimsOutOfOrder(t *testing.T) {
	ls := NewLineState()
	ls.Claim(Span{50, 60})
	ls.Claim(Span{10, 20})
	ls.Claim(Span{30, 35})

	got := ls.Spans()
	want := []Span{{10, 20}, {30, 35}, {50, 60}}
	if len(got) != len(want) {
		t.Fatalf("got %d spans, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Spans()[%d] = %v, want %v", i, got[i], want[i])
		}
	}

	if !ls.IsProtected(15, 16) {
		t.Error("span inside first claim not protected")
	}
	if !ls.IsProtected(32, 33) {
		t.Error("span inside second claim not protected")
	}
	if ls.IsProtected(21, 29) {
		t.Error("span in the gap between claims reported as protected")
	}
}

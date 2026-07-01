package pipeline

import (
	"strings"
	"testing"

	"sas-log-sanitize/internal/detect"
)

// substringDetector is a minimal stub Detector for pipeline tests: it finds
// every non-overlapping occurrence of a literal substring and emits it as a
// match with the given category/redact behavior. Real regex-based detectors
// arrive in Milestone 3+; this is purely pipeline-orchestration scaffolding.
type substringDetector struct {
	name     string
	needle   string
	category string
	redact   bool
}

func (d substringDetector) Name() string { return d.name }

func (d substringDetector) Detect(line string) []detect.Match {
	if d.needle == "" {
		return nil
	}
	var matches []detect.Match
	start := 0
	for {
		i := strings.Index(line[start:], d.needle)
		if i < 0 {
			break
		}
		s := start + i
		e := s + len(d.needle)
		matches = append(matches, detect.Match{
			Span:     detect.Span{Start: s, End: e},
			Value:    d.needle,
			Category: d.category,
			Redact:   d.redact,
		})
		start = e
	}
	return matches
}

func TestPipelinePseudonymizeRoundTrip(t *testing.T) {
	p := New([]detect.Detector{
		substringDetector{name: "host", needle: "db-prod-01", category: "HOST"},
	})
	line := "connecting to db-prod-01 now"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if got != "connecting to HOST_001 now" {
		t.Errorf("ReplaceLine = %q", got)
	}
}

func TestPipelineRedactNeverRegistersInMapping(t *testing.T) {
	p := New([]detect.Detector{
		substringDetector{name: "pw", needle: "Passw0rd!", category: "PASSWORD", redact: true},
	})
	line := "password=Passw0rd! connecting"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if got != "password=SECRET_REDACTED connecting" {
		t.Errorf("ReplaceLine = %q", got)
	}
	if p.Registry.Count("PASSWORD") != 0 {
		t.Errorf("redacted match leaked into registry, Count = %d", p.Registry.Count("PASSWORD"))
	}
	mapping := p.Registry.Mapping()
	for cat, m := range mapping {
		for tok, val := range m {
			if val == "Passw0rd!" {
				t.Errorf("secret value found in mapping under %s/%s", cat, tok)
			}
		}
	}
}

func TestPipelineClaimOnlyMatchLeftInPlaceAndBlocksLaterDetectors(t *testing.T) {
	// uuidLike claims the span but assigns no category (claim-only, like the
	// real UUID detector in plan Decision 6). hostLike runs after it and
	// would otherwise match the same text.
	p := New([]detect.Detector{
		substringDetector{name: "claim-only", needle: "ABCD-1234", category: ""},
		substringDetector{name: "host", needle: "ABCD-1234", category: "HOST"},
	})
	line := "id=ABCD-1234 seen"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if got != line {
		t.Errorf("ReplaceLine = %q, want unchanged %q (claim-only match should not be replaced)", got, line)
	}
	if p.Registry.Count("HOST") != 0 {
		t.Errorf("later detector matched inside a claimed span; HOST count = %d", p.Registry.Count("HOST"))
	}
}

func TestPipelineEarlierDetectorWinsOnOverlap(t *testing.T) {
	// Both detectors would match overlapping text; the one earlier in
	// Detectors order claims it first per plan Decision 4.
	p := New([]detect.Detector{
		substringDetector{name: "email", needle: "foo@bar.com", category: "EMAIL"},
		substringDetector{name: "domain", needle: "bar.com", category: "DOMAIN"},
	})
	line := "contact foo@bar.com please"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if got != "contact EMAIL_001 please" {
		t.Errorf("ReplaceLine = %q", got)
	}
	if p.Registry.Count("DOMAIN") != 0 {
		t.Errorf("later overlapping detector still registered a match; DOMAIN count = %d", p.Registry.Count("DOMAIN"))
	}
}

func TestPipelineNonOverlappingMatchesBothApply(t *testing.T) {
	p := New([]detect.Detector{
		substringDetector{name: "host", needle: "db-prod-01", category: "HOST"},
		substringDetector{name: "user", needle: "jdoe", category: "USER"},
	})
	line := "jdoe connected to db-prod-01"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if got != "USER_001 connected to HOST_001" {
		t.Errorf("ReplaceLine = %q", got)
	}
}

func TestPipelineReplaceOrdersByPositionNotDetectorOrder(t *testing.T) {
	// "user" detector runs after "host" in Detectors order but matches text
	// that appears earlier in the line. ReplaceLine must still produce
	// correctly ordered output (walk() returns claim order, not position
	// order -- this verifies ReplaceLine's position sort).
	p := New([]detect.Detector{
		substringDetector{name: "host", needle: "db-prod-01", category: "HOST"},
		substringDetector{name: "user", needle: "jdoe", category: "USER"},
	})
	line := "jdoe connected to db-prod-01"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	want := "USER_001 connected to HOST_001"
	if got != want {
		t.Errorf("ReplaceLine = %q, want %q", got, want)
	}
}

func TestPipelineScanAndReplaceAgreeOnSameWalk(t *testing.T) {
	// Regression guard for the Pass1/Pass2 divergence risk called out in the
	// plan (Decision 2): both passes must derive their matches from the same
	// walk(), so every non-redacted match Pass 2 wants to replace was
	// necessarily registered by Pass 1.
	p := New([]detect.Detector{
		substringDetector{name: "email", needle: "foo@bar.com", category: "EMAIL"},
		substringDetector{name: "domain", needle: "bar.com", category: "DOMAIN"},
		substringDetector{name: "host", needle: "db-prod-01", category: "HOST"},
	})
	line := "contact foo@bar.com about db-prod-01"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if strings.Contains(got, "TOKEN_MISSING") {
		t.Errorf("ReplaceLine produced a TOKEN_MISSING marker, indicating Pass1/Pass2 divergence: %q", got)
	}
}

func TestPipelineEmptyLine(t *testing.T) {
	p := New([]detect.Detector{
		substringDetector{name: "host", needle: "db-prod-01", category: "HOST"},
	})
	p.ScanLine("")
	if got := p.ReplaceLine(""); got != "" {
		t.Errorf("ReplaceLine(\"\") = %q, want empty", got)
	}
}

func TestPipelineNoDetectors(t *testing.T) {
	p := New(nil)
	line := "nothing to see here"
	p.ScanLine(line)
	if got := p.ReplaceLine(line); got != line {
		t.Errorf("ReplaceLine with no detectors = %q, want unchanged", got)
	}
}

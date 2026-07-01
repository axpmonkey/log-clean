package pipeline

import (
	"testing"

	"sas-log-sanitize/internal/detect"
)

func TestReplacementCountsTracksOccurrencesNotUniqueValues(t *testing.T) {
	p := New([]detect.Detector{
		substringDetector{name: "host", needle: "db-prod-01", category: "HOST"},
		substringDetector{name: "pw", needle: "Secret1", category: "PASSWORD", redact: true},
	})
	lines := []string{
		"db-prod-01 connected",
		"db-prod-01 connected again", // same value, second occurrence
		"password=Secret1",
	}
	for _, l := range lines {
		p.ScanLine(l)
	}
	for _, l := range lines {
		p.ReplaceLine(l)
	}

	counts := p.ReplacementCounts()
	if counts["HOST"] != 2 {
		t.Errorf("HOST replacement count = %d, want 2 (occurrences, not unique values)", counts["HOST"])
	}
	if counts["SECRET"] != 1 {
		t.Errorf("SECRET replacement count = %d, want 1", counts["SECRET"])
	}
}

package pipeline

import (
	"strings"
	"testing"
)

func TestReverseSubstitutesKnownTokens(t *testing.T) {
	categories := map[string]map[string]string{
		"HOST": {"HOST_001": "db-prod-01.acme.internal"},
		"USER": {"USER_001": "jdoe"},
	}
	got := Reverse(categories, "connected as USER_001 to HOST_001 now")
	want := "connected as jdoe to db-prod-01.acme.internal now"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReverseLeavesUnknownTokenUnchanged(t *testing.T) {
	categories := map[string]map[string]string{"HOST": {"HOST_001": "db-prod-01"}}
	got := Reverse(categories, "see HOST_999 for details")
	if got != "see HOST_999 for details" {
		t.Errorf("got %q, want unchanged (HOST_999 was never in the mapping)", got)
	}
}

func TestReverseLeavesSecretRedactedUnchanged(t *testing.T) {
	// SECRET_REDACTED is not reversible by design -- the original secret was
	// never recorded anywhere (plan Decision 5).
	categories := map[string]map[string]string{"HOST": {"HOST_001": "db-prod-01"}}
	got := Reverse(categories, "password=SECRET_REDACTED for HOST_001")
	want := "password=SECRET_REDACTED for db-prod-01"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestReverseEmptyMapping(t *testing.T) {
	got := Reverse(map[string]map[string]string{}, "HOST_001 USER_002")
	if got != "HOST_001 USER_002" {
		t.Errorf("got %q, want unchanged", got)
	}
}

// TestRoundTripReversibility exercises the full property from the plan's
// testing strategy: reverse(sanitize(input)) == input, modulo redacted
// secrets (which are intentionally not reversible).
func TestRoundTripReversibility(t *testing.T) {
	p := New(identityDetectors())
	lines := []string{
		"2026-06-30 13:00:00.000 INFO connecting to jdbc:postgresql://jdoe:Secret1@db-prod-01.acme.internal:5432/sasdb",
		"2026-06-30 13:00:01.000 INFO Notification sent to jdoe@acme.internal",
		"2026-06-30 13:00:02.000 INFO Reading /home/jdoe/config.txt",
	}

	for _, l := range lines {
		p.ScanLine(l)
	}

	categories := p.Registry.Mapping()
	for _, original := range lines {
		sanitized := p.ReplaceLine(original)
		reversed := Reverse(categories, sanitized)

		// The password is redacted, not reversible, so the reversed line
		// won't exactly equal the original wherever a secret was redacted.
		// Replace the known secret in the original with the redaction
		// marker to get the expected reversed form.
		expected := strings.ReplaceAll(original, "Secret1", "SECRET_REDACTED")
		if reversed != expected {
			t.Errorf("round trip mismatch:\n original:  %q\n sanitized: %q\n reversed:  %q\n want:      %q",
				original, sanitized, reversed, expected)
		}
	}
}

package detect

import (
	"strings"
	"testing"
)

func TestLoadAllowlistParsesEntriesSkippingCommentsAndBlanks(t *testing.T) {
	input := strings.NewReader(`
# customer-supplied hostnames
db-prod-01.acme.internal
app-prod-01.acme.internal

# another comment
mq-prod-01
`)
	entries, _, err := LoadAllowlist(input)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3: %v", len(entries), entries)
	}
}

func TestLoadAllowlistSortsLongestFirst(t *testing.T) {
	input := strings.NewReader("short1\nmuch-longer-hostname.acme.internal\nmid-host\n")
	entries, _, err := LoadAllowlist(input)
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	want := []string{"much-longer-hostname.acme.internal", "mid-host", "short1"}
	if len(entries) != len(want) {
		t.Fatalf("got %v, want %v", entries, want)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entries[%d] = %q, want %q", i, entries[i], want[i])
		}
	}
}

func TestLoadAllowlistWarnsOnShortEntries(t *testing.T) {
	entries, warnings, err := LoadAllowlist(strings.NewReader("db1\ndb-prod-01.acme.internal\n"))
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, `"db1"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about short entry %q, got warnings: %v", "db1", warnings)
	}
}

func TestLoadAllowlistWarnsOnSubstringEntries(t *testing.T) {
	_, warnings, err := LoadAllowlist(strings.NewReader("dbprod\ndbprod01\n"))
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	found := false
	for _, w := range warnings {
		if strings.Contains(w, `"dbprod"`) && strings.Contains(w, `"dbprod01"`) {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a substring-collision warning, got: %v", warnings)
	}
}

func TestLoadAllowlistNoWarningsForCleanEntries(t *testing.T) {
	_, warnings, err := LoadAllowlist(strings.NewReader("db-prod-01.acme.internal\napp-prod-01.acme.internal\n"))
	if err != nil {
		t.Fatalf("LoadAllowlist: %v", err)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings for clean entries: %v", warnings)
	}
}

func TestAllowlistDetector(t *testing.T) {
	cases := []struct {
		name  string
		hosts []string
		input string
		want  []string
	}{
		{"bare hostname in path", []string{"db-prod-01"}, "/var/log/db-prod-01-archive/out.log", []string{"db-prod-01"}},
		{"hostname inside compound string", []string{"mqprod01"}, "connecting to mqprod01-backup now", []string{"mqprod01"}},
		{"standalone match", []string{"app-prod-01.acme.internal"}, "host app-prod-01.acme.internal is up", []string{"app-prod-01.acme.internal"}},

		{"no match", []string{"nomatch-host"}, "totally unrelated text", nil},
		{"empty allowlist", []string{}, "db-prod-01 mentioned here", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := NewAllowlistDetector(c.hosts, false)
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "HOST")
		})
	}
}

func TestAllowlistDetectorMultipleHostsOrderIndependent(t *testing.T) {
	// hostA and hostB are equal length, so NewAllowlistDetector's
	// longest-first sort doesn't guarantee which is tried first; this test
	// checks both are found without depending on that order (unlike
	// expectSubstringMatches, which assumes line-position order).
	d := NewAllowlistDetector([]string{"hostA", "hostB"}, false)
	matches := d.Detect("from hostA to hostB")
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2: %+v", len(matches), matches)
	}
	values := map[string]bool{}
	for _, m := range matches {
		values[m.Value] = true
		if m.Category != "HOST" {
			t.Errorf("match %+v category = %q, want HOST", m, m.Category)
		}
	}
	if !values["hostA"] || !values["hostB"] {
		t.Errorf("matches = %+v, want both hostA and hostB present", matches)
	}
}

func TestAllowlistDetectorCaseInsensitive(t *testing.T) {
	d := NewAllowlistDetector([]string{"db-prod-01"}, true)
	line := "seen DB-PROD-01 and db-prod-01 today"
	matches := d.Detect(line)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want 2 (both cases): %+v", len(matches), matches)
	}
	// The tokenized Value is the exact text from the line, so a reverse
	// round-trip restores original casing rather than the allowlist entry's.
	if matches[0].Value != "DB-PROD-01" {
		t.Errorf("match 0 Value = %q, want the exact cased text DB-PROD-01", matches[0].Value)
	}
	if matches[1].Value != "db-prod-01" {
		t.Errorf("match 1 Value = %q, want db-prod-01", matches[1].Value)
	}
}

func TestAllowlistDetectorCaseSensitiveByDefault(t *testing.T) {
	d := NewAllowlistDetector([]string{"db-prod-01"}, false)
	if matches := d.Detect("seen DB-PROD-01 today"); len(matches) != 0 {
		t.Errorf("case-sensitive detector matched a differently-cased host: %+v", matches)
	}
}

func TestAllowlistDetectorLongestMatchFirst(t *testing.T) {
	// "db-prod-01" is a substring of "db-prod-01-archive"; longest-first
	// ordering means the longer entry should claim the span (per the
	// pipeline's first-come overlap rule), leaving the shorter entry's
	// candidate for that same text unclaimed.
	d := NewAllowlistDetector([]string{"db-prod-01", "db-prod-01-archive"}, false)
	line := "backing up db-prod-01-archive now"

	accepted := resolveOverlaps(d.Detect(line))
	if len(accepted) != 1 {
		t.Fatalf("got %d accepted matches, want 1: %+v", len(accepted), accepted)
	}
	if accepted[0].Value != "db-prod-01-archive" {
		t.Errorf("accepted match = %q, want the longer entry to win", accepted[0].Value)
	}
}

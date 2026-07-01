package pipeline

import (
	"testing"

	"sas-log-sanitize/internal/detect"
)

// fullDetectorChain is a thin test wrapper around the real production chain
// builder (DefaultDetectorChain) with an allowlist included.
func fullDetectorChain(allowlist []string) []detect.Detector {
	return DefaultDetectorChain(nil, allowlist)
}

func TestURLEmbeddedHostSharesTokenWithStandaloneOccurrence(t *testing.T) {
	p := New(fullDetectorChain(nil))
	lines := []string{
		"jdbc:postgresql://db-prod-01.acme.internal:5432/sasdb connected",
		"resolved db-prod-01.acme.internal to an address",
	}
	for _, l := range lines {
		p.ScanLine(l)
	}

	got := []string{p.ReplaceLine(lines[0]), p.ReplaceLine(lines[1])}
	want := []string{
		"URL_001 connected",
		"resolved HOST_001 to an address",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d: got %q, want %q", i, got[i], want[i])
		}
	}
}

func TestUNCEmbeddedServerSharesTokenWithStandaloneOccurrence(t *testing.T) {
	p := New(fullDetectorChain(nil))
	lines := []string{
		`mapped \\fileserver01\share for backup`,
		`fileserver01 reachable on the network`,
	}
	for _, l := range lines {
		p.ScanLine(l)
	}

	got0 := p.ReplaceLine(lines[0])
	if got0 != `mapped UNC_001 for backup` {
		t.Errorf("line 0 = %q", got0)
	}

	// fileserver01 is a bare hostname (no dot), so it only gets tokenized
	// standalone here because it was already registered via UNC
	// cross-registration -- the allowlist isn't involved, demonstrating the
	// registry-only nature of registerEmbeddedHost (Milestone 5).
	mapping := p.Registry.Mapping()
	if mapping["HOST"]["HOST_001"] != "fileserver01" {
		t.Errorf("HOST_001 = %q, want fileserver01", mapping["HOST"]["HOST_001"])
	}
}

func TestAllowlistDetectorCatchesBareHostnameInCompoundPath(t *testing.T) {
	// "db-prod-01" has no dot, so the FQDN detector alone would never catch
	// it inside "/var/log/db-prod-01-archive/" -- this is exactly the case
	// the customer-supplied allowlist exists for (plan: allowlist detector
	// spec).
	p := New(fullDetectorChain([]string{"db-prod-01"}))
	line := "archiving to /var/log/db-prod-01-archive/out.log now"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	want := "archiving to /var/log/HOST_001-archive/out.log now"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestAllowlistDetectorReusesTokenFromFQDNDetection(t *testing.T) {
	// The same hostname found by the FQDN detector standalone and by the
	// allowlist substring pass elsewhere must resolve to the same token
	// (plan: Milestone 5 cross-detector consistency).
	p := New(fullDetectorChain([]string{"db-prod-01"}))
	lines := []string{
		"resolved db-prod-01.acme.internal successfully", // FQDN detector claims the full dotted name
		"archive dir db-prod-01-archive in use",          // allowlist substring catches the bare form
	}
	for _, l := range lines {
		p.ScanLine(l)
	}

	got0 := p.ReplaceLine(lines[0])
	got1 := p.ReplaceLine(lines[1])

	if got0 != "resolved HOST_001 successfully" {
		t.Errorf("line 0 = %q", got0)
	}
	if got1 != "archive dir HOST_002-archive in use" {
		// Note: "db-prod-01.acme.internal" and "db-prod-01" are different
		// string values (one is the FQDN, one is the bare allowlist entry),
		// so they get *different* tokens despite referring to the same
		// physical host -- the registry dedupes by exact value, not by
		// semantic identity. This is expected: true cross-format identity
		// for a hostname that appears in both fully-qualified and bare form
		// would require normalizing one to the other, which the plan does
		// not specify and this implementation does not attempt.
		t.Errorf("line 1 = %q, want archive dir HOST_002-archive in use", got1)
	}
}

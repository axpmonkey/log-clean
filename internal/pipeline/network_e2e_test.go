package pipeline

import (
	"testing"

	"sas-log-sanitize/internal/audit"
	"sas-log-sanitize/internal/detect"
)

// TestNetworkDetectorsEndToEnd exercises the real Milestone 3 detectors
// (UUID, URL, FQDN, IPv4, IPv6, MAC) through the actual two-pass pipeline
// against a synthetic SAS-log-shaped bundle, then re-scans the sanitized
// output with the audit package to confirm nothing residual leaked through.
// Detector order follows plan Decision 4 (UUID first per the addendum, then
// URL, FQDN, IPv4, IPv6, MAC).
func TestNetworkDetectorsEndToEnd(t *testing.T) {
	lines := []string{
		"2026-06-30 12:00:00.123 INFO Session 550e8400-e29b-41d4-a716-446655440000 started",
		"2026-06-30 12:00:01.000 INFO Connecting to jdbc:postgresql://db-prod-01.acme.internal:5432/sasdb",
		"2026-06-30 12:00:02.500 INFO Resolved db-prod-01.acme.internal to 10.20.30.40",
		"2026-06-30 12:00:03.750 WARN SAS 9.4.1.2 license check",
		"2026-06-30 12:00:04.900 DEBUG IPv6 peer fe80::1%eth0 MAC 00:1A:2B:3C:4D:5E",
	}

	p := New([]detect.Detector{
		detect.UUIDDetector{},
		detect.URLDetector{},
		detect.FQDNDetector{},
		detect.IPv4Detector{},
		detect.IPv6Detector{},
		detect.MACDetector{},
	})

	for _, line := range lines {
		p.ScanLine(line)
	}

	want := []string{
		"2026-06-30 12:00:00.123 INFO Session 550e8400-e29b-41d4-a716-446655440000 started",
		"2026-06-30 12:00:01.000 INFO Connecting to URL_001",
		"2026-06-30 12:00:02.500 INFO Resolved HOST_001 to IPV4_001",
		"2026-06-30 12:00:03.750 WARN SAS 9.4.1.2 license check",
		"2026-06-30 12:00:04.900 DEBUG IPv6 peer IPV6_001 MAC MAC_001",
	}

	var got []string
	for _, line := range lines {
		got = append(got, p.ReplaceLine(line))
	}

	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d:\n got:  %q\n want: %q", i, got[i], want[i])
		}
	}

	// Sanity check the token registry assigned exactly what the sanitized
	// output implies: HOST_001 only appears once because the URL's embedded
	// host isn't cross-registered yet (that's Milestone 5 work), so the
	// standalone occurrence in line 3 is the first encounter.
	mapping := p.Registry.Mapping()
	if mapping["HOST"]["HOST_001"] != "db-prod-01.acme.internal" {
		t.Errorf("HOST_001 = %q, want db-prod-01.acme.internal", mapping["HOST"]["HOST_001"])
	}
	if mapping["IPV4"]["IPV4_001"] != "10.20.30.40" {
		t.Errorf("IPV4_001 = %q, want 10.20.30.40", mapping["IPV4"]["IPV4_001"])
	}

	scanner := audit.NewScanner()
	var findings []audit.Finding
	for i, line := range got {
		findings = append(findings, scanner.ScanLine("synthetic.log", i+1, line)...)
	}
	if audit.HasHigh(findings) {
		t.Errorf("sanitized output has High-severity audit findings: %+v", findings)
	}
}

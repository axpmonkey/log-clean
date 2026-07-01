package audit

import (
	"strings"
	"testing"
)

func TestScannerFindsUnredactedIPv4(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 12, "connected from 192.168.1.1 directly")
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(findings), findings)
	}
	if findings[0].Pattern != "unredacted-ipv4" || findings[0].Severity != SeverityHigh {
		t.Errorf("finding = %+v", findings[0])
	}
	if findings[0].Match != "192.168.1.1" {
		t.Errorf("match = %q", findings[0].Match)
	}
}

func TestScannerFindsUnredactedFQDN(t *testing.T) {
	// Other Medium-severity rules (e.g. hostname-shaped-bare-word) may also
	// fire on overlapping text -- that's expected, findings aren't deduped
	// across rules. This test only checks the specific High-severity FQDN
	// rule fired.
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "host db-prod-01.acme.internal leaked")
	found := false
	for _, f := range findings {
		if f.Pattern == "unredacted-fqdn" && f.Match == "db-prod-01.acme.internal" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an unredacted-fqdn finding, got: %+v", findings)
	}
}

func TestScannerDoesNotFlagOwnIPV4OrIPV6TokenAsServerSuffixWord(t *testing.T) {
	// Regression test: IPV4_001 and IPV6_001 are our own token format, but
	// the category names "IPV4"/"IPV6" end in a digit, so the broad
	// server-suffix-bare-word rule (any letters-then-digits word) would
	// otherwise match "IPV4"/"IPV6" as if they were leaked hostnames -- a
	// false positive caused entirely by our own naming scheme.
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "connected from HOST_001 (IPV4_001 / IPV6_001) using MAC_001")
	for _, f := range findings {
		if f.Pattern == "server-suffix-bare-word" {
			t.Errorf("own token format flagged as server-suffix-bare-word: %+v", f)
		}
	}
}

func TestScannerFindsMACShape(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "iface 00:1A:2B:3C:4D:5E leaked")
	if len(findings) != 1 || findings[0].Pattern != "mac-shape" {
		t.Fatalf("findings = %+v", findings)
	}
}

func TestScannerCleanSanitizedLineHasNoFindings(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "connected from HOST_001 (IPV4_001) using MAC_001")
	if len(findings) != 0 {
		t.Errorf("clean sanitized line produced findings: %+v", findings)
	}
}

func TestScannerVersionStringDoesNotTriggerFQDNRule(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "SAS 9.4.1.2 build complete")
	for _, f := range findings {
		if f.Pattern == "unredacted-fqdn" {
			t.Errorf("version string falsely flagged as unredacted FQDN: %+v", f)
		}
	}
}

func TestScannerVersionStringDoesNotTriggerIPv4Rule(t *testing.T) {
	// Regression test: the audit pass must share the IPv4 detector's
	// version-context suppression, or it flags strings the sanitizer
	// intentionally left untouched as residual PII.
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "SAS 9.4.1.2 build complete")
	for _, f := range findings {
		if f.Pattern == "unredacted-ipv4" {
			t.Errorf("version string falsely flagged as unredacted IPv4: %+v", f)
		}
	}
}

func TestScannerFindsEmailShape(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "contact jdoe@acme.internal leaked")
	found := false
	for _, f := range findings {
		if f.Pattern == "email-shape" && f.Match == "jdoe@acme.internal" && f.Severity == SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an email-shape finding, got: %+v", findings)
	}
}

func TestScannerFindsLongRandomStringNearCredentialKeyword(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "token=abcdefghijklmnopqrstuvwxyz123456 leaked")
	found := false
	for _, f := range findings {
		if f.Pattern == "long-random-near-credential-keyword" && f.Severity == SeverityMedium {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a long-random-near-credential-keyword finding, got: %+v", findings)
	}
}

func TestScannerDoesNotFlagLongStringFarFromCredentialKeyword(t *testing.T) {
	s := NewScanner()
	// "abcdefghijklmnopqrstuvwxyz123456" is 20+ chars but no credential
	// keyword anywhere nearby.
	findings := s.ScanLine("app.log", 1, "checksum abcdefghijklmnopqrstuvwxyz123456 verified ok for this build artifact today")
	for _, f := range findings {
		if f.Pattern == "long-random-near-credential-keyword" {
			t.Errorf("flagged a long string with no nearby credential keyword: %+v", f)
		}
	}
}

func TestScannerFindsWindowsPathWithRealUsername(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, `C:\Users\jdoe\AppData leaked`)
	found := false
	for _, f := range findings {
		if f.Pattern == "windows-path-with-username" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a windows-path-with-username finding, got: %+v", findings)
	}
}

func TestScannerDoesNotFlagWindowsPathAlreadyTokenized(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, `C:\Users\USER_001\AppData clean`)
	for _, f := range findings {
		if f.Pattern == "windows-path-with-username" {
			t.Errorf("flagged an already-tokenized Windows user path: %+v", f)
		}
	}
}

func TestScannerFindsUnixPathWithRealUsername(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "/home/jdoe/config.txt leaked")
	found := false
	for _, f := range findings {
		if f.Pattern == "unix-path-with-username" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a unix-path-with-username finding, got: %+v", findings)
	}
}

func TestScannerDoesNotFlagUnixPathAlreadyTokenized(t *testing.T) {
	s := NewScanner()
	findings := s.ScanLine("app.log", 1, "/home/USER_001/config.txt clean")
	for _, f := range findings {
		if f.Pattern == "unix-path-with-username" {
			t.Errorf("flagged an already-tokenized Unix user path: %+v", f)
		}
	}
}

func TestHasHigh(t *testing.T) {
	if HasHigh(nil) {
		t.Error("HasHigh(nil) = true")
	}
	low := []Finding{{Severity: SeverityMedium}}
	if HasHigh(low) {
		t.Error("HasHigh with only Medium findings = true")
	}
	high := []Finding{{Severity: SeverityMedium}, {Severity: SeverityHigh}}
	if !HasHigh(high) {
		t.Error("HasHigh with a High finding present = false")
	}
}

func TestReportFormatsFindingsAndTally(t *testing.T) {
	findings := []Finding{
		{File: "a.log", Line: 3, Pattern: "unredacted-ipv4", Match: "10.0.0.1", Excerpt: "ip 10.0.0.1 seen", Severity: SeverityHigh},
		{File: "b.log", Line: 7, Pattern: "hostname-shaped", Match: "db-prod", Excerpt: "db-prod node", Severity: SeverityMedium},
	}
	out := Report(findings)
	if !strings.Contains(out, "a.log:3") || !strings.Contains(out, "10.0.0.1") {
		t.Errorf("report missing expected IPv4 finding details: %s", out)
	}
	if !strings.Contains(out, "High=1, Medium=1") {
		t.Errorf("report tally incorrect: %s", out)
	}
}

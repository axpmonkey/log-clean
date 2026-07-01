package pipeline

import (
	"testing"

	"sas-log-sanitize/internal/audit"
)

// TestZeroHighFindingsOnSanitizedCorpus is the acceptance-criterion test
// committed to in the plan's audit pass notes: validate the false-positive
// rate of the High-severity audit rules against a representative synthetic
// corpus, targeting zero High findings on correctly sanitized output, since
// --strict gates only on High severity and needs to be trustworthy.
func TestZeroHighFindingsOnSanitizedCorpus(t *testing.T) {
	lines := []string{
		"2026-06-30 13:00:00.000 INFO SAS 9.4.1.2 (TS1M6) starting up",
		"2026-06-30 13:00:00.123 INFO Session 550e8400-e29b-41d4-a716-446655440000 started",
		`2026-06-30 13:00:01.000 INFO OPTIONS METAUSER="sasadm" METAPASS="x9Y2z" connecting`,
		"2026-06-30 13:00:02.000 INFO Connecting to jdbc:postgresql://jdoe:Secret1@db-prod-01.acme.internal:5432/sasdb",
		"2026-06-30 13:00:03.000 INFO LDAP bind as CN=svc-sas,OU=Service,DC=acme,DC=internal succeeded",
		"2026-06-30 13:00:04.000 INFO Notification sent to jdoe@acme.internal",
		"2026-06-30 13:00:05.000 INFO Kerberos ticket for jdoe@EXAMPLE issued",
		`2026-06-30 13:00:06.000 WARN Logged in as ACME\jdoe from workstation`,
		"2026-06-30 13:00:07.000 INFO Reading /home/jdoe/config.txt",
		`2026-06-30 13:00:08.000 INFO Reading C:\Users\asmith\settings.ini`,
		`2026-06-30 13:00:09.000 INFO Mapped \\fileserver01\share for backup`,
		"2026-06-30 13:00:10.000 DEBUG IPv6 peer fe80::1%eth0 MAC 00:1A:2B:3C:4D:5E",
		"2026-06-30 13:00:11.000 INFO Resolved db-prod-01.acme.internal to 10.20.30.40",
		"2026-06-30 13:00:12.000 ERROR AKIAABCDEFGHIJKLMNOP rejected by IAM",
		"2026-06-30 13:00:13.000 INFO Authorization: Bearer abc123.token-value_here issued",
		"2026-06-30 13:00:14.000 INFO -----BEGIN RSA PRIVATE KEY-----",
		"2026-06-30 13:00:15.000 INFO -----END RSA PRIVATE KEY-----",
		"2026-06-30 13:00:16.000 INFO archiving to /var/log/db-prod-01-archive/out.log now",
	}

	p := New(fullDetectorChain([]string{"db-prod-01"}))
	for _, l := range lines {
		p.ScanLine(l)
	}

	var sanitized []string
	for _, l := range lines {
		sanitized = append(sanitized, p.ReplaceLine(l))
	}

	scanner := audit.NewScanner()
	var findings []audit.Finding
	for i, l := range sanitized {
		findings = append(findings, scanner.ScanLine("synthetic-bundle.log", i+1, l)...)
	}

	var high []audit.Finding
	for _, f := range findings {
		if f.Severity == audit.SeverityHigh {
			high = append(high, f)
		}
	}
	if len(high) != 0 {
		t.Errorf("expected zero High-severity findings on correctly sanitized output, got %d:\n%s",
			len(high), audit.Report(high))
	}

	// Sanity: confirm the corpus actually exercised real detectors (a test
	// that trivially passes because nothing was sanitized would be useless).
	if p.Registry.Count("HOST") == 0 || p.Registry.Count("USER") == 0 {
		t.Fatal("test corpus produced no HOST/USER tokens -- detectors may not be wired correctly")
	}
}

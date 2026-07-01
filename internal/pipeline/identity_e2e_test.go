package pipeline

import (
	"strings"
	"testing"

	"sas-log-sanitize/internal/detect"
)

// identityDetectors returns the Milestone 4+ detector chain (Decision 4
// order, allowlist omitted) for tests in this package. It's a thin wrapper
// around the real production chain builder (DefaultDetectorChain), so test
// coverage exercises the same chain Run() actually uses.
func identityDetectors() []detect.Detector {
	return DefaultDetectorChain(nil, nil)
}

func TestIdentityDetectorsEndToEnd(t *testing.T) {
	lines := []string{
		`2026-06-30 13:00:00.000 INFO OPTIONS METAUSER="sasadm" METAPASS="x9Y2z" connecting`,
		`2026-06-30 13:00:01.000 INFO LDAP bind as CN=svc-sas,OU=Service,DC=acme,DC=internal succeeded`,
		`2026-06-30 13:00:02.000 INFO Notification sent to jdoe@acme.internal`,
		`2026-06-30 13:00:03.000 INFO Kerberos ticket for jdoe@EXAMPLE issued`,
		`2026-06-30 13:00:04.000 WARN Logged in as ACME\jdoe from workstation`,
		`2026-06-30 13:00:05.000 INFO Reading /home/jdoe/config.txt`,
		`2026-06-30 13:00:06.000 INFO Reading C:\Users\asmith\settings.ini`,
		`2026-06-30 13:00:07.000 INFO Mapped \\fileserver01\share for backup`,
	}

	p := New(identityDetectors())
	for _, line := range lines {
		p.ScanLine(line)
	}

	want := []string{
		`2026-06-30 13:00:00.000 INFO OPTIONS METAUSER="USER_001" METAPASS="SECRET_REDACTED" connecting`,
		`2026-06-30 13:00:01.000 INFO LDAP bind as DN_001 succeeded`,
		`2026-06-30 13:00:02.000 INFO Notification sent to EMAIL_001`,
		`2026-06-30 13:00:03.000 INFO Kerberos ticket for KRB_001 issued`,
		`2026-06-30 13:00:04.000 WARN Logged in as DOMAIN_001\USER_002 from workstation`,
		// jdoe was already registered as USER_002 in line 5 -- same value,
		// same token, regardless of which detector found it.
		`2026-06-30 13:00:05.000 INFO Reading /home/USER_002/config.txt`,
		`2026-06-30 13:00:06.000 INFO Reading C:\Users\USER_003\settings.ini`,
		`2026-06-30 13:00:07.000 INFO Mapped UNC_001 for backup`,
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

	// The password must never appear anywhere in the sanitized output or the
	// mapping file (plan Decision 5: hard rule, secrets are never recorded).
	for i, line := range got {
		if strings.Contains(line, "x9Y2z") {
			t.Errorf("line %d leaked the redacted password: %q", i, line)
		}
	}
	for cat, m := range p.Registry.Mapping() {
		for tok, val := range m {
			if val == "x9Y2z" {
				t.Errorf("password leaked into mapping under %s/%s", cat, tok)
			}
		}
	}

	mapping := p.Registry.Mapping()
	if mapping["USER"]["USER_001"] != "sasadm" {
		t.Errorf("USER_001 = %q, want sasadm", mapping["USER"]["USER_001"])
	}
	if mapping["USER"]["USER_002"] != "jdoe" {
		t.Errorf("USER_002 = %q, want jdoe", mapping["USER"]["USER_002"])
	}
	if mapping["USER"]["USER_003"] != "asmith" {
		t.Errorf("USER_003 = %q, want asmith", mapping["USER"]["USER_003"])
	}
	if mapping["DOMAIN"]["DOMAIN_001"] != "ACME" {
		t.Errorf("DOMAIN_001 = %q, want ACME", mapping["DOMAIN"]["DOMAIN_001"])
	}
}

// TestJDBCEmbeddedCredentialsHostSelfHeals shows that even though the
// credentials detector claiming user:password@ causes the URL detector's
// whole-URL candidate to be discarded (overlap, per the partial-overlap
// rule), a *dotted* hostname in the leftover URL text still gets tokenized:
// the FQDN detector independently re-scans the whole line later (step 6) and
// finds it on its own, since nothing claimed that span. The URL just isn't
// collapsed into a single URL_NNN token in this shape -- see
// detect.CredentialsDetector's doc comment.
func TestJDBCEmbeddedCredentialsHostSelfHeals(t *testing.T) {
	p := New(identityDetectors())
	line := "jdbc:postgresql://jdoe:Secret1@db-prod-01.acme.internal:5432/sasdb"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	want := "jdbc:postgresql://USER_001:SECRET_REDACTED@HOST_001:5432/sasdb"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if strings.Contains(got, "Secret1") {
		t.Errorf("password leaked into output: %q", got)
	}
}

// TestJDBCEmbeddedCredentialsBareHostLeaks demonstrates the narrower gap
// that genuinely remains: a bare, non-dotted hostname (no TLD) inside a
// JDBC connection string with embedded credentials matches neither FQDN
// (requires a dot) nor IPv4, so it is left as plain, untokenized text. This
// is the case the audit pass's hostname-shaped-bare-word rule exists to
// catch. If a future change (e.g. Milestone 5's cross-detector consistency
// work) fixes this, this test will fail and the documented limitation in
// detect.CredentialsDetector should be updated.
func TestJDBCEmbeddedCredentialsBareHostLeaks(t *testing.T) {
	p := New(identityDetectors())
	line := "jdbc:postgresql://jdoe:Secret1@dbprod01:5432/sasdb"

	p.ScanLine(line)
	got := p.ReplaceLine(line)

	if strings.Contains(got, "Secret1") {
		t.Errorf("password leaked into output: %q", got)
	}
	if !strings.Contains(got, "dbprod01") {
		t.Errorf("expected documented limitation (bare host left untokenized) not reproduced, output = %q -- "+
			"if this now fails because the host IS tokenized, update detect.CredentialsDetector's doc comment "+
			"and this test, the limitation has been fixed", got)
	}
}

package detect

import "testing"

func TestEmailDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple email", "contact jdoe@acme.internal for help", []string{"jdoe@acme.internal"}},
		{"email with plus tag", "send to jdoe+support@acme.com please", []string{"jdoe+support@acme.com"}},
		{"email with dots in local part", "from j.doe@acme.com today", []string{"j.doe@acme.com"}},
		{"public domain email", "report to admin@example.org now", []string{"admin@example.org"}},
		{"two emails one line", "cc jdoe@acme.com and asmith@acme.com", []string{"jdoe@acme.com", "asmith@acme.com"}},

		{"no at sign", "not an email at all", nil},
		{"missing tld", "user@localhost is not matched", nil},
		{"bare domain no user", "visiting acme.com directly", nil},
		{"malformed trailing dot", "broken@acme. invalid", nil},

		{"dn mail attribute not double counted", "bind dn CN=jdoe,mail=jdoe@acme.internal,DC=acme,DC=internal", []string{"jdoe@acme.internal"}},
	}
	d := EmailDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "EMAIL")
		})
	}
}

func TestEmailDoesNotMatchInsideClaimedDNSpan(t *testing.T) {
	// Plan edge case: emails inside DN attribute values (e.g. "mail=foo@bar")
	// must not be double-counted once the DN detector has already claimed
	// the whole DN. This only happens via the pipeline's ordering (DN runs
	// before email), so this test exercises that combination directly.
	line := "bind dn CN=jdoe,mail=jdoe@acme.internal,DC=acme,DC=internal"

	dnMatches := DNDetector{}.Detect(line)
	emailMatches := EmailDetector{}.Detect(line)

	all := append(append([]Match{}, dnMatches...), emailMatches...)
	accepted := resolveOverlaps(all)

	emailCount := 0
	for _, m := range accepted {
		if m.Category == "EMAIL" {
			emailCount++
		}
	}
	if emailCount != 0 {
		t.Errorf("email matched separately even though it's inside an already-claimed DN span: %+v", accepted)
	}
}

func TestKerberosDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"bare realm no dot", "principal jdoe@EXAMPLE authenticated", []string{"jdoe@EXAMPLE"}},
		{"bare realm with numbers", "ticket for svc1@REALM1 issued", []string{"svc1@REALM1"}},
		{"realm at end of line", "auth as jdoe@EXAMPLE", []string{"jdoe@EXAMPLE"}},
		{"underscore in principal", "service_account@KRBTEST valid", []string{"service_account@KRBTEST"}},
		{"two principals", "from svc1@REALMA to svc2@REALMB", []string{"svc1@REALMA", "svc2@REALMB"}},

		{"plain text no principal", "nothing kerberos-shaped here", nil},
		{"lowercase realm not kerberos shaped", "jdoe@example not uppercase", nil},
	}
	d := KerberosDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "KRB")
		})
	}
}

func TestEmailDetectorClaimsDottedUppercaseRealmFirst(t *testing.T) {
	// Documents the known overlap noted in identity.go: a dotted uppercase
	// realm like "jdoe@EXAMPLE.COM" is syntactically also a valid email, so
	// in the real pipeline (email runs before kerberos per Decision 4) the
	// email detector claims it first, and the Kerberos detector never gets a
	// chance. The value still ends up safely tokenized, just as EMAIL_NNN
	// instead of KRB_NNN.
	line := "principal jdoe@EXAMPLE.COM authenticated"
	emailMatches := EmailDetector{}.Detect(line)
	krbMatches := KerberosDetector{}.Detect(line)

	all := append(append([]Match{}, emailMatches...), krbMatches...)
	accepted := resolveOverlaps(all)

	if len(accepted) != 1 || accepted[0].Category != "EMAIL" {
		t.Errorf("accepted = %+v, want a single EMAIL match (email runs first)", accepted)
	}
}

func TestBareUserDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"userid equals", "userid=jdoe logged in", []string{"jdoe"}},
		{"user equals", "user=svc_sas connecting", []string{"svc_sas"}},
		{"username equals quoted", `username="jdoe" found`, []string{"jdoe"}},
		{"metauser equals", "metaUser=sasadm authenticated", []string{"sasadm"}},
		{"authenticated user label", "Authenticated user: jdoe", []string{"jdoe"}},

		{"plain text", "nothing user-shaped here", nil},
		{"user word without equals", "the user is unspecified", nil},
		{"password not matched as user", "password=Passw0rd!", nil},
	}
	d := BareUserDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "USER")
		})
	}
}

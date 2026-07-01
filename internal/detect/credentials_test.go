package detect

import "testing"

func TestCredentialsDetectorRedactsKeyValueForms(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		redact []string // expected redacted substrings, in order
	}{
		{"password equals", `password=Passw0rd!`, []string{"Passw0rd!"}},
		{"password quoted", `password="Pa$$w0rd"`, []string{"Pa$$w0rd"}},
		{"pwd equals", `pwd=hunter2`, []string{"hunter2"}},
		{"secret equals", `secret=topsecretvalue`, []string{"topsecretvalue"}},
		{"pass colon form", `pass: mySecretPass`, []string{"mySecretPass"}},
		{"sas metapass option", `OPTIONS METAUSER="sasadm" METAPASS="x9Y2z"`, []string{"x9Y2z"}},
		{"ldap bind password", `bind password: ldapSecret1`, []string{"ldapSecret1"}},
		{"generic credential key", `api_credential=abc123XYZ`, []string{"abc123XYZ"}},

		{"plain text no credentials", "nothing sensitive here", nil},
		{"password word without equals", "the password is hidden elsewhere", nil},
		{"key without pass-like name", "username=jdoe", nil},
		{"empty value not matched", "password=", nil},
	}
	d := CredentialsDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := resolveOverlaps(d.Detect(c.input))
			var redacted []string
			for _, m := range matches {
				if m.Redact {
					redacted = append(redacted, m.Value)
				}
			}
			if len(redacted) != len(c.redact) {
				t.Fatalf("got redacted=%v, want %v (all matches: %+v)", redacted, c.redact, matches)
			}
			for i := range c.redact {
				if redacted[i] != c.redact[i] {
					t.Errorf("redacted[%d] = %q, want %q", i, redacted[i], c.redact[i])
				}
			}
		})
	}
}

func TestCredentialsDetectorKeyTextSurvives(t *testing.T) {
	// The key (e.g. "password=") must stay in the output; only the value is
	// claimed for redaction.
	d := CredentialsDetector{}
	line := "password=Passw0rd!"
	matches := resolveOverlaps(d.Detect(line))
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1: %+v", len(matches), matches)
	}
	if matches[0].Span.Start != len("password=") {
		t.Errorf("redacted span starts at %d, want %d (right after 'password=')", matches[0].Span.Start, len("password="))
	}
}

func TestCredentialsDetectorJDBCConnectionString(t *testing.T) {
	d := CredentialsDetector{}
	line := "jdbc:postgresql://jdoe:Secret1@db-prod-01:5432/sasdb"
	matches := resolveOverlaps(d.Detect(line))

	var user, pass *Match
	for i := range matches {
		switch {
		case matches[i].Category == "USER":
			user = &matches[i]
		case matches[i].Redact:
			pass = &matches[i]
		}
	}
	if user == nil || user.Value != "jdoe" {
		t.Errorf("user match = %+v, want value jdoe", user)
	}
	if pass == nil || pass.Value != "Secret1" {
		t.Errorf("password match = %+v, want value Secret1", pass)
	}
}

func TestCredentialsDetectorActiveMQConnectionString(t *testing.T) {
	d := CredentialsDetector{}
	line := "broker tcp://mquser:mqpass@mq-prod-01:61616"
	matches := resolveOverlaps(d.Detect(line))

	foundUser, foundPass := false, false
	for _, m := range matches {
		if m.Category == "USER" && m.Value == "mquser" {
			foundUser = true
		}
		if m.Redact && m.Value == "mqpass" {
			foundPass = true
		}
	}
	if !foundUser || !foundPass {
		t.Errorf("matches = %+v, want USER=mquser and a redacted mqpass", matches)
	}
}

func TestCredentialsDetectorSASMetaUserPseudonymized(t *testing.T) {
	d := CredentialsDetector{}
	line := `OPTIONS METAUSER="sasadm" METAPASS="x9Y2z"`
	matches := resolveOverlaps(d.Detect(line))

	var user *Match
	for i := range matches {
		if matches[i].Category == "USER" {
			user = &matches[i]
		}
	}
	if user == nil || user.Value != "sasadm" {
		t.Errorf("METAUSER match = %+v, want value sasadm pseudonymized", user)
	}
}

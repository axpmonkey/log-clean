package detect

import "testing"

func TestSecretsDetector(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		redact []string
	}{
		{"aws access key", "key id AKIAABCDEFGHIJKLMNOP found", []string{"AKIAABCDEFGHIJKLMNOP"}},
		{"aws secret key", `aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, []string{"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}},
		{"api key context", "api_key=abcdefghijklmnopqrstuvwxyz123456", []string{"abcdefghijklmnopqrstuvwxyz123456"}},
		{"jwt", "Authorization: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", []string{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"}},
		{"bearer header", "Authorization: Bearer abc123.token-value_here", []string{"abc123.token-value_here"}},

		{"short string not api key", "token=short", nil},
		{"plain text", "nothing sensitive here at all", nil},
		{"aws key wrong prefix", "AKIBABCDEFGHIJKLMNOP not a real prefix", nil},
		{"jwt missing third segment", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0", nil},

		{"gcp private key json field", `"private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n"`,
			[]string{`-----BEGIN PRIVATE KEY-----\nMIIEvQ\n-----END PRIVATE KEY-----\n`}},
		{"ssh key begin marker line", "-----BEGIN RSA PRIVATE KEY-----", []string{"-----BEGIN RSA PRIVATE KEY-----"}},
	}
	d := SecretsDetector{}
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

func TestSecretsDetectorSSHKeyEndMarker(t *testing.T) {
	d := SecretsDetector{}
	matches := d.Detect("-----END OPENSSH PRIVATE KEY-----")
	if len(matches) != 1 || !matches[0].Redact || matches[0].Value != "-----END OPENSSH PRIVATE KEY-----" {
		t.Errorf("matches = %+v", matches)
	}
}

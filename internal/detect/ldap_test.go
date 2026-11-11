package detect

import "testing"

func TestDNDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"basic dn", "bound as CN=jdoe,OU=Users,DC=acme,DC=internal",
			[]string{"CN=jdoe,OU=Users,DC=acme,DC=internal"}},
		{"dn with org and country, space in O value", "subject O=Acme Corp,L=Cary,ST=NC,C=US present",
			[]string{"O=Acme Corp,L=Cary,ST=NC,C=US"}},
		{"lowercase attribute names", "cn=jdoe,ou=users,dc=acme,dc=internal works case-insensitively",
			[]string{"cn=jdoe,ou=users,dc=acme,dc=internal"}},
		{"uid based dn", "entry UID=jdoe,OU=People,DC=acme,DC=internal found",
			[]string{"UID=jdoe,OU=People,DC=acme,DC=internal"}},
		{"two component dn", "CN=admins,DC=internal group",
			[]string{"CN=admins,DC=internal"}},

		{"single component not a dn", "CN=jdoe alone is not a dn", nil},
		{"plain text", "nothing ldap-shaped here", nil},
		{"email not mistaken for dn", "contact jdoe@acme.internal directly", nil},
		{"key value pair not dn shaped", "CN=jdoe and other=stuff", nil},

		{"dn embedded mid sentence", "the bind dn was CN=svc-sas,OU=Service Accounts,DC=acme,DC=internal for auth",
			[]string{"CN=svc-sas,OU=Service Accounts,DC=acme,DC=internal"}},
		{"value with spaces", "bind CN=John Doe,OU=Users,DC=corp,DC=com ok",
			[]string{"CN=John Doe,OU=Users,DC=corp,DC=com"}},
		{"escaped comma in value", `user (CN=Doe\, John,OU=Users,DC=corp) off`,
			[]string{`CN=Doe\, John,OU=Users,DC=corp`}},
		{"two dns one line", "from CN=a,DC=x to CN=b,DC=y",
			[]string{"CN=a,DC=x", "CN=b,DC=y"}},
	}
	d := DNDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "DN")
		})
	}
}

// The final DN component may contain spaces when it is a name-like
// attribute (CN, OU, O, L, ST) ending at a terminator or end of line.
func TestDNFinalComponentWithSpaces(t *testing.T) {
	cases := []struct{ input, want string }{
		{"member: CN=Jane Smith,OU=Sales Team", "CN=Jane Smith,OU=Sales Team"},
		{`group "CN=x,OU=Sales Team" ok`, "CN=x,OU=Sales Team"},
		{"user (CN=x,OU=Sales Team) disabled", "CN=x,OU=Sales Team"},
		{"<CN=x,O=Acme Widgets Inc>", "CN=x,O=Acme Widgets Inc"},
		{"bind CN=x,DC=corp,DC=com succeeded", "CN=x,DC=corp,DC=com"},
		{"bind CN=x,OU=Users at 10:00:01 failed", "CN=x,OU=Users"},
		{"bind CN=x,OU=Users rc=49", "CN=x,OU=Users"},
	}
	for _, c := range cases {
		m := DNDetector{}.Detect(c.input)
		if len(m) != 1 || m[0].Value != c.want {
			t.Errorf("%q: got %+v, want %q", c.input, m, c.want)
		}
	}
}

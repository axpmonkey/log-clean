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
		{"dn with org and country, partial due to space in O value", "subject O=Acme Corp,L=Cary,ST=NC,C=US present",
			[]string{"L=Cary,ST=NC,C=US"}},
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
			[]string{"CN=svc-sas,OU=Service", "DC=acme,DC=internal"}},
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

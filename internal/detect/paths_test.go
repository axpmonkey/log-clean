package detect

import "testing"

func TestUNCDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"simple unc share", `accessing \\fileserver01\share now`, []string{`\\fileserver01\share`}},
		{"unc with subpath", `reading \\fileserver01\share\data\logs.txt file`, []string{`\\fileserver01\share\data\logs.txt`}},
		{"unc with dollar admin share", `mapped \\dbserver\C$\temp drive`, []string{`\\dbserver\C$\temp`}},
		{"unc server with hyphen", `path \\db-prod-01\exports\out.csv exported`, []string{`\\db-prod-01\exports\out.csv`}},
		{"two unc paths", `from \\srv1\share1 to \\srv2\share2`, []string{`\\srv1\share1`, `\\srv2\share2`}},

		{"single backslash not unc", `C:\Users\jdoe\file.txt`, nil},
		{"plain text", "nothing unc-shaped here", nil},
		{"forward slash path not unc", "/var/log/sas/file.log", nil},
	}
	d := UNCDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "UNC")
		})
	}
}

func TestEmbeddedUNCServer(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantServer string
		wantOK     bool
	}{
		{"server and share", `\\fileserver01\share`, "fileserver01", true},
		{"server with subpath", `\\fileserver01\share\data\logs.txt`, "fileserver01", true},
		{"no leading double backslash", `fileserver01\share`, "", false},
		{"no share separator", `\\fileserver01`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			server, ok := EmbeddedUNCServer(c.input)
			if ok != c.wantOK || server != c.wantServer {
				t.Errorf("EmbeddedUNCServer(%q) = (%q, %v), want (%q, %v)", c.input, server, ok, c.wantServer, c.wantOK)
			}
		})
	}
}

func TestDomainUserDetector(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		wantDomain string
		wantUser   string
	}{
		{"simple domain user", `logged in as ACME\jdoe today`, "ACME", "jdoe"},
		{"domain with hyphen and digits", `running as CORP-NET1\svc_sas now`, "CORP-NET1", "svc_sas"},
		{"domain with underscore", `auth ACME_CORP\jdoe2 succeeded`, "ACME_CORP", "jdoe2"},
	}
	d := DomainUserDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			if len(matches) != 2 {
				t.Fatalf("got %d matches, want 2 (domain + user): %+v", len(matches), matches)
			}
			if matches[0].Category != "DOMAIN" || matches[0].Value != c.wantDomain {
				t.Errorf("domain match = %+v, want value %q", matches[0], c.wantDomain)
			}
			if matches[1].Category != "USER" || matches[1].Value != c.wantUser {
				t.Errorf("user match = %+v, want value %q", matches[1], c.wantUser)
			}
		})
	}
}

func TestDomainUserDetectorNegatives(t *testing.T) {
	cases := []string{
		"lowercase\\domain not matched",
		"no backslash here at all",
		"plain text only",
	}
	d := DomainUserDetector{}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if matches := d.Detect(input); len(matches) != 0 {
				t.Errorf("Detect(%q) = %+v, want no matches", input, matches)
			}
		})
	}
}

func TestUnixUserPathDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"home path", "/home/jdoe/config.txt loaded", []string{"jdoe"}},
		{"users path", "/Users/asmith/Documents/file.log read", []string{"asmith"}},
		{"export home path", "/export/home/svc_sas/data exported", []string{"svc_sas"}},
		{"two paths one line", "from /home/jdoe to /home/asmith", []string{"jdoe", "asmith"}},
		{"username with dot", "/home/j.doe/file written", []string{"j.doe"}},

		{"plain text no path", "nothing path-shaped here", nil},
		{"var log path not matched", "/var/log/sas/access.log", nil},
		{"root path not matched", "/root/.bashrc loaded", nil},
	}
	d := UnixUserPathDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "USER")
		})
	}
}

func TestWindowsUserPathDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"users path", `C:\Users\jdoe\AppData\file.txt loaded`, []string{"jdoe"}},
		{"documents and settings path", `C:\Documents and Settings\asmith\config.ini read`, []string{"asmith"}},
		{"username with dot", `C:\Users\j.doe\file.txt`, []string{"j.doe"}},
		{"two paths one line", `from C:\Users\jdoe to C:\Users\asmith`, []string{"jdoe", "asmith"}},

		{"plain text no path", "nothing path-shaped here", nil},
		{"program files not matched", `C:\Program Files\SAS\config.xml`, nil},
		{"forward slash not matched", "C:/Users/jdoe/file.txt", nil},
	}
	d := WindowsUserPathDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			expectSubstringMatches(t, matches, c.input, c.want, "USER")
		})
	}
}

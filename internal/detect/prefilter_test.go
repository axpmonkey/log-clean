package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// prefilterCorpus is every line of every golden fixture input plus lines
// aimed at each detector's edge cases.
func prefilterCorpus(t *testing.T) []string {
	lines := []string{
		"bound as cn=jdoe,ou=users,dc=acme", "jdoe@EXAMPLE", "jdoe@acme.internal", "ACME\\jdoe",
		`\\fileserver01\share`, `C:\Users\asmith\x`, "/export/home/jdoe/x", "/Users/jdoe/x", "USERNAME = jdoe",
		"Authenticated user: jdoe", "fe80::1%eth0", "::1", "00-1A-2B-3C-4D-5E", "00:1A:2B:3C:4D:5E",
		"550e8400-e29b-41d4-a716-446655440000", "10.1.2.3", "db.corp.example.com", "ldap://x:389",
		"metauser=sasadm", "nothing here at all",
	}
	root := filepath.Join("..", "..", "testdata", "golden")
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, string(filepath.Separator)+"input"+string(filepath.Separator)) {
			data, _ := os.ReadFile(p)
			lines = append(lines, strings.Split(string(data), "\n")...)
		}
		return nil
	})
	return lines
}

// P1.3: a prefilter may only skip a line on which its detector finds
// nothing -- it is a speed-up, never a behavior change.
func TestPrefiltersAreConservative(t *testing.T) {
	detectors := []Detector{
		UUIDDetector{}, DNDetector{}, EmailDetector{}, URLDetector{}, URLDetector{HostOnly: true},
		FQDNDetector{}, IPv4Detector{}, IPv6Detector{}, MACDetector{}, UNCDetector{}, KerberosDetector{},
		DomainUserDetector{}, BareUserDetector{}, UnixUserPathDetector{}, WindowsUserPathDetector{},
	}
	filtered := 0
	for _, d := range detectors {
		pf, ok := d.(Prefilter)
		if !ok {
			continue
		}
		filtered++
		for _, line := range prefilterCorpus(t) {
			if len(d.Detect(line)) > 0 && !pf.MightMatch(line) {
				t.Errorf("%s: prefilter rejects %q, but Detect matches it", d.Name(), line)
			}
		}
	}
	if filtered < 10 {
		t.Errorf("only %d detectors have a prefilter", filtered)
	}
}

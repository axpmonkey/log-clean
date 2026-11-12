package detect

import (
	"math/rand"
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
		// DN gate: timestamp commas, spaced and mixed-case attributes.
		"2026-11-10T12:00:00,123 INFO user=u1 rc=0", "bind CN=Jane Q. Smith, OU=Users, dc=acme",
		"uid=jdoe,ou=People,o=acme", "a=b,\tC=US", "x=1, y=2", "CN=svc,St=NC", "CN=svc,\u017ft=NC",
		// query-parameter gates.
		"GET /app?ticket=ST-1-abc&code=xyz&State=s1;token=t2", "exit code=0 state=RUNNING",
		"POST SAMLResponse=PHNhbWw+&RelayState=r1", "x_ticket=1 aticket=2 ticket = 3",
		"/cb?Access_Token=abc&id_token=def", "pwd=hunter2;sessionid=99",
		"uid=jdoe@saspw", "UID = 'asmith'", "uid=1001(sas) gid=1001", "u\u017fer=x",
		"tic\u212aet=abc", "?\u017ftate=1",
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

// The query-parameter gates in queryParamSecrets may only skip a pattern on
// lines where that pattern matches nothing.
func TestQueryParamGatesAreConservative(t *testing.T) {
	for _, line := range prefilterCorpus(t) {
		lower := asciiLower(line)
		if len(redactGroup(line, secretParamPattern, 1)) > 0 && !hasParamKey(lower, secretParamKeys) {
			t.Errorf("secret-param gate rejects %q, but the pattern matches it", line)
		}
		if len(redactGroup(line, ambiguousParamPattern, 1)) > 0 && !hasParamKey(lower, ambiguousParamKeys) {
			t.Errorf("ambiguous-param gate rejects %q, but the pattern matches it", line)
		}
	}
}

func TestBareUserPrefilter(t *testing.T) {
	for _, line := range []string{
		"user=jdoe", "USERID = 'x'", "username:\tbob", "metauser=sas1", "Authenticated user: jdoe", "uid = alice",
		"xuser=1", "the userName  =z", "uid=1001(sas)", "ſomething user=x",
	} {
		if !(BareUserDetector{}).MightMatch(line) {
			t.Errorf("prefilter rejects %q", line)
		}
	}
	for _, line := range []string{"user sasdemo logged in", "users: 3", "uidx=1", "the user, uid 7", ""} {
		if len((BareUserDetector{}).Detect(line)) > 0 {
			t.Errorf("unexpected Detect match on %q", line)
		}
	}
	if (BareUserDetector{}).MightMatch("user sasdemo logged in from host") {
		t.Error("prefilter passes a line with no user=/user: assignment")
	}
}

func TestDNPrefilterSkipsTimestampCommas(t *testing.T) {
	if (DNDetector{}).MightMatch("2026-11-10T12:00:00,123 INFO user=u1 rc=0") {
		t.Error("DN prefilter passes a line whose only comma is in the timestamp")
	}
}

// The Authorization / Cookie gates may only skip lines where their rules
// match nothing: checked on the fixture corpus and on random lines built
// from the patterns' pieces.
func TestHeaderNameGatesAreConservative(t *testing.T) {
	check := func(line string) {
		t.Helper()
		l := asciiLower(line)
		if len(authorizationValues(line)) > 0 && !headerNameGate(line, l, "authorization") {
			t.Errorf("authorization gate rejects %q", line)
		}
		if len(cookieValues(line)) > 0 && !headerNameGate(line, l, "cookie") {
			t.Errorf("cookie gate rejects %q", line)
		}
	}
	for _, line := range prefilterCorpus(t) {
		check(line)
	}
	frags := []string{"Authorization", "authorization", "Proxy-", "Cookie", "Set-", "cookie", "\"", ":", ",", " ", "\t",
		"name", "value", "{", "}", "Basic abc", "x", "=", "K", "\u212a"}
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 50000 && !t.Failed(); i++ {
		var sb strings.Builder
		for n := r.Intn(10); n >= 0; n-- {
			sb.WriteString(frags[r.Intn(len(frags))])
		}
		check(sb.String())
	}
	if headerNameGate("x com.sas.svcs.authorization.AuthorizationService y", "x com.sas.svcs.authorization.authorizationservice y", "authorization") {
		t.Error("gate passes a class name")
	}
}

package detect

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// The hand-written scanners must agree exactly with the regexes they
// replace. Random lines are built from fragments chosen to hit each
// pattern's edges (boundaries, octet limits, near-miss prefixes, case,
// non-ASCII bytes); checkScanners compares every scanner on each line.

func regexSpans(locs [][]int) [][2]int {
	var out [][2]int
	for _, l := range locs {
		out = append(out, [2]int{l[0], l[1]})
	}
	return out
}

func groupSpans(locs [][]int) [][2]int {
	var out [][2]int
	for _, l := range locs {
		if l[2] >= 0 {
			out = append(out, [2]int{l[2], l[3]})
		}
	}
	return out
}

var looseDottedQuad = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

func checkScanners(t *testing.T, line string) {
	t.Helper()
	same := func(name string, got, want [][2]int) {
		t.Helper()
		if len(got) == 0 && len(want) == 0 {
			return
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s(%q):\n got  %v\n want %v", name, line, got, want)
		}
	}
	same("findDottedQuads strict", findDottedQuads(line, true), regexSpans(ipv4Pattern.FindAllStringIndex(line, -1)))
	same("findDottedQuads loose", findDottedQuads(line, false), regexSpans(looseDottedQuad.FindAllStringIndex(line, -1)))
	same("findUUIDs", findUUIDs(line), regexSpans(uuidPattern.FindAllStringIndex(line, -1)))
	same("FindFQDNCandidates", FindFQDNCandidates(line), regexSpans(fqdnPattern.FindAllStringIndex(line, -1)))
	same("FindMACs", FindMACs(line), regexSpans(macPattern.FindAllStringIndex(line, -1)))
	same("findURLs", findURLs(line), regexSpans(urlPattern.FindAllStringIndex(line, -1)))
	same("findCASTickets", findCASTickets(line), regexSpans(casTicketPattern.FindAllStringIndex(line, -1)))

	var core [][2]int
	for _, l := range ipv6Core.FindAllStringIndex(line, -1) {
		if strings.Count(line[l[0]:l[1]], ":") >= 2 {
			core = append(core, [2]int{l[0], l[1]})
		}
	}
	same("findIPv6Candidates", findIPv6Candidates(line), core)

	if !hasNonASCII(line) {
		same("findParamValues secret", findParamValues(line, secretParamKeys, false),
			groupSpans(secretParamPattern.FindAllStringSubmatchIndex(line, -1)))
		same("findParamValues ambiguous", findParamValues(line, ambiguousParamKeys, true),
			groupSpans(ambiguousParamPattern.FindAllStringSubmatchIndex(line, -1)))
	}

	for i := 0; i <= len(line); i++ {
		if got, want := hasVersionKeywordSuffix(line[:i]), ipv4VersionKeyword.MatchString(line[:i]); got != want {
			t.Errorf("hasVersionKeywordSuffix(%q) = %v, want %v", line[:i], got, want)
		}
	}
}

var scannerFragments = []string{
	// digits, octets, dotted quads
	"0", "1", "9", "25", "255", "256", "199", "099", "300", "1234", ".", "..", "10.0.0.1", "1.2.3.4.5", "999.1.2.3",
	// uuids and near misses
	"550e8400-e29b-41d4-a716-446655440000", "550e8400-e29b-41d4-a716-44665544000", "ABCDEF01-2345-6789-abcd-ef0123456789",
	"deadbeef", "-", "a", "f", "g", "G", "_",
	// ipv6
	":", "::", "::1", "fe80::1", "12:00:00", "%eth0", "2001:db8::ff00:42:8329",
	// cas tickets
	"ST-", "PT-", "TGT-", "PGT-", "S", "T", "P", "ST-1-abc", "TGT-12-x.y_z", "PT-x-1", "XST-1-a",
	// query parameters
	"ticket", "TICKET", "Ticket", "access_token", "id_token", "refresh_token", "SAMLRequest", "samlresponse",
	"RelayState", "client_secret", "password", "pwd", "sessionid", "jsessionid", "code", "Code", "state", "token",
	"=", "?", "&", ";", "#", ",", ")", "<", ">", "\"", "'", "x_", "1",
	// version keywords
	"v", "V", "version", "Release", "sas", "SAS", "xsas", ": ", " = ", "::",
	// fqdn labels and tlds
	"com", "COM", "x", "ab", "a-b", "-a", "a-", "host01", "sas.example.com", "a.b", "a.b.c", ".com", "_x", "x1",
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	// urls
	"://", "http", "https", "ftp", "sftp", "ftps", "jdbc:", "jdbc:postgresql", "jdbc:x:", "tcp", "ssl", "nio", "amqp", "amqps",
	"mqtt", "ldap", "ldaps", "xhttp", "HTTP", "http://host:80/p?q=1", "<", ">", "/", "jdbc:sqlserver://h;db=x",
	// mac addresses
	"00:1A:2b:3C:4d:5E", "00-1a-2b-3c-4d-5e", "00:1A-2B:3C-4D:5E", "00:1A:2B:3C:4D", "0:1A", "AB", "ab:", "cd-",
	// spacing and non-ASCII
	" ", "  ", "\t", "\r", "\n", "\f", "\v", "é", "ſ", "K",
}

func randomScannerLine(r *rand.Rand) string {
	var sb strings.Builder
	for n := r.Intn(14); n >= 0; n-- {
		sb.WriteString(scannerFragments[r.Intn(len(scannerFragments))])
	}
	return sb.String()
}

func TestScannersMatchRegexps(t *testing.T) {
	fixed := []string{
		"", "10.20.30.40", "connect 10.20.30.40:8561 ok", "SAS 9.4.1.2", "version: 1.2.3.4", "x1.2.3.4", "1.2.3.4x",
		"1.2.3.4_", "256.1.1.1 and 1.1.1.256 and 01.002.3.4", "a.1.2.3.4.b", "é1.2.3.4é",
		"GET /SASLogon/app?ticket=ST-12-abc&code=xyz;state=s1&token=t2 HTTP/1.1",
		"ticket=a=ticket=b ticket= ticket=c", "x?code=1&&code=2", "SAMLResponse=PHN&RelayState=r",
		"member 550e8400-e29b-41d4-a716-446655440000, id=ABCDEF01-2345-6789-abcd-ef0123456789x",
		"host sas01.corp.example.com:8343 a.bb.c1 a.b.cc.dd x_y.com -Dcatalina.home=/x 1.2.3.com",
		"addr fe80::1%eth0 at 12:00:00,123", "TGT-1-abc-cas01.example.com", "_ST-1-a ST-1- ST--1-a",
	}
	for _, line := range fixed {
		checkScanners(t, line)
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 30000 && !t.Failed(); i++ {
		checkScanners(t, randomScannerLine(r))
	}
}

// FuzzScanners runs the same comparison on fuzzer-generated input:
// go test ./internal/detect -run '^$' -fuzz FuzzScanners
func FuzzScanners(f *testing.F) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 50; i++ {
		f.Add(randomScannerLine(r))
	}
	f.Fuzz(func(t *testing.T, line string) { checkScanners(t, line) })
}

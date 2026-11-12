package audit

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"sas-log-sanitize/internal/detect"
)

// The hand-written audit scanners must agree exactly with the regexes they
// replace (see scanners.go).

var macShapePattern = `\b([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`

func checkAuditScanners(t *testing.T, line string) {
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
	same("findHostnameShapedWords", findHostnameShapedWords(line), regexLocs(hostnameShapedPattern, line))
	same("findServerSuffixWords", findServerSuffixWords(line), regexLocs(serverSuffixPattern, line))
	// Exercise the ASCII scanners on non-ASCII lines too (the wrappers fall
	// back to the regex there): bytes >= 0x80 are never word bytes, so they
	// must still agree whenever no (?i) Unicode fold is involved.
	if !strings.ContainsAny(line, "Kſ") {
		same("hostname-shaped scanner", findWordShapes(line, matchHostnameShaped), regexLocs(hostnameShapedPattern, line))
		same("server-suffix scanner", findWordShapes(line, matchServerSuffix), regexLocs(serverSuffixPattern, line))
	}
}

var auditScannerFragments = []string{
	"a", "Z", "x1", "app", "APP", "-", "--", "_", ".", " ", "\t", ":", "1", "42", "007",
	"prod", "PROD", "Prod", "dev", "uat", "qa", "QA", "stage", "stg", "dr", "test", "Test", "pro", "de", "stag", "tes",
	"srv", "server", "host", "node", "db", "web", "mq", "SRV", "ser",
	"app-prod01", "db-uat", "xprod", "prod1", "web12-srv", "node7-mq", "IPV4_001", "AH01102", "b10", "log4j",
	"é", "ſ", "K", "\x80",
}

func randomAuditLine(r *rand.Rand) string {
	var sb strings.Builder
	for n := r.Intn(12); n >= 0; n-- {
		sb.WriteString(auditScannerFragments[r.Intn(len(auditScannerFragments))])
	}
	return sb.String()
}

func TestAuditScannersMatchRegexps(t *testing.T) {
	fixed := []string{
		"", "app-prod01 db-uat xprod prod1 web12-srv node7-MQ host3-server_x a1-db-", "foo-xprod bar-test-1 -dev qa",
		"instead of stage2 the uat-db_ and DR9", "IPV4_001 log4j java8 b10 AH01102", "aprod-", "a-prod-test9-",
	}
	for _, line := range fixed {
		checkAuditScanners(t, line)
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 50000 && !t.Failed(); i++ {
		checkAuditScanners(t, randomAuditLine(r))
	}
}

// FuzzAuditScanners: go test ./internal/audit -run '^$' -fuzz FuzzAuditScanners
func FuzzAuditScanners(f *testing.F) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 50; i++ {
		f.Add(randomAuditLine(r))
	}
	f.Fuzz(func(t *testing.T, line string) { checkAuditScanners(t, line) })
}

// The mac-shape rule now uses detect.FindMACs; make sure the rule still
// finds what its old regex did.
func TestMACShapeRuleUsesEquivalentScanner(t *testing.T) {
	line := "nic 00:1A:2b:3C:4d:5E and 00-1a-2b-3c-4d-5e x00:11:22:33:44:55"
	got := detect.FindMACs(line)
	want := regexLocs(regexp.MustCompile(macShapePattern), line)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

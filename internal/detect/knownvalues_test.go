package detect

import (
	"math/rand"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestKnownValuesDetectorMatching(t *testing.T) {
	d := NewKnownValuesDetector([]KnownValue{
		{Text: "pghost01.corp.example.com", Category: "HOST", Canonical: "pghost01.corp.example.com"},
		{Text: "jdoe", Category: "USER", Canonical: "jdoe"},
		{Text: "pghost01", Category: "HOST", Canonical: "pghost01.corp.example.com"},
		{Text: `\\files01\share`, Category: "UNC", Canonical: `\\files01\share`},
		{Text: "http://web01:8080/", Category: "URL", Canonical: "http://web01:8080/"},
	})
	cases := []struct {
		line string
		want []string // matched substrings, in order
	}{
		{"user JDOE and jdoe", []string{"JDOE", "jdoe"}},
		{"jdoes jdoe_x xjdoe", nil},                                                 // whole word only
		{"to pghost01.corp.example.com now", []string{"pghost01.corp.example.com"}}, // longest first
		{"pghost01-archive", []string{"pghost01"}},
		{`copy \\files01\share\x`, []string{`\\files01\share`}},
		{"GET http://web01:8080/x", []string{"http://web01:8080/"}},
		{"nothing", nil},
	}
	for _, c := range cases {
		var got []string
		for _, m := range d.Detect(c.line) {
			got = append(got, c.line[m.Span.Start:m.Span.End])
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %q, want %q", c.line, got, c.want)
		}
	}
	if m := d.Detect("ping PGHOST01")[0]; m.Value != "pghost01.corp.example.com" || m.Category != "HOST" {
		t.Errorf("short name maps to %+v", m)
	}
}

func TestIsSASInternalAccount(t *testing.T) {
	cases := []struct {
		line string
		val  string // the span, found in line
		want bool
	}{
		{"connected as sasadm@saspw ok", "sasadm@saspw", true},
		{"user=sastrust@saspw", "sastrust", true},
		{"user=SASEVS@SASPW;", "SASEVS", true},
		{"anon webanon@saspw", "webanon", true},
		{"user=sastrust", "sastrust", false},           // no @saspw
		{"user=sastrust@saspwx", "sastrust", false},    // other domain
		{"mail sastrust@saspw.com", "sastrust", false}, // email domain
		{"user=jsmith@saspw", "jsmith", false},         // not a SAS internal account
		{"x jsmith@saspw", "jsmith@saspw", false},
	}
	for _, c := range cases {
		start := strings.Index(c.line, c.val)
		if got := IsSASInternalAccount(c.line, start, start+len(c.val)); got != c.want {
			t.Errorf("IsSASInternalAccount(%q, %q) = %v, want %v", c.line, c.val, got, c.want)
		}
	}
}

// referenceKnownValueSpans is the original matcher -- every distinct value
// length, longest first, at every word start -- kept as the reference for
// the prefix-indexed one.
func referenceKnownValueSpans(values []KnownValue, line string) [][2]int {
	byLower := map[string]bool{}
	lenSet := map[int]bool{}
	var other []string
	for _, v := range values {
		key := asciiLower(v.Text)
		if byLower[key] || key == "" {
			continue
		}
		byLower[key] = true
		if isWordByte(key[0]) {
			lenSet[len(key)] = true
		} else {
			other = append(other, key)
		}
	}
	var lens []int
	for l := range lenSet {
		lens = append(lens, l)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(lens)))
	sort.SliceStable(other, func(i, j int) bool { return len(other[i]) > len(other[j]) })
	lower := asciiLower(line)
	var out [][2]int
	for i := 0; i < len(lower); i++ {
		if !isWordByte(lower[i]) || (i > 0 && isWordByte(lower[i-1])) {
			continue
		}
		for _, l := range lens {
			e := i + l
			if e <= len(lower) && byLower[lower[i:e]] && endsOnBoundary(lower, e) {
				out = append(out, [2]int{i, e})
				i = e - 1
				break
			}
		}
	}
	for _, key := range other {
		for from := 0; ; {
			k := strings.Index(lower[from:], key)
			if k < 0 {
				break
			}
			s, e := from+k, from+k+len(key)
			if endsOnBoundary(lower, e) {
				out = append(out, [2]int{s, e})
			}
			from = e
		}
	}
	return out
}

func TestKnownValuesIndexMatchesReference(t *testing.T) {
	frags := []string{"a", "b", "ab", "abc", "Abc", "x", "jdoe", "JDoe", "pg", "pghost01", "_", "-", ".", " ", "1", "9z",
		`\\srv`, "@", "é"}
	r := rand.New(rand.NewSource(3))
	gen := func(n int) string {
		var sb strings.Builder
		for k := r.Intn(n); k >= 0; k-- {
			sb.WriteString(frags[r.Intn(len(frags))])
		}
		return sb.String()
	}
	for round := 0; round < 3000 && !t.Failed(); round++ {
		var values []KnownValue
		for k := r.Intn(8); k >= 0; k-- {
			values = append(values, KnownValue{Text: gen(3), Category: "USER"})
		}
		d := NewKnownValuesDetector(values)
		for k := 0; k < 20; k++ {
			line := gen(12)
			got, want := d.FindAll(line), referenceKnownValueSpans(values, line)
			if len(got) == 0 && len(want) == 0 {
				continue
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("values %q line %q:\n got  %v\n want %v", values, line, got, want)
			}
		}
	}
}

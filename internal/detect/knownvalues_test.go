package detect

import (
	"reflect"
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

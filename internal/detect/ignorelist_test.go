package detect

import (
	"strings"
	"testing"
)

func TestLoadIgnoreListExactAndWildcard(t *testing.T) {
	input := strings.NewReader(`
# comment
license.example.com

*.sas.com
`)
	list, err := LoadIgnoreList(input)
	if err != nil {
		t.Fatalf("LoadIgnoreList: %v", err)
	}

	cases := []struct {
		value string
		want  bool
	}{
		{"license.example.com", true},
		{"LICENSE.EXAMPLE.COM", true}, // case-insensitive
		{"other.example.com", false},
		{"sas.com", true},     // wildcard covers the apex too
		{"db1.sas.com", true}, // wildcard covers subdomains
		{"notsas.com", false}, // must be a real subdomain, not a suffix collision
		{"sas.com.evil", false},
	}
	for _, c := range cases {
		if got := list.Matches(c.value); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestIgnoreListEmpty(t *testing.T) {
	var list IgnoreList
	if !list.Empty() {
		t.Fatal("zero-value IgnoreList should be Empty")
	}
	if list.Matches("anything.com") {
		t.Fatal("empty IgnoreList should never match")
	}
}

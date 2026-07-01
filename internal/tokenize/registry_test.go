package tokenize

import "testing"

func TestTokenForAssignsSequentially(t *testing.T) {
	r := NewRegistry()
	if got := r.TokenFor("HOST", "db-prod-01.acme.internal"); got != "HOST_001" {
		t.Errorf("first value = %q, want HOST_001", got)
	}
	if got := r.TokenFor("HOST", "app-prod-01.acme.internal"); got != "HOST_002" {
		t.Errorf("second value = %q, want HOST_002", got)
	}
}

func TestTokenForReturnsSameTokenForRepeatedValue(t *testing.T) {
	r := NewRegistry()
	first := r.TokenFor("HOST", "db-prod-01.acme.internal")
	r.TokenFor("HOST", "app-prod-01.acme.internal") // interleave a different value
	again := r.TokenFor("HOST", "db-prod-01.acme.internal")
	if first != again {
		t.Errorf("repeated value got different tokens: %q vs %q", first, again)
	}
}

func TestTokenForCategoriesAreIndependent(t *testing.T) {
	r := NewRegistry()
	host := r.TokenFor("HOST", "shared-string")
	user := r.TokenFor("USER", "shared-string")
	if host == user {
		t.Errorf("same value in different categories produced the same token: %q", host)
	}
	if host != "HOST_001" || user != "USER_001" {
		t.Errorf("got HOST=%q USER=%q, want HOST_001 and USER_001", host, user)
	}
}

func TestLookupMissingReturnsFalse(t *testing.T) {
	r := NewRegistry()
	if _, ok := r.Lookup("HOST", "never-seen"); ok {
		t.Error("Lookup found a value that was never registered")
	}
}

func TestLookupDoesNotAssign(t *testing.T) {
	r := NewRegistry()
	r.Lookup("HOST", "db-prod-01")
	if r.Count("HOST") != 0 {
		t.Errorf("Lookup assigned a token; Count = %d, want 0", r.Count("HOST"))
	}
}

func TestMappingReflectsFirstEncounterOrder(t *testing.T) {
	r := NewRegistry()
	r.TokenFor("HOST", "second-encountered")
	r.TokenFor("HOST", "first-encountered") // assigned HOST_002, not HOST_001, since it's encountered second
	m := r.Mapping()
	if m["HOST"]["HOST_001"] != "second-encountered" {
		t.Errorf("HOST_001 = %q, want second-encountered", m["HOST"]["HOST_001"])
	}
	if m["HOST"]["HOST_002"] != "first-encountered" {
		t.Errorf("HOST_002 = %q, want first-encountered", m["HOST"]["HOST_002"])
	}
}

func TestFormatTokenPaddingGrowsPast999(t *testing.T) {
	cases := []struct {
		seq  int
		want string
	}{
		{1, "HOST_001"},
		{42, "HOST_042"},
		{999, "HOST_999"},
		{1000, "HOST_1000"},
	}
	for _, c := range cases {
		if got := FormatToken("HOST", c.seq); got != c.want {
			t.Errorf("FormatToken(HOST, %d) = %q, want %q", c.seq, got, c.want)
		}
	}
}

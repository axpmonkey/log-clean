package detect

import "testing"

func TestUUIDDetector(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
	}{
		{"lowercase uuid", "id=550e8400-e29b-41d4-a716-446655440000 seen",
			[]string{"550e8400-e29b-41d4-a716-446655440000"}},
		{"uppercase uuid", "ID=550E8400-E29B-41D4-A716-446655440000",
			[]string{"550E8400-E29B-41D4-A716-446655440000"}},
		{"mixed case uuid", "memberId: 550e8400-E29B-41d4-A716-446655440000 joined",
			[]string{"550e8400-E29B-41d4-A716-446655440000"}},
		{"two uuids on one line", "a=550e8400-e29b-41d4-a716-446655440000 b=660e8400-e29b-41d4-a716-446655440001",
			[]string{"550e8400-e29b-41d4-a716-446655440000", "660e8400-e29b-41d4-a716-446655440001"}},
		{"uuid embedded in path", "/var/lib/geode/550e8400-e29b-41d4-a716-446655440000/region",
			[]string{"550e8400-e29b-41d4-a716-446655440000"}},

		{"no uuid plain text", "nothing here looks like a uuid", nil},
		{"too short hex groups", "id=550e8400-e29b-41d4-a716-4466554400", nil},
		{"wrong group lengths", "id=550e840-e29b-41d4-a716-446655440000", nil},
		{"missing hyphens", "id=550e8400e29b41d4a716446655440000", nil},
		{"non-hex characters", "id=550e8400-e29b-41g4-a716-446655440000", nil},

		{"uuid adjacent to mac-shaped text avoids double count",
			"550e8400-e29b-41d4-a716-446655440000 and 00:1A:2B:3C:4D:5E",
			[]string{"550e8400-e29b-41d4-a716-446655440000"}},
		{"uuid alone on the line", "550e8400-e29b-41d4-a716-446655440000",
			[]string{"550e8400-e29b-41d4-a716-446655440000"}},
	}
	d := UUIDDetector{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			matches := d.Detect(c.input)
			// UUID is a claim-only detector: Category is intentionally empty,
			// not "UUID" -- it never gets tokenized or redacted.
			expectSubstringMatches(t, matches, c.input, c.want, "")
		})
	}
}

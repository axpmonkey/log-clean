package detect

import "regexp"

// dnPattern matches an LDAP Distinguished Name: two or more
// attribute=value components (CN, OU, DC, UID, O, L, ST, C) joined by
// commas. The whole DN is tokenized as a single unit (DN_NNN) rather than
// decomposed into its components -- the DN as a whole is the meaningful
// identifier for correlating support-case findings.
var dnPattern = regexp.MustCompile(`(?i)(?:CN|OU|DC|UID|O|L|ST|C)=[^,)\s]+(?:,\s*(?:CN|OU|DC|UID|O|L|ST|C)=[^,)\s]+)+`)

type DNDetector struct{}

func (DNDetector) Name() string { return "ldap-dn" }

func (DNDetector) Detect(line string) []Match {
	locs := dnPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, Match{
			Span:     Span{Start: loc[0], End: loc[1]},
			Value:    line[loc[0]:loc[1]],
			Category: "DN",
		})
	}
	return matches
}

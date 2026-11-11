package detect

import (
	"regexp"
	"strings"
)

// dnPattern matches an LDAP Distinguished Name: two or more
// attribute=value components (CN, OU, DC, UID, O, L, ST, C) joined by
// commas. The whole DN is tokenized as a single unit (DN_NNN) rather than
// decomposed into its components -- the DN as a whole is the meaningful
// identifier for correlating support-case findings.
//
// Value rules (RFC 4514 shaped):
//   - A non-final value runs up to the next unescaped comma, so it may
//     contain spaces, periods, hyphens and apostrophes ("CN=Jane Q. Smith",
//     "CN=Mary-Ann O'Brien", "OU=Service Accounts"). It is bounded by the
//     requirement that the comma be followed by another ATTR=.
//   - The final value cannot be bounded that way, so it stops at whitespace
//     or a terminator (" ' ( ) [ ] < >), keeping trailing log text such as
//     "... DC=com succeeded" out of the token. DNs are written most-specific
//     first, so the final component is almost always a DC/O/C value, which
//     has no spaces.
//   - "\," and other backslash escapes are part of the value
//     ("CN=Doe\, John").
//   - The first and last attributes must be well-known DN attributes; inner
//     components may use any attribute name ("mail=", "E=", "SN=", ...), so
//     a DN carrying an email attribute stays one token.
var dnPattern = regexp.MustCompile(`(?i)\b` + dnAttr + `=` + dnInnerValue +
	`(?:,\s*` + dnAnyAttr + `=` + dnInnerValue + `)*` +
	`,\s*` + dnAttr + `=` + dnFinalValue)

const (
	dnAttr       = `(?:CN|OU|DC|UID|O|L|ST|C)`
	dnAnyAttr    = `[A-Za-z][A-Za-z0-9-]*`
	dnInnerValue = `(?:\\.|[^,\\=\r\n"()\[\]<>])+`
	dnFinalValue = `(?:\\.|[^,\\=\s"'()\[\]<>])+`
)

type DNDetector struct{}

func (DNDetector) Name() string { return "ldap-dn" }

func (DNDetector) Detect(line string) []Match {
	locs := dnPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		end := extendFinalDNValue(line, loc[0], loc[1])
		matches = append(matches, Match{
			Span:     Span{Start: loc[0], End: end},
			Value:    line[loc[0]:end],
			Category: "DN",
		})
	}
	return matches
}

// nameLikeDNAttrs are the attributes whose values are free-text names that
// may contain spaces ("OU=Sales Team", "O=Acme Widgets Inc").
var nameLikeDNAttrs = map[string]bool{"CN": true, "OU": true, "O": true, "L": true, "ST": true}

// dnTerminators end a DN that is quoted, parenthesized or bracketed.
const dnTerminators = `"'()[]<>`

// extendFinalDNValue lets the last component of the DN at line[s:e] run on
// over spaces when it is a name-like attribute: dnPattern has to stop the
// final value at whitespace (it can't otherwise tell "DC=com succeeded"
// from a value), which left the second word of "OU=Sales Team" behind. The
// run-on text must be name-like (letters, digits, spaces, . - _ &) and end
// at a terminator or end of line; anything containing ':', '=', ',' etc.
// ("rc=49", "at 10:00:01") is log text, not part of the DN.
func extendFinalDNValue(line string, s, e int) int {
	dn := line[s:e]
	c := strings.LastIndexByte(dn, ',')
	eq := strings.IndexByte(dn[c+1:], '=')
	if c < 0 || eq < 0 || !nameLikeDNAttrs[strings.ToUpper(strings.TrimSpace(dn[c+1:c+1+eq]))] {
		return e
	}
	rest := line[e:]
	k := strings.IndexAny(rest, dnTerminators)
	if k < 0 {
		k = len(rest)
	}
	run := strings.TrimRight(rest[:k], " \t")
	if run == "" || strings.TrimLeft(run, " \t") == run {
		return e // nothing to add, or not separated by whitespace
	}
	for i := 0; i < len(run); i++ {
		b := run[i]
		if !(isWordByte(b) || b == ' ' || b == '.' || b == '-' || b == '&') {
			return e
		}
	}
	return e + len(run)
}

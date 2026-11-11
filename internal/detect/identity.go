package detect

import "regexp"

// emailPattern is a simplified RFC 5322 shape: local-part@domain.tld.
var emailPattern = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`)

// kerberosPattern matches "user@REALM" where the realm is uppercase, the
// conventional Kerberos realm style and the only thing that distinguishes it
// from an email address. In practice, dotted uppercase realms like
// "user@EXAMPLE.COM" are syntactically also valid emails and will usually
// already be claimed by the (earlier-running, per Decision 4) email
// detector; this pattern mainly catches bare, non-dotted realms like
// "jdoe@EXAMPLE" that the email pattern's "requires a dot" rule rejects.
var kerberosPattern = regexp.MustCompile(`\b[a-zA-Z0-9._-]+@[A-Z][A-Z0-9.-]*\b`)

// bareUserPattern matches usernames in the key=value and label: value
// positions SAS logs commonly use. Separate alternatives, each with its own
// capture group; Detect uses whichever group fired.
//
// "uid=" only takes a value starting with a letter: Unix id(1) output
// ("uid=1001(sas) gid=...") puts a numeric user ID there, which is not a
// username. A uid= inside an LDAP DN never gets here -- the DN detector runs
// earlier and claims the whole DN.
var bareUserPattern = regexp.MustCompile(`(?i)\b(?:userid|user|username|metauser)\s*=\s*["']?([a-zA-Z0-9._-]+)|Authenticated user:\s*([a-zA-Z0-9._-]+)|\buid\s*=\s*["']?([a-zA-Z][a-zA-Z0-9._-]*)`)

type EmailDetector struct{}

func (EmailDetector) Name() string { return "email" }

func (EmailDetector) Detect(line string) []Match {
	return wholeMatches(line, emailPattern, "EMAIL")
}

type KerberosDetector struct{}

func (KerberosDetector) Name() string { return "kerberos" }

func (KerberosDetector) Detect(line string) []Match {
	return wholeMatches(line, kerberosPattern, "KRB")
}

type BareUserDetector struct{}

func (BareUserDetector) Name() string { return "bare-user" }

func (BareUserDetector) Detect(line string) []Match {
	var matches []Match
	for _, loc := range bareUserPattern.FindAllStringSubmatchIndex(line, -1) {
		s, e := -1, -1
		for g := 1; 2*g+1 < len(loc); g++ {
			if loc[2*g] >= 0 {
				s, e = loc[2*g], loc[2*g+1]
				break
			}
		}
		if s < 0 {
			continue
		}
		matches = append(matches, Match{
			Span:     Span{Start: s, End: e},
			Value:    line[s:e],
			Category: "USER",
		})
	}
	return matches
}

// wholeMatches is a small helper for detectors whose entire regex match (no
// sub-group extraction) is the value to pseudonymize.
func wholeMatches(line string, pattern *regexp.Regexp, category string) []Match {
	locs := pattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, Match{
			Span:     Span{Start: loc[0], End: loc[1]},
			Value:    line[loc[0]:loc[1]],
			Category: category,
		})
	}
	return matches
}

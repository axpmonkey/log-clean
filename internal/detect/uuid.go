package detect

import "regexp"

// uuidPattern matches the canonical 8-4-4-4-12 hyphenated hex UUID shape.
var uuidPattern = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

// UUIDDetector claims UUID-shaped spans without replacing them (plan
// Decision 6): Geode uses UUIDs as member IDs, and they're useful for
// correlating events across a support bundle, so we leave them in the
// sanitized output as-is. Its only job is to occupy the span so no other
// detector partially matches inside a UUID (e.g. a MAC-address detector
// snagging a hyphen-separated hex run inside one). Per Decision 4 it must run
// before every other detector.
//
// Exception: a UUID that is the *value of a credential* (a CSRF token, a
// session cookie, "access_token":"<uuid>") is not claimed. Because this
// detector runs first, claiming it would make the credential rules skip it
// and leak the secret. So when a line holds a UUID, the credential/secret
// rules are consulted first, and any UUID inside a span they would redact is
// left for them (detector order and span claiming are unchanged).
type UUIDDetector struct{}

func (UUIDDetector) Name() string { return "uuid" }

func (UUIDDetector) Detect(line string) []Match {
	locs := findUUIDs(line) // uuidPattern
	if locs == nil {
		return nil
	}
	secret := redactedSpans(line)
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		if overlapsAny(loc[0], loc[1], secret) {
			continue
		}
		matches = append(matches, Match{
			Span:  Span{Start: loc[0], End: loc[1]},
			Value: line[loc[0]:loc[1]],
			// Category left empty: claim-only, never tokenized or redacted.
		})
	}
	return matches
}

// redactedSpans returns the spans the credential and secret detectors would
// redact on line.
func redactedSpans(line string) []Span {
	var out []Span
	for _, d := range []Detector{CredentialsDetector{}, SecretsDetector{}} {
		for _, m := range d.Detect(line) {
			if m.Redact {
				out = append(out, m.Span)
			}
		}
	}
	return out
}

func overlapsAny(s, e int, spans []Span) bool {
	for _, sp := range spans {
		if s < sp.End && sp.Start < e {
			return true
		}
	}
	return false
}

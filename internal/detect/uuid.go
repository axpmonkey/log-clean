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
type UUIDDetector struct{}

func (UUIDDetector) Name() string { return "uuid" }

func (UUIDDetector) Detect(line string) []Match {
	locs := uuidPattern.FindAllStringIndex(line, -1)
	if locs == nil {
		return nil
	}
	matches := make([]Match, 0, len(locs))
	for _, loc := range locs {
		matches = append(matches, Match{
			Span:  Span{Start: loc[0], End: loc[1]},
			Value: line[loc[0]:loc[1]],
			// Category left empty: claim-only, never tokenized or redacted.
		})
	}
	return matches
}

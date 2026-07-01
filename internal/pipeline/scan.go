package pipeline

import "sas-log-sanitize/internal/detect"

// ScanLine runs Pass 1 over a single line: every accepted, pseudonymizable
// match is registered in the token registry. Redacted (secret) matches and
// claim-only matches (Category == "", e.g. UUIDs) are never registered --
// secrets must never appear in the mapping file (plan Decision 5).
func (p *Pipeline) ScanLine(line string) {
	for _, m := range p.walk(line) {
		if m.Redact || m.Category == "" {
			continue
		}
		p.Registry.TokenFor(m.Category, m.Value)
		registerEmbeddedHost(p, m)
	}
}

// registerEmbeddedHost implements the cross-detector consistency mechanism
// from the URL/UNC detector specs (Milestone 5): a hostname embedded in a
// URL or UNC path gets registered into the HOST category too, so the same
// hostname found standalone elsewhere in the bundle gets the identical
// token. This only feeds the registry -- it does not claim any span and does
// not change how the URL/UNC match itself gets replaced (the whole value is
// still replaced as a single URL_NNN/UNC_NNN token in ReplaceLine).
func registerEmbeddedHost(p *Pipeline, m detect.Match) {
	switch m.Category {
	case "URL":
		if host, ok := detect.EmbeddedHost(m.Value); ok {
			p.Registry.TokenFor("HOST", host)
		}
	case "UNC":
		if server, ok := detect.EmbeddedUNCServer(m.Value); ok {
			p.Registry.TokenFor("HOST", server)
		}
	}
}

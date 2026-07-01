// Package tokenize assigns sequential, deterministic-within-run tokens to
// detected values and keeps the value->token mapping per category, per plan
// Decision 1.
package tokenize

// Registry assigns sequential tokens to detected values, keyed by category.
// Token numbering follows first-encounter order: the first unique value seen
// in a category gets _001, the next gets _002, and so on. Callers are
// responsible for driving TokenFor in a deterministic order (alphabetical
// file order, then line order) so numbering is stable within a run.
type Registry struct {
	categories map[string]*categoryEntries
}

type categoryEntries struct {
	order   []string          // values in first-encounter order
	tokens  map[string]string // value -> token
	nextSeq int
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{categories: make(map[string]*categoryEntries)}
}

// TokenFor returns the token for value in category, assigning a new
// sequential token on first encounter and returning the existing token on
// every subsequent call for the same (category, value) pair.
func (r *Registry) TokenFor(category, value string) string {
	c, ok := r.categories[category]
	if !ok {
		c = &categoryEntries{tokens: make(map[string]string)}
		r.categories[category] = c
	}
	if tok, ok := c.tokens[value]; ok {
		return tok
	}
	c.nextSeq++
	tok := FormatToken(category, c.nextSeq)
	c.tokens[value] = tok
	c.order = append(c.order, value)
	return tok
}

// Lookup returns the existing token for value in category without assigning
// a new one. Pass 2 uses this -- it must only ever encounter values Pass 1
// already registered, since both passes walk detectors identically.
func (r *Registry) Lookup(category, value string) (string, bool) {
	c, ok := r.categories[category]
	if !ok {
		return "", false
	}
	tok, ok := c.tokens[value]
	return tok, ok
}

// Mapping returns the full category -> token -> original-value mapping, e.g.
// for writing the mapping file. The map is rebuilt on each call, so callers
// should not call it in a hot loop.
func (r *Registry) Mapping() map[string]map[string]string {
	out := make(map[string]map[string]string, len(r.categories))
	for cat, c := range r.categories {
		m := make(map[string]string, len(c.order))
		for _, v := range c.order {
			m[c.tokens[v]] = v
		}
		out[cat] = m
	}
	return out
}

// Count returns the number of unique values registered in category.
func (r *Registry) Count(category string) int {
	c, ok := r.categories[category]
	if !ok {
		return 0
	}
	return len(c.order)
}

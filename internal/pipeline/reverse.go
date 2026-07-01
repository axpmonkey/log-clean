package pipeline

import "regexp"

// tokenPattern matches our own CATEGORY_NNN token shape. It does not match
// "SECRET_REDACTED" -- that literal has no trailing digits, so it's left
// untouched by Reverse by construction, not by special-casing: redacted
// secrets are never recorded anywhere, so there is nothing to reverse them
// to (plan: reversibility property, "modulo redacted secrets, which are not
// reversible by design").
var tokenPattern = regexp.MustCompile(`\b[A-Z][A-Z0-9]*_[0-9]+\b`)

// Reverse substitutes every CATEGORY_NNN token found in text with its
// original value, looked up across all categories in the given mapping
// (typically tokenize.MappingFile.Categories). A token with no matching
// entry -- e.g. a typo, a token from a different run, or simply text that
// happens to look like one -- is left unchanged rather than guessed at.
func Reverse(categories map[string]map[string]string, text string) string {
	flat := flattenCategories(categories)
	return tokenPattern.ReplaceAllStringFunc(text, func(tok string) string {
		if val, ok := flat[tok]; ok {
			return val
		}
		return tok
	})
}

// flattenCategories merges every category's token->value map into one,
// since a token already encodes which category it belongs to (the prefix)
// and reverse substitution doesn't need to know the category separately.
func flattenCategories(categories map[string]map[string]string) map[string]string {
	flat := make(map[string]string)
	for _, tokens := range categories {
		for tok, val := range tokens {
			flat[tok] = val
		}
	}
	return flat
}

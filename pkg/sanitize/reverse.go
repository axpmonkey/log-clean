package sanitize

import (
	"sas-log-sanitize/internal/pipeline"
	"sas-log-sanitize/internal/tokenize"
)

// Reverse loads the mapping file at mappingPath and substitutes every
// CATEGORY_NNN token found in text with its original value. SECRET_REDACTED
// is left unchanged -- it was never recorded anywhere, so it can't be
// reversed (plan Decision 5).
func Reverse(mappingPath, text string) (string, error) {
	mf, err := tokenize.LoadMappingFile(mappingPath)
	if err != nil {
		return "", inputErrorf("loading mapping file: %w", err)
	}
	return pipeline.Reverse(mf.Categories, text), nil
}

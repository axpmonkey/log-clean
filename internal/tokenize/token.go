package tokenize

import "strconv"

// FormatToken renders a category and 1-based sequence number as e.g.
// "HOST_001". Numbers are zero-padded to at least 3 digits and grow naturally
// past 999 (HOST_999, HOST_1000, ...), per the tokenization scheme.
func FormatToken(category string, seq int) string {
	return category + "_" + formatSeq(seq)
}

func formatSeq(seq int) string {
	s := strconv.Itoa(seq)
	for len(s) < 3 {
		s = "0" + s
	}
	return s
}

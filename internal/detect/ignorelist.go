package detect

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// IgnoreList holds customer-supplied hostnames/domains that should never be
// tokenized or redacted, even though a detector would otherwise recognize
// them (e.g. a vendor domain like "sas.com" that shows up constantly in
// license-check and support-portal URLs and isn't sensitive). This is the
// inverse of AllowlistDetector, which forces tokenization of listed
// hostnames -- IgnoreList suppresses matches entirely so the original text
// passes through unchanged.
type IgnoreList struct {
	exact     map[string]bool
	wildcards []string // lowercased suffixes from "*.suffix" entries, without the leading "*."
}

// LoadIgnoreList parses an ignore-list file: one entry per non-empty,
// non-comment line ('#' starts a comment). An entry may be a bare hostname
// ("db1.internal.example.com") for an exact match, or a wildcard suffix
// ("*.sas.com") to also ignore every subdomain of sas.com (and sas.com
// itself). Matching is case-insensitive, since hostnames are.
func LoadIgnoreList(r io.Reader) (IgnoreList, error) {
	list := IgnoreList{exact: make(map[string]bool)}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.ToLower(line)
		if suffix, ok := strings.CutPrefix(line, "*."); ok {
			list.wildcards = append(list.wildcards, suffix)
			continue
		}
		list.exact[line] = true
	}
	if err := scanner.Err(); err != nil {
		return IgnoreList{}, fmt.Errorf("reading ignorelist: %w", err)
	}
	return list, nil
}

// Matches reports whether value (a hostname/FQDN a detector found) should
// be suppressed: an exact (case-insensitive) match against a bare entry, or
// value equals or is a subdomain of a "*.suffix" entry.
func (l IgnoreList) Matches(value string) bool {
	v := strings.ToLower(value)
	if l.exact[v] {
		return true
	}
	for _, suffix := range l.wildcards {
		if v == suffix || strings.HasSuffix(v, "."+suffix) {
			return true
		}
	}
	return false
}

// Empty reports whether the ignore list has no entries, so callers can skip
// the Matches check entirely on the common no-ignorelist-configured path.
func (l IgnoreList) Empty() bool {
	return len(l.exact) == 0 && len(l.wildcards) == 0
}

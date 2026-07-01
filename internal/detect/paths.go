package detect

import (
	"regexp"
	"strings"
)

// uncPattern matches a Windows UNC path: \\server\share[\rest...]. The whole
// path is tokenized as a single UNC_NNN unit.
var uncPattern = regexp.MustCompile(`\\\\[a-zA-Z0-9_-]+\\[a-zA-Z0-9_$.-]+(\\[^\s"<>|]*)?`)

type UNCDetector struct{}

func (UNCDetector) Name() string { return "unc" }

func (UNCDetector) Detect(line string) []Match {
	return wholeMatches(line, uncPattern, "UNC")
}

// EmbeddedUNCServer extracts the server portion of a UNC path, e.g.
// "\\fileserver01\share\data" -> "fileserver01". Like network.EmbeddedHost,
// it's called by pipeline.ScanLine to cross-register the server into the
// HOST category (Milestone 5).
func EmbeddedUNCServer(uncValue string) (server string, ok bool) {
	trimmed := strings.TrimPrefix(uncValue, `\\`)
	if trimmed == uncValue {
		return "", false
	}
	end := strings.IndexByte(trimmed, '\\')
	if end < 0 {
		return "", false
	}
	server = trimmed[:end]
	if server == "" {
		return "", false
	}
	return server, true
}

// domainUserPattern matches "DOMAIN\user": an uppercase NetBIOS-style domain
// name (per Windows convention, max 15 chars + leading letter) followed by a
// backslash and a username. Group 1 is the domain, group 2 is the user;
// output renders as "DOMAIN_NNN\USER_NNN".
var domainUserPattern = regexp.MustCompile(`\b([A-Z][A-Z0-9_-]{1,15})\\([a-zA-Z0-9._-]+)\b`)

type DomainUserDetector struct{}

func (DomainUserDetector) Name() string { return "domain-user" }

func (DomainUserDetector) Detect(line string) []Match {
	var matches []Match
	for _, loc := range domainUserPattern.FindAllStringSubmatchIndex(line, -1) {
		domStart, domEnd := loc[2], loc[3]
		userStart, userEnd := loc[4], loc[5]
		matches = append(matches,
			Match{Span: Span{domStart, domEnd}, Value: line[domStart:domEnd], Category: "DOMAIN"},
			Match{Span: Span{userStart, userEnd}, Value: line[userStart:userEnd], Category: "USER"},
		)
	}
	return matches
}

// unixUserPathPattern and winUserPathPattern tokenize only the username
// portion of a home-directory path, leaving the rest of the path intact
// (e.g. "/home/USER_001/whatever/the/rest.txt").
var (
	unixUserPathPattern = regexp.MustCompile(`(?:/home/|/Users/|/export/home/)([a-zA-Z0-9._-]+)`)
	winUserPathPattern  = regexp.MustCompile(`(?:C:\\Users\\|C:\\Documents and Settings\\)([a-zA-Z0-9._-]+)`)
)

type UnixUserPathDetector struct{}

func (UnixUserPathDetector) Name() string { return "unix-user-path" }

func (UnixUserPathDetector) Detect(line string) []Match {
	return pseudonymizeGroup(line, unixUserPathPattern, 1, "USER")
}

type WindowsUserPathDetector struct{}

func (WindowsUserPathDetector) Name() string { return "windows-user-path" }

func (WindowsUserPathDetector) Detect(line string) []Match {
	return pseudonymizeGroup(line, winUserPathPattern, 1, "USER")
}

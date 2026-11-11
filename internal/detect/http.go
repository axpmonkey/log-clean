package detect

import (
	"regexp"
	"strings"
)

// HTTP credential rules: Authorization headers and session cookies. They live in
// CredentialsDetector (and run first there) so no narrower credential rule
// can claim a fragment of the header value first -- a partial claim would
// make the pipeline drop the whole header match and leak the rest.

var (
	// authHeaderPattern matches header-style "Authorization: <value>" and
	// "Proxy-Authorization: <value>", plus the JSON-object form
	// `"Authorization": "<value>"`. A quoted value (group 1) ends at its
	// closing quote; an unquoted header value (group 2) runs to end of line,
	// since schemes like Digest carry quoted parameters inside the value.
	authHeaderPattern = regexp.MustCompile(`(?i)\b(?:proxy-)?authorization"?\s*:\s*(?:"([^"\r\n]*)|([^"\s][^\r\n]*))`)

	// authJSONNameValuePattern matches the HAR / name-value JSON form
	// `{"name":"Authorization","value":"<value>"}`.
	authJSONNameValuePattern = regexp.MustCompile(`(?i)"name"\s*:\s*"(?:proxy-)?authorization"\s*,\s*"value"\s*:\s*"([^"]*)"`)

	// authSchemePrefix matches a leading auth scheme token ("Basic ",
	// "Negotiate ", "Digest ", ...). The scheme is kept in the output -- it
	// is useful for troubleshooting and not secret -- and everything after
	// it is redacted.
	authSchemePrefix = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*\s+`)

	// cookieHeaderPattern / cookieJSONNameValuePattern find Cookie and
	// Set-Cookie header values in the same three shapes as Authorization.
	// Group 1 is "set-" when present (Set-Cookie), groups 2/3 the quoted /
	// unquoted value.
	cookieHeaderPattern        = regexp.MustCompile(`(?i)\b(set-)?cookie"?\s*:\s*(?:"([^"\r\n]*)|([^"\s][^\r\n]*))`)
	cookieJSONNameValuePattern = regexp.MustCompile(`(?i)"name"\s*:\s*"(set-)?cookie"\s*,\s*"value"\s*:\s*"([^"]*)"`)

	// sensitiveXHeaderPattern matches custom credential headers in text
	// form: "X-CSRF-Token: v", "X-XSRF-TOKEN: v", "X-Auth-Token: v",
	// "x-api-key: \"v\"", "X-Session-Id: v".
	sensitiveXHeaderPattern = regexp.MustCompile(`(?i)\bx-[a-z0-9-]*(?:csrf|xsrf|token|api-?key|secret|session|auth)[a-z0-9-]*"?\s*:\s*"?([^"\s,;]+)`)

	// jsessionIDPattern catches a Java session ID anywhere it appears,
	// including the ";jsessionid=" URL path parameter.
	jsessionIDPattern = regexp.MustCompile(`(?i)\bjsessionid=([^;&?\s"',#]+)`)
)

// authorizationValues redacts the credentials part of every Authorization /
// Proxy-Authorization value on the line, for every scheme (Basic, Bearer,
// Negotiate, NTLM, Digest, ...). A value with no scheme token is redacted
// whole.
func authorizationValues(line string) []Match {
	var out []Match
	for _, p := range []*regexp.Regexp{authJSONNameValuePattern, authHeaderPattern} {
		for _, loc := range p.FindAllStringSubmatchIndex(line, -1) {
			s, e := loc[2], loc[3]
			if s < 0 && len(loc) > 4 {
				s, e = loc[4], loc[5] // unquoted header value
			}
			if s < 0 {
				continue
			}
			for e > s && (line[e-1] == ' ' || line[e-1] == '\t') {
				e--
			}
			if sch := authSchemePrefix.FindStringIndex(line[s:e]); sch != nil {
				s += sch[1]
			}
			if s >= e {
				continue
			}
			out = append(out, Match{Span: Span{Start: s, End: e}, Value: line[s:e], Redact: true})
		}
	}
	return out
}

// cookieValues redacts cookie values in Cookie / Set-Cookie headers while
// keeping cookie names: every name=value pair of a Cookie header, and only
// the first pair of a Set-Cookie header (the rest are attributes such as
// Path=/ and HttpOnly, which aren't secret and help troubleshooting).
func cookieValues(line string) []Match {
	var out []Match
	for _, p := range []*regexp.Regexp{cookieJSONNameValuePattern, cookieHeaderPattern} {
		for _, loc := range p.FindAllStringSubmatchIndex(line, -1) {
			isSetCookie := loc[2] >= 0
			s, e := -1, -1
			for g := 2; 2*g+1 < len(loc); g++ {
				if loc[2*g] >= 0 {
					s, e = loc[2*g], loc[2*g+1]
					break
				}
			}
			if s < 0 {
				continue
			}
			out = append(out, cookiePairValues(line, s, e, isSetCookie)...)
		}
	}
	return out
}

// cookiePairValues splits line[s:e] on ';' and returns a redaction for the
// value half of each name=value pair (only the first pair when firstOnly).
func cookiePairValues(line string, s, e int, firstOnly bool) []Match {
	var out []Match
	for pos := s; pos < e; {
		end := strings.IndexByte(line[pos:e], ';')
		if end < 0 {
			end = e
		} else {
			end += pos
		}
		if eq := strings.IndexByte(line[pos:end], '='); eq >= 0 {
			vs, ve := pos+eq+1, end
			for ve > vs && (line[ve-1] == ' ' || line[ve-1] == '\t') {
				ve--
			}
			if ve > vs {
				out = append(out, Match{Span: Span{Start: vs, End: ve}, Value: line[vs:ve], Redact: true})
			}
		}
		if firstOnly {
			break
		}
		pos = end + 1
	}
	return out
}

// ---- Query-string / form-body credentials ---------------------------------

const (
	// secretParamNames are parameter names whose value is a credential
	// wherever they appear as name=value: logon tickets, OAuth tokens, SAML
	// messages, passwords and session IDs.
	secretParamNames = `ticket|access_token|id_token|refresh_token|SAMLRequest|SAMLResponse|RelayState|client_secret|password|pwd|sessionid|jsessionid`
	// ambiguousParamNames are only credentials as URL/form parameters
	// (after '?', '&' or ';'); in log prose "state=RUNNING" or "exit code=0"
	// are ordinary values that must survive.
	ambiguousParamNames = `code|state|token`
	// paramValue stops at the next parameter separator, whitespace, quote,
	// fragment or closing punctuation.
	paramValue = `([^&\s"'#;,<>)]+)`
)

var (
	secretParamPattern    = regexp.MustCompile(`(?i)\b(?:` + secretParamNames + `)=` + paramValue)
	ambiguousParamPattern = regexp.MustCompile(`(?i)[?&;](?:` + ambiguousParamNames + `)=` + paramValue)

	// secretParamJSONPattern covers HAR queryString / params arrays:
	// {"name":"code","value":"..."}. The explicit name/value pairing makes
	// even the ambiguous names unambiguous here.
	secretParamJSONPattern = regexp.MustCompile(`(?i)"name"\s*:\s*"(?:` + secretParamNames + `|` + ambiguousParamNames + `)"\s*,\s*"value"\s*:\s*"([^"]*)"`)

	// secretJSONKeyPattern covers JSON objects keyed by a credential name:
	// {"access_token":"...","password":"..."} in JSON logs and HAR bodies.
	// The ambiguous names are excluded except "token"; "state":"RUNNING" in
	// a JSON log is ordinary data.
	secretJSONKeyPattern = regexp.MustCompile(`(?i)"(?:` + secretParamNames + `|token)"\s*:\s*"([^"]*)"`)

	// casTicketPattern matches CAS-style service / proxy / ticket-granting
	// tickets on their own ("ST-12345-abc...", "TGT-1-xyz-cas01").
	casTicketPattern = regexp.MustCompile(`\b(?:ST|PT|TGT|PGT)-\d+-[A-Za-z0-9._-]+`)
)

// queryParamSecrets redacts credential-bearing parameter values in absolute
// and relative URLs, form bodies and HAR queryString arrays, plus standalone
// CAS tickets. It runs inside CredentialsDetector, which is ahead of the URL
// detector in the chain: claiming the value span makes the URL detector skip
// the URL (partial-overlap rule), so the ticket can no longer be tokenized as
// part of a whole-URL token and written to the mapping file. The host inside
// the URL is still tokenized by the FQDN/IPv4 detectors.
//
// lower is line ASCII-lowercased, used to skip patterns whose required
// characters are absent.
func queryParamSecrets(line, lower string) []Match {
	var out []Match
	if strings.IndexByte(lower, '"') >= 0 && strings.IndexByte(lower, ':') >= 0 {
		out = append(out, redactGroup(line, secretParamJSONPattern, 1)...)
		out = append(out, redactGroup(line, secretJSONKeyPattern, 1)...)
	}
	switch {
	case strings.IndexByte(lower, '=') < 0:
	case !hasNonASCII(line):
		out = append(out, redactSpans(line, findParamValues(line, secretParamKeys, false))...)
		out = append(out, redactSpans(line, findParamValues(line, ambiguousParamKeys, true))...)
	default: // (?i) folding of non-ASCII letters: see scanners.go
		if hasParamKey(lower, secretParamKeys) {
			out = append(out, redactGroup(line, secretParamPattern, 1)...)
		}
		if hasParamKey(lower, ambiguousParamKeys) {
			out = append(out, redactGroup(line, ambiguousParamPattern, 1)...)
		}
	}
	if strings.Contains(line, "T-") {
		out = append(out, redactSpans(line, findCASTickets(line))...)
	}
	return out
}

// secretParamKeys / ambiguousParamKeys gate secretParamPattern and
// ambiguousParamPattern (see hasParamKey): most SAS log lines contain an '='
// but no credential parameter name, and the case-insensitive alternations
// are expensive to run on every one of them.
var (
	secretParamKeys    = toSet(strings.Split(strings.ToLower(secretParamNames), "|")...)
	ambiguousParamKeys = toSet(strings.Split(ambiguousParamNames, "|")...)
)

// secretParamNameSet is every credential parameter name, lowercased.
var secretParamNameSet = toSet(strings.Split(strings.ToLower(secretParamNames+"|"+ambiguousParamNames), "|")...)

// IsSecretParamName reports whether a query-string / form parameter with
// this name carries a credential (case-insensitive). Used by the HAR handler
// for queryString and postData.params entries, where the explicit name/value
// pairing makes even the ambiguous names (code, state, token) unambiguous.
func IsSecretParamName(name string) bool {
	return secretParamNameSet[strings.ToLower(name)]
}

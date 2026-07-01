package detect

import (
	"regexp"
	"strings"
)

// Credential patterns redact only the value, never the key -- so
// "password=Passw0rd!" becomes "password=SECRET_REDACTED", keeping the log
// line structurally readable. Each pattern below captures the value in its
// own group; redactGroup turns that capture into a single Redact match.

var (
	kvPasswordPattern  = regexp.MustCompile(`(?i)\bpassword\s*=\s*["']?([^"'\s,;)]+)`)
	kvPwdPattern       = regexp.MustCompile(`(?i)\bpwd\s*=\s*["']?([^"'\s,;)]+)`)
	kvSecretPattern    = regexp.MustCompile(`(?i)\bsecret\s*=\s*["']?([^"'\s,;)]+)`)
	kvPassColonPattern = regexp.MustCompile(`(?i)\bpass(?:word)?:\s*([^\s,;)]+)`)

	// genericCredentialKVPattern is a catch-all for key=value pairs whose
	// key merely contains a credential-shaped word. It necessarily overlaps
	// the more specific patterns above on plain "password=" cases; that's
	// fine because the pipeline claims spans in the order this detector
	// returns them (see Detect, below), so the specific patterns always win.
	genericCredentialKVPattern = regexp.MustCompile(`(?i)\b\w*(?:pass|secret|apikey|api_key|token|credential)\w*\s*=\s*["']?([^"'\s,;)]+)`)

	// jdbcCredsPattern matches "user:password@host" inside a jdbc:<driver>://
	// connection string. Group 1 is the username (pseudonymized), group 2 is
	// the password (redacted), group 3 is the host up to the next ':' (port),
	// '/' (path), or whitespace.
	jdbcCredsPattern = regexp.MustCompile(`jdbc:[^/]+://([^:@/\s]+):([^@\s]+)@([^:/\s]+)`)

	// activeMQCredsPattern matches the same user:password@host shape for the
	// ActiveMQ-style transport schemes used in SAS middleware logs.
	activeMQCredsPattern = regexp.MustCompile(`(?:tcp|ssl|nio|amqp)://([^:@/\s]+):([^@\s]+)@([^:/\s]+)`)

	// sasMetaPassPattern / sasMetaUserPattern match SAS metadata server
	// connection options, e.g. `OPTIONS METAUSER="sasadm" METAPASS="x"`.
	sasMetaPassPattern = regexp.MustCompile(`(?i)OPTIONS\s+[^;]*METAPASS\s*=\s*["']?([^"'\s;]+)`)
	sasMetaUserPattern = regexp.MustCompile(`(?i)OPTIONS\s+[^;]*METAUSER\s*=\s*["']?([^"'\s;]+)`)

	// ldapBindPattern matches an LDAP bind password/pw/pwd assignment.
	ldapBindPattern = regexp.MustCompile(`(?i)\bbind\s*(?:password|pw|pwd)\s*[:=]\s*["']?([^"'\s]+)`)
)

// CredentialsDetector finds passwords and other secrets embedded in
// connection strings, SAS OPTIONS statements, and generic key=value pairs,
// and fully redacts the value only (plan Decision 5: credentials are never
// pseudonymized or recorded in the mapping file).
//
// When a credential sits inside a JDBC/ActiveMQ-style URL (e.g.
// "jdbc:postgresql://jdoe:secret@db-prod-01.acme.internal:5432/sasdb"), this
// detector claims the user:password@ span before the URL detector (which
// runs later, per Decision 4) gets a chance to see the line, so the URL is
// never tokenized as a single URL_NNN unit in this shape (any span overlap
// causes the URL detector's candidate to be skipped -- the partial-overlap
// rule in Decision 3). The host that follows "@" is handled directly here:
//   - A bare, non-dotted host (e.g. "dbprod01") is tokenized as HOST_NNN by
//     jdbcLikeCreds, since neither the FQDN detector (needs a dot) nor IPv4
//     would otherwise catch it -- this is the leak that used to remain.
//   - A dotted host or numeric IP is deliberately left for the dedicated
//     FQDN/IPv4 detectors, which re-scan the leftover URL text independently
//     and categorize it correctly (HOST vs IPV4) rather than lumping an IP
//     into HOST.
type CredentialsDetector struct{}

func (CredentialsDetector) Name() string { return "credentials" }

func (CredentialsDetector) Detect(line string) []Match {
	var matches []Match

	// Order matters here: more specific patterns first, so they claim their
	// span before the generic catch-all would otherwise also match it.
	matches = append(matches, redactGroup(line, kvPasswordPattern, 1)...)
	matches = append(matches, redactGroup(line, kvPwdPattern, 1)...)
	matches = append(matches, redactGroup(line, kvSecretPattern, 1)...)
	matches = append(matches, redactGroup(line, kvPassColonPattern, 1)...)
	matches = append(matches, redactGroup(line, sasMetaPassPattern, 1)...)
	matches = append(matches, redactGroup(line, ldapBindPattern, 1)...)
	matches = append(matches, redactGroup(line, genericCredentialKVPattern, 1)...)

	// SAS METAUSER is pseudonymized (it's a username, not a secret), not redacted.
	matches = append(matches, pseudonymizeGroup(line, sasMetaUserPattern, 1, "USER")...)

	// JDBC / ActiveMQ embedded credentials: username pseudonymized, password redacted.
	matches = append(matches, jdbcLikeCreds(line, jdbcCredsPattern)...)
	matches = append(matches, jdbcLikeCreds(line, activeMQCredsPattern)...)

	return matches
}

// redactGroup returns one fully-redacted Match per regex match, using
// capture group groupIdx as the span to redact (so the key, e.g.
// "password=", stays in the output).
func redactGroup(line string, pattern *regexp.Regexp, groupIdx int) []Match {
	var matches []Match
	for _, loc := range pattern.FindAllStringSubmatchIndex(line, -1) {
		s, e := loc[2*groupIdx], loc[2*groupIdx+1]
		if s < 0 {
			continue // group didn't participate in this match
		}
		matches = append(matches, Match{
			Span:   Span{Start: s, End: e},
			Value:  line[s:e],
			Redact: true,
		})
	}
	return matches
}

// pseudonymizeGroup is redactGroup's counterpart for values that should be
// tokenized rather than redacted (e.g. usernames found alongside secrets).
func pseudonymizeGroup(line string, pattern *regexp.Regexp, groupIdx int, category string) []Match {
	var matches []Match
	for _, loc := range pattern.FindAllStringSubmatchIndex(line, -1) {
		s, e := loc[2*groupIdx], loc[2*groupIdx+1]
		if s < 0 {
			continue
		}
		matches = append(matches, Match{
			Span:     Span{Start: s, End: e},
			Value:    line[s:e],
			Category: category,
		})
	}
	return matches
}

// jdbcLikeCreds extracts the username (group 1, pseudonymized), password
// (group 2, redacted), and host (group 3) from a "user:password@host"
// pattern shared by JDBC and ActiveMQ-style connection strings.
//
// The host is only emitted as a HOST match when it is bare (no dot): that's
// the case the dedicated FQDN/IPv4 detectors can't catch, so it would
// otherwise leak. A dotted host or IP is left unclaimed here so those
// detectors categorize it correctly (HOST vs IPV4) when they re-scan.
func jdbcLikeCreds(line string, pattern *regexp.Regexp) []Match {
	var matches []Match
	for _, loc := range pattern.FindAllStringSubmatchIndex(line, -1) {
		userStart, userEnd := loc[2], loc[3]
		passStart, passEnd := loc[4], loc[5]
		hostStart, hostEnd := loc[6], loc[7]
		if userStart >= 0 {
			matches = append(matches, Match{
				Span:     Span{Start: userStart, End: userEnd},
				Value:    line[userStart:userEnd],
				Category: "USER",
			})
		}
		if passStart >= 0 {
			matches = append(matches, Match{
				Span:   Span{Start: passStart, End: passEnd},
				Value:  line[passStart:passEnd],
				Redact: true,
			})
		}
		if hostStart >= 0 {
			host := line[hostStart:hostEnd]
			if !strings.Contains(host, ".") {
				matches = append(matches, Match{
					Span:     Span{Start: hostStart, End: hostEnd},
					Value:    host,
					Category: "HOST",
				})
			}
		}
	}
	return matches
}

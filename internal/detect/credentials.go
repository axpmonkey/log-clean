package detect

import "regexp"

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

	// jdbcCredsPattern matches "user:password@" inside a jdbc:<driver>://
	// connection string. Group 1 is the username (pseudonymized), group 2 is
	// the password (redacted).
	jdbcCredsPattern = regexp.MustCompile(`jdbc:[^/]+://([^:@/\s]+):([^@\s]+)@`)

	// activeMQCredsPattern matches the same user:password@ shape for the
	// ActiveMQ-style transport schemes used in SAS middleware logs.
	activeMQCredsPattern = regexp.MustCompile(`(?:tcp|ssl|nio|amqp)://([^:@/\s]+):([^@\s]+)@`)

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
// Known limitation: when a credential sits inside a JDBC/ActiveMQ-style URL
// (e.g. "jdbc:postgresql://jdoe:secret@db-prod-01.acme.internal:5432/sasdb"),
// this detector claims the user:password@ span before the URL detector
// (which runs later, per Decision 4) gets a chance to see the line. Since
// any span overlap causes the URL detector's candidate to be skipped
// entirely (the partial-overlap rule in Decision 3), the URL is never
// tokenized as a single URL_NNN unit in this shape. In practice this mostly
// self-heals: the FQDN/IPv4/IPv6/MAC detectors that run after the URL
// detector (steps 6-9) re-scan the whole line independently, so a dotted
// hostname or numeric IP in the leftover URL text still gets tokenized on
// its own (just as HOST_NNN/IPV4_NNN rather than being absorbed into a
// URL_NNN). The gap that remains is a *bare*, non-dotted hostname with no
// TLD (e.g. "dbprod01" with no domain suffix) -- it matches neither FQDN
// (requires a dot) nor IPv4, so it is left as plain, untokenized text. The
// audit pass's hostname-shaped-bare-word rule is the backstop for that
// narrower case. See plan Decision 3's partial-overlap rule for why this
// tradeoff was made.
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

// jdbcLikeCreds extracts the username (group 1, pseudonymized) and password
// (group 2, redacted) from a "user:password@" pattern shared by JDBC and
// ActiveMQ-style connection strings.
func jdbcLikeCreds(line string, pattern *regexp.Regexp) []Match {
	var matches []Match
	for _, loc := range pattern.FindAllStringSubmatchIndex(line, -1) {
		userStart, userEnd := loc[2], loc[3]
		passStart, passEnd := loc[4], loc[5]
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
	}
	return matches
}

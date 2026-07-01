package detect

import "regexp"

var (
	awsAccessKeyPattern = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)

	// awsSecretKeyPattern is contextual: AWS secret keys have no fixed
	// prefix, so we only treat a 20+ char base64-ish string as a secret when
	// it's clearly assigned to an aws_secret_access_key-shaped key.
	awsSecretKeyPattern = regexp.MustCompile(`(?i)\baws_secret_access_key\s*=\s*["']?([A-Za-z0-9/+=]{20,})`)

	// apiKeyContextPattern requires both a credential-shaped key name *and*
	// a 32+ char opaque value -- matching plan Decision 6's intent of
	// avoiding false positives on arbitrary long strings that aren't
	// actually secrets.
	apiKeyContextPattern = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access_token|token)\s*[:=]\s*["']?([a-zA-Z0-9_-]{32,})`)

	jwtPattern    = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	bearerPattern = regexp.MustCompile(`(?i)\bBearer\s+([A-Za-z0-9._~+/=-]+)`)

	// gcpPrivateKeyPattern matches a GCP service-account JSON's
	// "private_key" field, which is typically emitted on a single log line
	// as a JSON string with literal "\n" escapes (not real newlines), so
	// it's fully redactable per-line like any other key=value secret.
	gcpPrivateKeyPattern = regexp.MustCompile(`"private_key"\s*:\s*"((?:[^"\\]|\\.)*)"`)

	sshKeyBeginPattern = regexp.MustCompile(`-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)
	sshKeyEndPattern   = regexp.MustCompile(`-----END (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----`)
)

// IsSSHPrivateKeyBegin reports whether line contains an SSH/PEM private-key
// BEGIN marker. IsSSHPrivateKeyEnd is its counterpart for the END marker.
// These exist because an SSH/PEM private key spans many lines (the BEGIN
// marker, dozens of base64 body lines, then the END marker), and no
// single-line detector can see the body -- each Detect call gets one line in
// isolation. The pipeline's file-level block redactor (pipeline.Run) uses
// these predicates to redact every line from BEGIN through END inclusive,
// which is where the multi-line key body actually gets scrubbed. This
// detector still redacts the BEGIN/END marker lines on their own (below) as
// a backstop for callers that drive ScanLine/ReplaceLine directly without
// the file-level loop, so the two share one marker definition.
func IsSSHPrivateKeyBegin(line string) bool { return sshKeyBeginPattern.MatchString(line) }

// IsSSHPrivateKeyEnd reports whether line contains an SSH/PEM private-key END
// marker. See IsSSHPrivateKeyBegin.
func IsSSHPrivateKeyEnd(line string) bool { return sshKeyEndPattern.MatchString(line) }

// SecretsDetector finds API keys, tokens, JWTs, cloud provider credentials,
// and SSH key markers, fully redacting them per plan Decision 5.
//
// SSH/PEM private keys: this detector redacts the BEGIN and END marker lines,
// but the multi-line base64 key body between them is redacted by the
// pipeline's file-level block redactor (pipeline.Run), which has the
// cross-line state a per-line detector lacks. See IsSSHPrivateKeyBegin.
type SecretsDetector struct{}

func (SecretsDetector) Name() string { return "secrets" }

func (SecretsDetector) Detect(line string) []Match {
	var matches []Match

	matches = append(matches, redactWhole(line, awsAccessKeyPattern)...)
	matches = append(matches, redactGroup(line, awsSecretKeyPattern, 1)...)
	matches = append(matches, redactGroup(line, apiKeyContextPattern, 1)...)
	matches = append(matches, redactWhole(line, jwtPattern)...)
	matches = append(matches, redactGroup(line, bearerPattern, 1)...)
	matches = append(matches, redactGroup(line, gcpPrivateKeyPattern, 1)...)
	matches = append(matches, redactWhole(line, sshKeyBeginPattern)...)
	matches = append(matches, redactWhole(line, sshKeyEndPattern)...)

	return matches
}

// redactWhole returns one fully-redacted Match per regex match, using the
// entire match (not a capture group) as the span to redact.
func redactWhole(line string, pattern *regexp.Regexp) []Match {
	var matches []Match
	for _, loc := range pattern.FindAllStringIndex(line, -1) {
		matches = append(matches, Match{
			Span:   Span{Start: loc[0], End: loc[1]},
			Value:  line[loc[0]:loc[1]],
			Redact: true,
		})
	}
	return matches
}

package pipeline

import "sas-log-sanitize/internal/detect"

// DefaultDetectorChain builds the full detector chain in plan Decision 4
// order: UUID claim-only detector first, credentials/secrets (full
// redaction), then identity/network/path detectors, with the customer
// hostname allowlist substring pass running last. This is the chain real
// runs (via Run) should use; extraTLDs and allowlist may be empty/nil.
func DefaultDetectorChain(extraTLDs []string, allowlist []string) []detect.Detector {
	chain := []detect.Detector{
		detect.UUIDDetector{},
		detect.CredentialsDetector{},
		detect.SecretsDetector{},
		detect.DNDetector{},
		detect.EmailDetector{},
		detect.URLDetector{},
		detect.NewFQDNDetectorWithExtraTLDs(extraTLDs),
		detect.IPv4Detector{},
		detect.IPv6Detector{},
		detect.MACDetector{},
		detect.UNCDetector{},
		detect.KerberosDetector{},
		detect.DomainUserDetector{},
		detect.BareUserDetector{},
		detect.UnixUserPathDetector{},
		detect.WindowsUserPathDetector{},
	}
	if len(allowlist) > 0 {
		chain = append(chain, detect.NewAllowlistDetector(allowlist))
	}
	return chain
}

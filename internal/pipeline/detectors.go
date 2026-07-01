package pipeline

import (
	"net/netip"

	"sas-log-sanitize/internal/detect"
)

// ChainOptions carries the per-run knobs that shape the detector chain,
// grouped into a struct so DefaultDetectorChain's signature stays stable as
// more config-driven options (extra TLDs, allowlist, IPv4 skip ranges,
// case-insensitive allowlist matching) are wired through. Every field is
// optional -- the zero value builds the default chain.
type ChainOptions struct {
	// ExtraTLDs are appended to the FQDN detector's TLD allowlist.
	ExtraTLDs []string
	// Allowlist holds customer hostnames for the substring pass (runs last).
	Allowlist []string
	// AllowlistCaseInsensitive matches allowlist entries regardless of case
	// (detectors.allowlist.case_insensitive).
	AllowlistCaseInsensitive bool
	// IPv4SkipRanges are CIDR blocks whose addresses are left untokenized
	// (detectors.ipv4.skip_ranges).
	IPv4SkipRanges []netip.Prefix
}

// DefaultDetectorChain builds the full detector chain in plan Decision 4
// order: UUID claim-only detector first, credentials/secrets (full
// redaction), then identity/network/path detectors, with the customer
// hostname allowlist substring pass running last. This is the chain real
// runs (via Run) should use.
func DefaultDetectorChain(opts ChainOptions) []detect.Detector {
	chain := []detect.Detector{
		detect.UUIDDetector{},
		detect.CredentialsDetector{},
		detect.SecretsDetector{},
		detect.DNDetector{},
		detect.EmailDetector{},
		detect.URLDetector{},
		detect.NewFQDNDetectorWithExtraTLDs(opts.ExtraTLDs),
		detect.NewIPv4Detector(opts.IPv4SkipRanges),
		detect.IPv6Detector{},
		detect.MACDetector{},
		detect.UNCDetector{},
		detect.KerberosDetector{},
		detect.DomainUserDetector{},
		detect.BareUserDetector{},
		detect.UnixUserPathDetector{},
		detect.WindowsUserPathDetector{},
	}
	if len(opts.Allowlist) > 0 {
		chain = append(chain, detect.NewAllowlistDetector(opts.Allowlist, opts.AllowlistCaseInsensitive))
	}
	return chain
}

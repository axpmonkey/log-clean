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
	// IPClass makes the IPv4 detector emit IPV4_PRIV / IPV4_PUB tokens.
	IPClass bool
	// URLMode is URLModeHost (default, also for "") or URLModeWhole.
	URLMode string
}

// URL tokenization modes (--url-mode).
const (
	// URLModeHost tokenizes only a URL's userinfo and host, keeping scheme,
	// port, path and parameter names. The default.
	URLModeHost = "host"
	// URLModeWhole replaces each URL with a single URL_NNN token.
	URLModeWhole = "whole"
)

// DefaultDetectorChain builds the full detector chain in plan Decision 4
// order: UUID claim-only detector first, credentials/secrets (full
// redaction), then identity/network/path detectors, with the customer
// hostname allowlist substring pass running last. This is the chain real
// runs (via Run) should use.
func DefaultDetectorChain(opts ChainOptions) []detect.Detector {
	ipv4 := detect.NewIPv4Detector(opts.IPv4SkipRanges)
	ipv4.Classify = opts.IPClass
	chain := []detect.Detector{
		detect.UUIDDetector{},
		detect.CredentialsDetector{},
		detect.SecretsDetector{},
		detect.DNDetector{},
		detect.EmailDetector{},
		detect.URLDetector{HostOnly: opts.URLMode != URLModeWhole},
		detect.NewFQDNDetectorWithExtraTLDs(opts.ExtraTLDs),
		ipv4,
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

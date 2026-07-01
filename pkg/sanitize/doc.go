// Package sanitize is the public library API for sas-log-sanitize: it
// sanitizes a directory of SAS 9.4 support logs by replacing infrastructure
// identifiers, credentials, and PII with consistent, reversible tokens. See
// Options for configuration and Sanitize for the entry point.
//
// Scope note on profiles: internal/profile implements per-file format
// auto-detection (filename + first-line heuristics), but Sanitize does not
// yet build a separate detector chain per file based on that detection.
// Instead, Options.Profiles selects which built-in profiles'
// extra_internal_tlds get unioned into a single FQDN detector shared across
// the whole run. Full per-file profile-driven detector tuning (the plan's
// ipv4.skip_ranges and allowlist.case_insensitive config overrides) is not
// implemented.
package sanitize

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
// the whole run. The config file's detector overrides
// (detectors.fqdn.extra_internal_tlds, ipv4.skip_ranges, and
// allowlist.case_insensitive) are applied as whole-run settings, not
// per-file.
package sanitize

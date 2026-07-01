# Changelog

All notable changes to this project are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added
- Two-pass sanitization pipeline with deterministic, sequential per-category
  tokenization (`HOST_001`, `IPV4_001`, ...).
- Detectors for UUIDs (claim-only), credentials/secrets (full redaction),
  LDAP DNs, emails, URLs, FQDNs, IPv4/IPv6, MAC addresses, UNC paths,
  Kerberos principals, `DOMAIN\user`, bare usernames, and Unix/Windows
  user-home paths.
- Customer hostname allowlist (`--hostlist`) with substring matching and
  short/ambiguous-entry warnings.
- Cross-detector token consistency: a hostname found in a URL, UNC path, or
  standalone gets the same token wherever it appears.
- Audit pass (`internal/audit`) covering every rule in the design plan's
  audit table, sharing validation logic with the corresponding sanitization
  detectors to avoid false positives.
- Reverse mode (`--reverse`) and audit-only mode (`--audit-only`).
- Built-in YAML profiles (default, sas94, tomcat, apache, postgres-wipds,
  activemq, geode) with filename/first-line auto-detection.
- Full CLI: `--input`/`-i`, `--output`/`-o`, `--mapping`/`-m`, `--hostlist`,
  `--profiles`, `--audit`, `--strict`, `--config`, `--verbose`/`-v`,
  `--quiet`/`-q`, `--dry-run`, `--version`, `--help`.
- Docker-based build/test workflow (no local Go install required).

### Known limitations
See the README's Limitations section -- notably: SSH/PEM private key bodies
are not redacted (marker lines only), JDBC credentials combined with a bare
(non-dotted) hostname can leave that hostname untokenized, and per-file
profile-driven detector tuning is partial (only `extra_internal_tlds` is
wired through).

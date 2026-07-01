# Architecture

## Two-pass pipeline

Sanitization runs in two passes over the same ordered detector chain
(`internal/pipeline.Pipeline.walk`, shared by both passes so they can never
disagree about what matched):

1. **Scan** (`ScanLine`): walks every line of every file, registering every
   non-redacted, non-claim-only match into the token registry
   (`internal/tokenize.Registry`). This builds the full value -> token
   mapping before any output is written.
2. **Replace** (`ReplaceLine`): walks every line again, substituting each
   match with its already-assigned token (or `SECRET_REDACTED` for
   credentials/secrets) and writing the result.

Pass 1 must run to completion before Pass 2 starts, file order must be
deterministic (alphabetical, by relative path), and both passes must use an
identical line-by-line detector walk -- otherwise Pass 2 could try to replace
a value Pass 1 never registered. See `internal/pipeline/pipeline.go`.

## Token registry

`internal/tokenize.Registry` assigns sequential tokens (`HOST_001`,
`HOST_002`, ...) per category, in first-encounter order. The same value
always gets the same token within a run; a fresh `Registry` (and therefore a
fresh token numbering) is created for every run -- there is no cross-bundle
consistency by design (see README limitations).

## Span claiming

`internal/detect.LineState` tracks which byte ranges of the current line
have already been claimed by an earlier detector. The pipeline (not
individual detectors) applies this centrally: each detector returns
candidate matches independent of any other detector's state, and the
pipeline's `walk` accepts a candidate only if it doesn't overlap an
already-claimed span, in detector-list order.

Any overlap -- even partial -- rejects the whole candidate; there is no
"matching around" a claimed sub-span. This keeps replacement deterministic at
the cost of occasionally leaving a longer match unclaimed when an earlier,
narrower detector claimed part of it first (see
`detect.CredentialsDetector`'s doc comment for a concrete example with JDBC
connection strings).

## Detector ordering

Detectors run in a strict, fixed order (`pipeline.DefaultDetectorChain`):
UUID claim-only first, then credentials/secrets (full redaction), then
identity/network/path detectors from broadest-and-most-sensitive to
narrowest, with the customer hostname allowlist substring pass running last.
Order matters because of the span-claiming rule above -- see the ordering
table and rationale in the original design plan
(`sas-log-sanitize-plan.md`, Decision 4) if available, or
`internal/pipeline/detectors.go`.

## Cross-detector consistency

A hostname embedded in a URL or UNC path is also registered into the `HOST`
category during Pass 1 (`pipeline.registerEmbeddedHost`), so the same
hostname found standalone elsewhere in the bundle gets the same token. This
is registry-only -- it doesn't claim a span or change how the URL/UNC value
itself is replaced (it's still replaced as a single `URL_NNN`/`UNC_NNN`
token). Note the registry dedupes by exact string value: a hostname's
fully-qualified form (`db-prod-01.acme.internal`) and its bare form
(`db-prod-01`, e.g. from the allowlist) are different strings and get
different tokens even though they're the same physical host.

## Audit pass

`internal/audit.Scanner` re-scans already-sanitized output for patterns that
look like residual PII -- a second line of defense, not a guarantee. Several
rules deliberately share validation logic with the corresponding
sanitization detector (e.g. `detect.IsValidFQDN`,
`detect.LooksLikeVersionString`) so the audit pass doesn't flag text a
detector intentionally chose not to touch. High-severity rules are tuned to
have a low false-positive rate (what `--strict` gates on); Medium-severity
rules are intentionally broad and noisy by design -- false negatives are
worse than false positives for a security tool.

## Encoding and binary detection

`internal/io` handles BOM-based encoding detection (UTF-8/UTF-16LE/UTF-16BE),
Windows-1252 fallback for non-BOM, invalid-UTF-8 files, and binary file
skipping. One subtlety: binary-content sniffing must check for a UTF-16 BOM
*before* running its non-printable-byte-ratio heuristic, since UTF-16-encoded
ASCII text is roughly half NUL bytes and would otherwise be misdetected as
binary (see `pipeline.discoverFiles` and `sanitize.AuditDirectory`, which
both apply this check in that order).

# Architecture

## Two-pass pipeline

Sanitization runs in two passes over the same ordered detector chain
(`internal/pipeline.Pipeline.walk`, shared by both passes so they can never
disagree about what matched):

1. **Scan** (`ScanLine`): walks every line of every file, registering every
   non-redacted, non-claim-only match into the token registry
   (`internal/tokenize.Registry`). This builds the full value -> token
   mapping before any output is written.
2. **Known-values sweep** (between the passes,
   `Pipeline.EnableKnownValuesSweep`): once the registry is complete, a
   `detect.KnownValuesDetector` is built from every registered `USER` and
   `HOST` value (plus each host's short name) and appended as the last
   detector. See "Cross-detector consistency" below.
3. **Replace** (`ReplaceLine`): walks every line again, substituting each
   match with its already-assigned token (or `SECRET_REDACTED` for
   credentials/secrets) and writing the result. The audit pass scans each
   sanitized line as it is produced.

Pass 1 must run to completion before Pass 2 starts, and both passes must use
an identical detector walk -- otherwise Pass 2 could try to replace a value
Pass 1 never registered. The sweep only ever emits values that are already
registered, so it can be added for Pass 2 alone. See
`internal/pipeline/pipeline.go` and `internal/pipeline/run.go`.

## Inputs: discovery, archives, compression

`pipeline.discoverFiles` (`internal/pipeline/discover.go`) turns the input
into a list of files sorted by output path -- the order that token numbering
depends on:

- Binary files are skipped by extension or content sniffing. Sniffing checks
  for a UTF-16 BOM *before* the non-printable-byte heuristic, since
  UTF-16-encoded ASCII is roughly half NUL bytes.
- `*.gz` files are kept and read decompressed; their output is written back
  gzip-compressed under the same name.
- `.zip`, `.tar`, `.tar.gz` and `.tgz` archives (the input itself or anywhere
  inside it) are extracted by `internal/archive` into a private (0700)
  temporary directory that is removed when the run ends. Their files are
  output under a folder named after the archive (`bundle.zip` ->
  `bundle/...`). Entries with absolute or `..` paths, symlinks and other
  non-regular files, and archives inside archives are never written; they
  are reported as skipped. Total extracted bytes are capped
  (`--max-extract-mb`, default 20 GiB) against decompression bombs.

Every skipped file is listed, with its reason, at the top of `_summary.txt`,
in `_summary.json`, and in the CLI's exit summary.

## Streaming and parallelism

Files are streamed, never read whole: `openDecoded` reads a 64 KB sample to
detect the encoding, then feeds the rest through `ioenc.LineReader` from the
file handle (decompressing on the fly for `*.gz`). Peak memory depends on
the number of distinct values in the registry, not on file size.

Both passes run in parallel (`internal/pipeline/parallel.go`), at two
levels, without changing any result:

- **Across files**: each file is scanned into its own registry
  (`forkForScan`); the per-file registries are merged into the run's
  registry in sorted-path order (`Registry.Merge`). Numbering is per
  category, so this gives exactly the tokens a sequential scan would.
- **Within a file**: `processChunks` has one reader goroutine split the file
  into chunks of lines and hand them to workers, then emits results in
  input order -- Pass 1 merges chunk registries in order, Pass 2 writes
  chunk output in order. State that spans lines (whether a line is inside a
  multi-line PEM private-key block) is computed by the single reader, never
  by the workers.

A semaphore caps CPU-bound work at `--workers` (default one per CPU) across
all files, and each file has a bounded window of in-flight chunks. Audit
findings and replacement counts are collected per file/chunk and combined in
input order, so `_audit.txt` and `_summary.*` are identical for any worker
count. Progress (files, MB, MB/s, ETA) goes to stderr.

Two cheap checks keep most regexes off most lines: detectors may implement
`detect.Prefilter` (`MightMatch`: e.g. no `@` means no email), and the
credential and secret detectors gate each of their rules on a keyword it
requires. Both are conservative -- `TestPrefiltersAreConservative` checks
that a prefilter never rejects a line its detector would match.

## HAR files

`*.har` files (and `*.json` files starting with a top-level `"log"` key,
including `*.har.gz`) go through `internal/har` instead of the line
pipeline. It streams the JSON token by token, preserving key order and
number formatting, and writes indented output:

- credential headers (Authorization, Cookie, Set-Cookie, CSRF/XSRF/token/
  API-key/session headers) and every cookie value are redacted whole;
- `queryString` / `postData.params` values are redacted when the parameter
  name is a credential (`ticket`, `code`, `state`, `password`, ...);
- response bodies are dropped (kept and scanned with `--keep-har-bodies`);
- timings, sizes, status, methods and header names are untouched;
- every other string value goes through the normal detector walk.

Only small name/value list entries are parsed whole; everything else,
including bodies being dropped, is streamed, so memory is bounded by the
largest single string. Pass 1 decides per file whether the HAR parses: a
HAR that doesn't (e.g. truncated) falls back to line-based processing in
*both* passes, so Pass 2 never writes half a JSON document.

## Token registry

`internal/tokenize.Registry` assigns sequential tokens (`HOST_001`,
`HOST_002`, ...) per category, in first-encounter order. The same value
always gets the same token within a run; a fresh `Registry` (and therefore a
fresh token numbering) is created for every run -- there is no cross-bundle
consistency by design (see README limitations).

`HOST`, `DOMAIN` and `EMAIL` values are case-insensitive:
`SASMID01.corp.example.com` and `sasmid01.corp.example.com` share one token,
and the mapping keeps the spelling seen first. `USER` stays case-sensitive
(Unix usernames are). Token categories may have several parts
(`IPV4_PRIV_001` with `--ip-class`); reverse mode and the audit's token-shape
checks accept that form.

## Span claiming

`internal/detect.LineState` tracks which byte ranges of the current line
have already been claimed by an earlier detector. The pipeline (not
individual detectors) applies this centrally: each detector returns
candidate matches independent of any other detector's state, and the
pipeline's `walk` accepts a candidate only if it doesn't overlap an
already-claimed span, in detector-list order.

Any overlap -- even partial -- rejects the whole candidate; there is no
"matching around" a claimed sub-span. This keeps replacement deterministic
at the cost of occasionally leaving a longer match unclaimed when an
earlier, narrower detector claimed part of it first. Two consequences shape
the rules:

- Inside `CredentialsDetector`, free-text values (HTTP Authorization and
  cookie headers) and per-parameter URL/form values are matched *before*
  the generic `key=value` rules, so no narrower rule can claim a fragment
  and drop the whole value.
- A credential rule claiming a query-string value makes the URL detector
  skip that URL; the host inside it is then tokenized by the FQDN/IPv4
  detectors. (With the default `--url-mode=host` the URL detector only
  claims the userinfo and host anyway.)

## Detector ordering

Detectors run in a strict, fixed order (`pipeline.DefaultDetectorChain`):
UUID claim-only first, then credentials/secrets (full redaction), then
identity/network/path detectors from broadest-and-most-sensitive to
narrowest, with the customer hostname allowlist substring pass after them
and the known-values sweep (added for Pass 2) last of all. Order matters
because of the span-claiming rule above -- see the ordering table and
rationale in the original design plan (`sas-log-sanitize-plan.md`, Decision
4) if available, or `internal/pipeline/detectors.go`.

The UUID detector runs first so nothing matches *inside* a UUID, but it does
not claim a UUID that is the value of a credential (a CSRF token, a session
cookie, `"access_token":"<uuid>"`): when a line holds a UUID it consults the
credential and secret rules and leaves UUIDs inside their redaction spans
for them. Claiming those would make the credential rules skip them and leak
the secret.

## Cross-detector consistency

Several mechanisms make the same real value get the same token everywhere:

- **Hosts inside URLs and UNC paths.** In the default `--url-mode=host`,
  the URL detector tokenizes a URL's host as `HOST` directly (and its
  userinfo as `USER`/redacted), so it shares a token with the same host
  elsewhere. In `--url-mode=whole`, and for UNC paths, the whole value
  becomes one `URL_NNN`/`UNC_NNN` token and the embedded host/server is
  additionally registered into `HOST` during Pass 1
  (`pipeline.registerEmbeddedHost`).
- **Known-values sweep.** A `USER` or `HOST` value found anywhere is
  replaced everywhere in Pass 2, whole-word and case-insensitively --
  including lines and files where no detector matched it (`user jdoe logged
  in` after `/home/jdoe/` was seen). A host's first label is swept too, with
  the full name's token: `pghost01` becomes the token of
  `pghost01.corp.example.com`, so reverse mode returns the full name. Values
  shorter than 3 (users) or 4 (host labels) characters, purely numeric
  values, common words and generic account names (`admin`, `root`, `sas`,
  ...) are not swept, and short names are only taken from names with three
  or more labels (in `acme.com`, `acme` is the organization, not a host).
  Matching is a hash lookup at each word start, not a regex alternation --
  an alternation of thousands of case-insensitive values is far too slow.
- **Case-insensitive host/domain/email tokens** (see "Token registry").

A host that only ever appears as a bare short name, never with its full
name, is still only caught by the allowlist (`--hostlist`).

## Audit pass

`internal/audit.Scanner` re-scans already-sanitized output for patterns that
look like residual PII -- a second line of defense, not a guarantee. Several
rules deliberately share validation logic with the corresponding
sanitization detector (e.g. `detect.IsValidFQDN`,
`detect.LooksLikeVersionString`) so the audit pass doesn't flag text a
detector intentionally chose not to touch.

Besides shape rules, the High `known-original-value` rule searches the
output for every original value the run knows about -- the sweep's values
plus every value of every other category in the mapping -- so a leak no
shape rule recognizes (a bare username) is still caught, as is any future
detector regression. `--audit-only` reads the mapping from `--mapping` or
finds it next to the directory.

High-severity rules are tuned to have a low false-positive rate (any High
finding exits 1); Medium-severity rules are intentionally broad and noisy by
design -- false negatives are worse than false positives for a security
tool -- so they only fail a run under `--strict`. Known non-PII noise is
suppressed: httpd message IDs (`AH01102`), Java build suffixes (`-b10`),
and long attribute *names* containing a credential keyword
(`certificateKeystorePassword`).

## Encoding

`internal/io` handles BOM-based encoding detection (UTF-8/UTF-16LE/UTF-16BE)
and, for files without a BOM, the UTF-8 vs Windows-1252 decision. That
decision is made from the 64 KB sample (`DetectSample`, which ignores a
multi-byte character cut off at the sample's end). Output bytes are
preserved either way -- invalid bytes pass through a Go string unchanged --
and `TestLateWindows1252BytesRoundTrip` checks that a Windows-1252 byte
after the sample neither corrupts output nor hides a value from the
detectors. Line endings (CRLF/LF) and a missing final newline are reproduced
exactly.

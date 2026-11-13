# Add a detector

This guide walks through adding a new detector to `internal/detect` and
wiring it into the pipeline. Read [Architecture](architecture.md#span-claiming)
first: span claiming and detector order decide whether your detector ever
sees a value.

## Before you start

Check whether you need a new detector at all.

- **A value is missed only in some bundles?** A `--hostlist` or
  `extra_internal_tlds` entry may be enough. See
  [Tune detection](guides/tune-detection.md).
- **A new credential key or header?** Add a rule to `CredentialsDetector`
  instead of writing a new detector.

## 1. Implement the interface

Add a type in `internal/detect`, in a new file or an existing one:

```go
type MyDetector struct{}

func (MyDetector) Name() string { return "my-thing" }

func (MyDetector) Detect(line string) []Match {
	// Return every candidate in the line. Don't check LineState:
	// the pipeline applies span claiming centrally.
}
```

Set these fields on each `Match`:

| Field | Set it to |
|---|---|
| `Span`, `Value` | The byte range of the match, and the matched text. |
| `Category` | The token category (for example `"HOST"`) to pseudonymize the value. Leave it empty for a claim-only match, which occupies a span and is never replaced (see `UUIDDetector`). |
| `Redact` | `true` for secrets. A redacted match becomes `SECRET_REDACTED` and is never registered. **Leave `Category` empty** on redacted matches. |

**Rules:**

- **Be a pure function of the line.** Pass 2 skips any detector that found
  nothing on the same line in Pass 1. A detector that depends on other state
  produces wrong output.
- **Implement `Prefilter` if you can.** A cheap `MightMatch(line) bool` check
  keeps your detector off most lines. It must never reject a line that
  `Detect` would match. `TestPrefiltersAreConservative` checks this.

## 2. Place it in the chain

Add the detector to `DefaultDetectorChain` in
`internal/pipeline/detectors.go`. Order matters. Earlier detectors claim
spans first, and a candidate that overlaps any claimed span is dropped
entirely.

- Put broad, sensitive detectors (credentials, secrets, DNs) **before**
  narrow ones (paths, bare usernames).
- Ask what else could match the same text, and which of the two should win.

## 3. Write tests

In `<file>_test.go`, include at least:

- **5 positive cases:** values that must match.
- **5 negative cases:** look-alikes that must not match.
- **2 edge cases:** an overlap with another detector, and an encoding edge case.

Use `expectSubstringMatches` and `resolveOverlaps` from `testhelpers_test.go`
instead of writing byte offsets by hand.

For an end-to-end check, add a golden case under `testdata/golden/<name>/`
with an `input/` folder and an `expected/` folder.

## 4. Keep secrets out of the mapping file

If the detector finds secrets, make sure the value can't reach the registry.
`ScanLine` filters out `Redact: true` matches before registering anything.
Don't get around that by also setting a `Category`.

## 5. Share logic with the audit

If the audit needs the same judgment (a suppression heuristic, a validity
check), export a function from `internal/detect` and call it from
`internal/audit/scanner.go`. Don't re-implement it with a second regex. Two
copies of "is this a false positive?" drift apart. That has already caused
bugs here, which is why `LooksLikeVersionString` and `IsValidFQDN` are shared.

## 6. Update acceptance tests

If the detector changes what typical sanitized output looks like, update
`pkg/sanitize/sanitize_test.go` or
`internal/pipeline/golden_audit_test.go`. The zero-High-findings acceptance
test needs to stay meaningful.

## 7. Document it

Add a row to [Detectors](reference/detectors.md) in the right position, along
with any new limitation. If the detector adds a token category, add it to
[Output files](reference/output-files.md#token-categories).

## 8. Check

```sh
make test
make lint
```

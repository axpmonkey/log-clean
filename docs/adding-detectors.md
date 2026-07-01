# Adding a detector

1. **Implement the `detect.Detector` interface** in a new or existing file
   under `internal/detect`:

   ```go
   type MyDetector struct{}

   func (MyDetector) Name() string { return "my-thing" }

   func (MyDetector) Detect(line string) []Match {
       // Find candidates; return them independent of any other detector's
       // state. The pipeline applies span-claiming centrally -- you don't
       // need to check LineState yourself.
   }
   ```

   - Set `Category` to a token category (e.g. `"HOST"`) for values that
     should be pseudonymized, or leave it empty for a claim-only detector
     (no replacement, just occupies a span -- see `UUIDDetector`).
   - Set `Redact: true` for secrets that must never be tokenized or recorded
     in the mapping file (passwords, API keys, etc.).

2. **Decide where it goes in detector order** (`pipeline.DefaultDetectorChain`
   in `internal/pipeline/detectors.go`). Order matters: earlier detectors
   claim their spans first, and any overlap with an already-claimed span
   discards a later candidate entirely (no partial/sub-span matching). Put
   broader, more sensitive detectors (credentials, secrets, DNs) before
   narrower ones (paths, bare usernames).

3. **Write tests** in `<file>_test.go`: at minimum 5 positive cases, 5
   negative cases, and 2 edge cases (overlap with another detector, an
   encoding edge case). Use `expectSubstringMatches` /
   `resolveOverlaps` from `testhelpers_test.go` rather than hand-computing
   byte offsets -- they're error-prone to get right by hand.

4. **If your detector emits secrets**, make sure there's no path by which the
   matched value could end up in the registry or mapping file. `Redact: true`
   matches are filtered out of registration in `pipeline.ScanLine`; don't
   bypass that by also giving a redacted match a non-empty `Category`.

5. **If your detector's logic needs to be shared with the audit pass** (e.g.
   a suppression heuristic, or a validation check like TLD allowlisting),
   export the relevant function from `internal/detect` and have
   `internal/audit/scanner.go` call it directly, rather than re-implementing
   similar logic with a separate regex. Two independent implementations of
   "is this really a false positive" will drift -- this has already caused
   real bugs in this codebase (see the `LooksLikeVersionString` and
   `IsValidFQDN` sharing, both added after the audit pass initially
   re-derived its own, slightly different versions and produced false
   positives).

6. **Update `pkg/sanitize/sanitize_test.go` or
   `internal/pipeline/golden_audit_test.go`** if your detector changes the
   shape of typical sanitized output, so the zero-High-findings acceptance
   test stays meaningful.

7. Run `make test` and `make lint` before submitting.

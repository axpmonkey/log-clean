package sanitize

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"sas-log-sanitize/internal/audit"
	"sas-log-sanitize/internal/detect"
	"sas-log-sanitize/internal/pipeline"
	"sas-log-sanitize/internal/profile"
	"sas-log-sanitize/internal/runlog"
	"sas-log-sanitize/internal/tokenize"
)

// Result summarizes a completed sanitization run.
type Result struct {
	FilesProcessed  int
	FilesSkipped    []pipeline.SkippedFile
	BytesProcessed  int64
	AuditFindings   []audit.Finding
	HasHighFindings bool
	// Strict records whether the run was --strict (it changes ExitStatus).
	Strict            bool
	MappingPath       string
	OutputDir         string
	ReplacementCounts map[string]int
	// HostlistWarnings are the hostlist parser's warnings. They quote
	// hostlist entries (real hostnames), so they are returned for the CLI to
	// print to stderr instead of being written to _runlog.txt, which lives in
	// the shareable output directory.
	HostlistWarnings []string
}

// Sanitize runs a full sanitization pass per opts: discovers files under
// opts.InputDir, replaces detected identifiers/credentials with tokens, and
// (unless opts.DryRun) writes sanitized output, the mapping file, an audit
// report, and a summary to opts.OutputDir, plus a runlog of the run itself.
func Sanitize(opts Options) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	opts = opts.applyDefaults()
	if err := opts.checkMappingLocation(); err != nil {
		return Result{}, err
	}

	// opts.InputDir may name either a directory (a full log bundle) or a
	// single file -- pipeline.Run's discoverFiles/relPath logic handles
	// both, so the only thing checked here is that the path exists at all.
	_, err := os.Stat(opts.InputDir)
	if err != nil {
		return Result{}, inputErrorf("input path %s: %w", opts.InputDir, err)
	}

	var logWriter io.Writer = io.Discard
	var runlogFile *os.File
	if !opts.DryRun {
		if err := os.MkdirAll(opts.OutputDir, 0o755); err != nil {
			return Result{}, inputErrorf("creating output directory %s: %w", opts.OutputDir, err)
		}
		runlogFile, err = os.Create(filepath.Join(opts.OutputDir, "_runlog.txt"))
		if err != nil {
			return Result{}, processingErrorf("creating runlog: %w", err)
		}
		defer runlogFile.Close()
		logWriter = runlogFile
	}
	log := runlog.New(logWriter, opts.Verbose)
	log.Info("sas-log-sanitize %s starting: input=%s output=%s dry_run=%v", opts.ToolVersion, opts.InputDir, opts.OutputDir, opts.DryRun)

	allowlist, hostlistWarnings, err := loadAllowlist(opts.HostlistPath, log)
	if err != nil {
		return Result{}, err
	}

	ignoreList, err := loadIgnoreList(opts.IgnorelistPath)
	if err != nil {
		return Result{}, err
	}

	skipRanges, err := parseSkipRanges(opts.IPv4SkipRanges)
	if err != nil {
		return Result{}, err
	}

	extraTLDs, err := resolveExtraTLDs(opts.Profiles, opts.ExtraInternalTLDs, log)
	if err != nil {
		return Result{}, err
	}

	chain := pipeline.DefaultDetectorChain(pipeline.ChainOptions{
		ExtraTLDs:                extraTLDs,
		Allowlist:                allowlist,
		AllowlistCaseInsensitive: opts.AllowlistCaseInsensitive,
		IPv4SkipRanges:           skipRanges,
		URLMode:                  opts.URLMode,
		IPClass:                  opts.IPClass,
	})
	p := pipeline.New(chain)
	p.Ignore = ignoreList
	p.IPv4SkipRanges = skipRanges

	runResult, err := pipeline.Run(p, pipeline.RunOptions{
		InputDir:      opts.InputDir,
		OutputDir:     opts.OutputDir,
		AuditEnabled:  opts.AuditEnabled,
		DryRun:        opts.DryRun,
		ToolVersion:   opts.ToolVersion,
		KeepHARBodies: opts.KeepHARBodies,
		Workers:       opts.Workers,
		Progress:      opts.Progress,

		MaxExtractBytes: opts.MaxExtractBytes,
	}, log)
	if err != nil {
		log.Error("run failed: %v", err)
		return Result{}, processingErrorf("sanitizing %s: %w", opts.InputDir, err)
	}

	hasHigh := audit.HasHigh(runResult.AuditFindings)
	log.Info("done: %d files processed, %d skipped, %d audit findings (high=%v)",
		runResult.FilesProcessed, len(runResult.FilesSkipped), len(runResult.AuditFindings), hasHigh)

	if !opts.DryRun {
		if err := tokenize.WriteMappingFile(opts.MappingPath, runResult.Mapping); err != nil {
			return Result{}, processingErrorf("writing mapping file: %w", err)
		}
		if opts.AuditEnabled {
			auditPath := filepath.Join(opts.OutputDir, "_audit.txt")
			if err := os.WriteFile(auditPath, []byte(audit.Report(runResult.AuditFindings)), 0o644); err != nil {
				return Result{}, processingErrorf("writing audit report: %w", err)
			}
		}
		summaryPath := filepath.Join(opts.OutputDir, "_summary.txt")
		if err := os.WriteFile(summaryPath, []byte(formatSummary(runResult)), 0o644); err != nil {
			return Result{}, processingErrorf("writing summary: %w", err)
		}
		js, err := summaryJSON(runResult, opts)
		if err != nil {
			return Result{}, processingErrorf("encoding summary: %w", err)
		}
		if err := os.WriteFile(filepath.Join(opts.OutputDir, "_summary.json"), js, 0o644); err != nil {
			return Result{}, processingErrorf("writing summary: %w", err)
		}
	}

	return Result{
		FilesProcessed:    runResult.FilesProcessed,
		FilesSkipped:      runResult.FilesSkipped,
		BytesProcessed:    runResult.BytesProcessed,
		AuditFindings:     runResult.AuditFindings,
		HasHighFindings:   hasHigh,
		Strict:            opts.Strict,
		MappingPath:       opts.MappingPath,
		OutputDir:         opts.OutputDir,
		ReplacementCounts: runResult.ReplacementCounts,
		HostlistWarnings:  hostlistWarnings,
	}, nil
}

// loadAllowlist parses the hostlist. Its warnings quote entries (real
// hostnames), so only their count goes to the runlog; the text is returned
// for the caller to show outside the output directory.
func loadAllowlist(hostlistPath string, log *runlog.Logger) ([]string, []string, error) {
	if hostlistPath == "" {
		return nil, nil, nil
	}
	f, err := os.Open(hostlistPath)
	if err != nil {
		return nil, nil, inputErrorf("opening hostlist %s: %w", hostlistPath, err)
	}
	defer f.Close()

	entries, warnings, err := detect.LoadAllowlist(f)
	if err != nil {
		return nil, nil, configErrorf("parsing hostlist %s: %w", hostlistPath, err)
	}
	if len(warnings) > 0 {
		log.Warn("hostlist: %d warnings (shown on stderr; not logged here because they quote hostlist entries)", len(warnings))
	}
	return entries, warnings, nil
}

func loadIgnoreList(ignorelistPath string) (detect.IgnoreList, error) {
	if ignorelistPath == "" {
		return detect.IgnoreList{}, nil
	}
	f, err := os.Open(ignorelistPath)
	if err != nil {
		return detect.IgnoreList{}, inputErrorf("opening ignorelist %s: %w", ignorelistPath, err)
	}
	defer f.Close()

	list, err := detect.LoadIgnoreList(f)
	if err != nil {
		return detect.IgnoreList{}, configErrorf("parsing ignorelist %s: %w", ignorelistPath, err)
	}
	return list, nil
}

// parseSkipRanges converts CIDR strings (detectors.ipv4.skip_ranges) into
// parsed prefixes, returning a config-kind error on the first malformed one
// so a typo in the config surfaces immediately rather than silently skipping
// nothing.
func parseSkipRanges(cidrs []string) ([]netip.Prefix, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, configErrorf("invalid ipv4 skip_range %q: %w", c, err)
		}
		prefixes = append(prefixes, p)
	}
	return prefixes, nil
}

// resolveExtraTLDs unions extra_internal_tlds across every requested profile
// (or every built-in profile, for "auto"/unset) with the config file's own
// detectors.fqdn.extra_internal_tlds (configTLDs). See doc.go's scope note:
// this is a whole-run union, not a true per-file profile selection.
func resolveExtraTLDs(requested []string, configTLDs []string, log *runlog.Logger) ([]string, error) {
	builtin, err := profile.LoadBuiltin()
	if err != nil {
		return nil, processingErrorf("loading built-in profiles: %w", err)
	}

	useAll := len(requested) == 0
	for _, r := range requested {
		if r == "auto" {
			useAll = true
		}
	}

	var selected []profile.Profile
	if useAll {
		selected = builtin
	} else {
		for _, name := range requested {
			p, ok := profile.ByName(builtin, name)
			if !ok {
				return nil, configErrorf("unknown profile %q", name)
			}
			selected = append(selected, p)
		}
	}

	// Dedup case-insensitively, since the FQDN detector lowercases extra TLDs
	// anyway (detect.NewFQDNDetectorWithExtraTLDs); keep first-seen casing.
	seen := map[string]bool{}
	var extra []string
	add := func(tlds []string) {
		for _, tld := range tlds {
			key := strings.ToLower(tld)
			if !seen[key] {
				seen[key] = true
				extra = append(extra, tld)
			}
		}
	}
	for _, p := range selected {
		add(p.ExtraInternalTLDs)
	}
	add(configTLDs)

	log.Info("profiles in effect: %s (extra TLDs: %v)", profileNames(selected), extra)
	return extra, nil
}

func profileNames(profiles []profile.Profile) string {
	names := ""
	for i, p := range profiles {
		if i > 0 {
			names += ","
		}
		names += p.Name
	}
	return names
}

// Exit statuses a successful run can end with (errors exit 2-4 and never
// produce a Result).
const (
	ExitClean    = 0 // no High findings (and, with --strict, no findings at all)
	ExitFindings = 1 // High findings, or any finding with --strict
)

// ExitStatus is the CLI exit code for this result. The CLI, --audit-only and
// _summary.json all use the same rule (ExitStatusFor), so they can't
// disagree.
func (r Result) ExitStatus() int {
	return ExitStatusFor(r.AuditFindings, r.Strict)
}

// ExitStatusFor applies the exit-code rule: High findings exit 1; Medium
// findings exit 1 only under --strict. Medium rules are deliberately broad
// (they flag words like "java8"), so letting them fail every run made exit
// code 1 near-universal and meaningless.
func ExitStatusFor(findings []audit.Finding, strict bool) int {
	if audit.HasHigh(findings) || (strict && len(findings) > 0) {
		return ExitFindings
	}
	return ExitClean
}

// SummarySchemaVersion is the _summary.json schema version.
const SummarySchemaVersion = 1

// summaryJSON renders _summary.json: the run's counts in machine-readable
// form for other tools (e.g. sas-casefile build). It holds counts, relative
// paths and reasons only -- never an original value.
func summaryJSON(r pipeline.RunResult, opts Options) ([]byte, error) {
	type skipped struct {
		Path   string `json:"path"`
		Reason string `json:"reason"`
	}
	type auditCounts struct {
		Enabled bool `json:"enabled"`
		High    int  `json:"high"`
		Medium  int  `json:"medium"`
	}
	s := struct {
		SchemaVersion          int            `json:"schema_version"`
		ToolVersion            string         `json:"tool_version"`
		FilesProcessed         int            `json:"files_processed"`
		FilesSkipped           int            `json:"files_skipped"`
		BytesProcessed         int64          `json:"bytes_processed"`
		ReplacementsByCategory map[string]int `json:"replacements_by_category"`
		UniqueValuesByCategory map[string]int `json:"unique_values_by_category"`
		SkippedFiles           []skipped      `json:"skipped_files"`
		Audit                  auditCounts    `json:"audit"`
		ExitStatus             int            `json:"exit_status"`
	}{
		SchemaVersion:          SummarySchemaVersion,
		ToolVersion:            opts.ToolVersion,
		FilesProcessed:         r.FilesProcessed,
		FilesSkipped:           len(r.FilesSkipped),
		BytesProcessed:         r.BytesProcessed,
		ReplacementsByCategory: r.ReplacementCounts,
		UniqueValuesByCategory: map[string]int{},
		SkippedFiles:           []skipped{},
		Audit:                  auditCounts{Enabled: opts.AuditEnabled},
		ExitStatus:             ExitStatusFor(r.AuditFindings, opts.Strict),
	}
	for cat, m := range r.Mapping.Categories {
		s.UniqueValuesByCategory[cat] = len(m)
	}
	for _, f := range r.FilesSkipped {
		s.SkippedFiles = append(s.SkippedFiles, skipped{Path: filepath.ToSlash(f.RelPath), Reason: f.Reason})
	}
	for _, f := range r.AuditFindings {
		if f.Severity == audit.SeverityHigh {
			s.Audit.High++
		} else {
			s.Audit.Medium++
		}
	}
	out, err := json.MarshalIndent(s, "", "  ")
	return append(out, '\n'), err
}

func formatSummary(r pipeline.RunResult) string {
	// Skipped files come first: a skipped file is history the analysis
	// won't see (a rotated log, an unreadable archive), so it must not be
	// buried under the counts.
	out := fmt.Sprintf("Skipped files (%d):\n", len(r.FilesSkipped))
	if len(r.FilesSkipped) == 0 {
		out += "  none\n"
	}
	for _, s := range r.FilesSkipped {
		out += fmt.Sprintf("  %s: %s\n", s.RelPath, s.Reason)
	}
	out += fmt.Sprintf("\nFiles processed: %d\nFiles skipped: %d\nBytes processed: %d\n\nReplacements by category:\n",
		r.FilesProcessed, len(r.FilesSkipped), r.BytesProcessed)
	// Sort categories so the summary is byte-for-byte deterministic across
	// runs -- ranging over the map directly would emit them in Go's
	// randomized map-iteration order.
	cats := make([]string, 0, len(r.ReplacementCounts))
	for cat := range r.ReplacementCounts {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	for _, cat := range cats {
		out += fmt.Sprintf("  %s: %d\n", cat, r.ReplacementCounts[cat])
	}
	return out
}

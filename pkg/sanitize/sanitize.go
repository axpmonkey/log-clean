package sanitize

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"sas-log-sanitize/internal/audit"
	"sas-log-sanitize/internal/detect"
	"sas-log-sanitize/internal/pipeline"
	"sas-log-sanitize/internal/profile"
	"sas-log-sanitize/internal/runlog"
	"sas-log-sanitize/internal/tokenize"
)

// Result summarizes a completed sanitization run.
type Result struct {
	FilesProcessed    int
	FilesSkipped      []pipeline.SkippedFile
	BytesProcessed    int64
	AuditFindings     []audit.Finding
	HasHighFindings   bool
	MappingPath       string
	OutputDir         string
	ReplacementCounts map[string]int
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

	allowlist, err := loadAllowlist(opts.HostlistPath, log)
	if err != nil {
		return Result{}, err
	}

	ignoreList, err := loadIgnoreList(opts.IgnorelistPath)
	if err != nil {
		return Result{}, err
	}

	extraTLDs, err := resolveExtraTLDs(opts.Profiles, log)
	if err != nil {
		return Result{}, err
	}

	chain := pipeline.DefaultDetectorChain(extraTLDs, allowlist)
	p := pipeline.New(chain)
	p.Ignore = ignoreList

	runResult, err := pipeline.Run(p, pipeline.RunOptions{
		InputDir:     opts.InputDir,
		OutputDir:    opts.OutputDir,
		AuditEnabled: opts.AuditEnabled,
		DryRun:       opts.DryRun,
		ToolVersion:  opts.ToolVersion,
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
	}

	return Result{
		FilesProcessed:    runResult.FilesProcessed,
		FilesSkipped:      runResult.FilesSkipped,
		BytesProcessed:    runResult.BytesProcessed,
		AuditFindings:     runResult.AuditFindings,
		HasHighFindings:   hasHigh,
		MappingPath:       opts.MappingPath,
		OutputDir:         opts.OutputDir,
		ReplacementCounts: runResult.ReplacementCounts,
	}, nil
}

func loadAllowlist(hostlistPath string, log *runlog.Logger) ([]string, error) {
	if hostlistPath == "" {
		return nil, nil
	}
	f, err := os.Open(hostlistPath)
	if err != nil {
		return nil, inputErrorf("opening hostlist %s: %w", hostlistPath, err)
	}
	defer f.Close()

	entries, warnings, err := detect.LoadAllowlist(f)
	if err != nil {
		return nil, configErrorf("parsing hostlist %s: %w", hostlistPath, err)
	}
	for _, w := range warnings {
		log.Warn("hostlist: %s", w)
	}
	return entries, nil
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

// resolveExtraTLDs unions extra_internal_tlds across every requested
// profile (or every built-in profile, for "auto"/unset). See doc.go's scope
// note: this is a whole-run union, not a true per-file profile selection.
func resolveExtraTLDs(requested []string, log *runlog.Logger) ([]string, error) {
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

	seen := map[string]bool{}
	var extra []string
	for _, p := range selected {
		for _, tld := range p.ExtraInternalTLDs {
			if !seen[tld] {
				seen[tld] = true
				extra = append(extra, tld)
			}
		}
	}
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

func formatSummary(r pipeline.RunResult) string {
	out := fmt.Sprintf("Files processed: %d\nFiles skipped: %d\nBytes processed: %d\n\nReplacements by category:\n",
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
	if len(r.FilesSkipped) > 0 {
		out += "\nSkipped files:\n"
		for _, s := range r.FilesSkipped {
			out += fmt.Sprintf("  %s: %s\n", s.RelPath, s.Reason)
		}
	}
	return out
}

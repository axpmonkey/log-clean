// Command sanitize is the CLI entry point for sas-log-sanitize.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"sas-log-sanitize/internal/audit"
	"sas-log-sanitize/internal/profile"
	"sas-log-sanitize/pkg/sanitize"
)

// version is set by the Makefile via -ldflags at build time.
var version = "dev"

// Exit codes per the plan's CLI design.
const (
	exitOK = iota
	exitFindingsWarning
	exitInputError
	exitProcessingError
	exitConfigError
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type flags struct {
	input, output, mapping, hostlist, ignorelist, profiles, config string
	urlMode                                                        string
	workers, maxExtractMB                                          int
	audit, strict, reverseMode, auditOnly, allowMappingInOutput    bool
	keepHARBodies, ipClass                                         bool
	verbose, quiet, dryRun                                         bool
	showVersion, showHelp                                          bool

	// Config-file-only detector overrides (no CLI flag): populated by
	// applyConfigFile from the config's detectors section.
	ipv4SkipRanges           []string
	allowlistCaseInsensitive bool
	extraInternalTLDs        []string
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sas-log-sanitize", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var f flags
	fs.StringVar(&f.input, "input", "", "input directory, a single log file, or a .zip/.tar/.tar.gz bundle")
	fs.StringVar(&f.input, "i", "", "shorthand for --input")
	fs.StringVar(&f.output, "output", "", "output directory (default: <input>-sanitized)")
	fs.StringVar(&f.output, "o", "", "shorthand for --output")
	fs.StringVar(&f.mapping, "mapping", "", "path for mapping file (default: <output>.mapping.json, next to the output directory)")
	fs.BoolVar(&f.allowMappingInOutput, "allow-mapping-in-output", false, "allow --mapping to point inside the output directory")
	fs.StringVar(&f.mapping, "m", "", "shorthand for --mapping")
	fs.StringVar(&f.hostlist, "hostlist", "", "path to customer-supplied hostname allowlist")
	fs.StringVar(&f.ignorelist, "ignorelist", "", "path to hostnames/domains to never redact (supports \"*.domain\" wildcards)")
	fs.StringVar(&f.urlMode, "url-mode", "host", `"host" tokenizes only a URL's userinfo and host (keeps port/path); "whole" replaces the entire URL`)
	fs.BoolVar(&f.keepHARBodies, "keep-har-bodies", false, "keep HAR response bodies (scanned) instead of dropping them")
	fs.BoolVar(&f.ipClass, "ip-class", false, "tokenize IPv4 addresses as IPV4_PRIV_NNN / IPV4_PUB_NNN to keep internal vs external visible")
	fs.IntVar(&f.maxExtractMB, "max-extract-mb", 20480, "cap on total bytes extracted from .zip/.tar archives, in MB (decompression-bomb guard)")
	fs.IntVar(&f.workers, "workers", 0, "files processed in parallel per pass (default: one per CPU)")
	fs.StringVar(&f.profiles, "profiles", "auto", `comma-separated profiles to apply, or "auto"`)
	fs.BoolVar(&f.audit, "audit", true, "run audit pass after sanitization")
	fs.BoolVar(&f.strict, "strict", false, "also exit 1 on Medium-severity audit findings (High findings always exit 1)")
	fs.BoolVar(&f.reverseMode, "reverse", false, "reverse mode: substitute tokens back to original values")
	fs.BoolVar(&f.auditOnly, "audit-only", false, "audit-only mode: scan an already-sanitized directory")
	fs.StringVar(&f.config, "config", "", "path to YAML config file")
	fs.BoolVar(&f.verbose, "verbose", false, "verbose logging to the runlog")
	fs.BoolVar(&f.verbose, "v", false, "shorthand for --verbose")
	fs.BoolVar(&f.quiet, "quiet", false, "suppress non-error output")
	fs.BoolVar(&f.quiet, "q", false, "shorthand for --quiet")
	fs.BoolVar(&f.dryRun, "dry-run", false, "show what would be replaced, write nothing")
	fs.BoolVar(&f.showVersion, "version", false, "print version and exit")
	fs.BoolVar(&f.showHelp, "help", false, "show usage")

	if err := fs.Parse(args); err != nil {
		return exitConfigError
	}

	if f.showVersion {
		fmt.Fprintf(stdout, "sas-log-sanitize %s\n", version)
		return exitOK
	}
	if f.showHelp {
		fs.Usage()
		return exitOK
	}

	if f.config != "" {
		if code := applyConfigFile(&f, fs, stderr); code != exitOK {
			return code
		}
	}

	switch {
	case f.reverseMode:
		return runReverse(&f, fs.Args(), stdout, stderr)
	case f.auditOnly:
		return runAuditOnly(&f, fs.Args(), stdout, stderr)
	default:
		return runSanitize(&f, fs.Args(), stdout, stderr)
	}
}

func applyConfigFile(f *flags, fs *flag.FlagSet, stderr io.Writer) int {
	data, err := os.ReadFile(f.config)
	if err != nil {
		fmt.Fprintf(stderr, "sas-log-sanitize: reading config %s: %v\n", f.config, err)
		return exitConfigError
	}
	cfg, err := profile.ParseConfig(data)
	if err != nil {
		fmt.Fprintf(stderr, "sas-log-sanitize: parsing config %s: %v\n", f.config, err)
		return exitConfigError
	}
	// Flags explicitly set on the command line win over config file values;
	// flag.Visit only calls back for flags actually passed by the user.
	explicit := map[string]bool{}
	fs.Visit(func(fl *flag.Flag) { explicit[fl.Name] = true })

	if cfg.Output != "" && !explicit["output"] && !explicit["o"] {
		f.output = cfg.Output
	}
	if cfg.Hostlist != "" && !explicit["hostlist"] {
		f.hostlist = cfg.Hostlist
	}
	if cfg.Ignorelist != "" && !explicit["ignorelist"] {
		f.ignorelist = cfg.Ignorelist
	}
	// These have no CLI flag, so they come straight from the config file.
	f.ipv4SkipRanges = cfg.Detectors.IPv4.SkipRanges
	f.allowlistCaseInsensitive = cfg.Detectors.Allowlist.CaseInsensitive
	f.extraInternalTLDs = cfg.Detectors.FQDN.ExtraInternalTLDs
	if cfg.Detectors.IPv4.IPClass && !explicit["ip-class"] {
		f.ipClass = true
	}
	if cfg.Detectors.URL.Mode != "" && !explicit["url-mode"] {
		f.urlMode = cfg.Detectors.URL.Mode
	}
	if len(cfg.Profiles) > 0 && !explicit["profiles"] {
		f.profiles = strings.Join(cfg.Profiles, ",")
	}
	if cfg.Audit != nil && !explicit["audit"] {
		f.audit = *cfg.Audit
	}
	if cfg.Strict && !explicit["strict"] {
		f.strict = true
	}
	if cfg.Verbose && !explicit["verbose"] && !explicit["v"] {
		f.verbose = true
	}
	return exitOK
}

func runSanitize(f *flags, positional []string, stdout, stderr io.Writer) int {
	input := f.input
	if input == "" && len(positional) > 0 {
		input = positional[0]
	}

	opts := sanitize.Options{
		InputDir:                 input,
		OutputDir:                f.output,
		MappingPath:              f.mapping,
		AllowMappingInOutput:     f.allowMappingInOutput,
		URLMode:                  f.urlMode,
		KeepHARBodies:            f.keepHARBodies,
		Workers:                  f.workers,
		MaxExtractBytes:          int64(f.maxExtractMB) << 20,
		IPClass:                  f.ipClass,
		HostlistPath:             f.hostlist,
		IgnorelistPath:           f.ignorelist,
		IPv4SkipRanges:           f.ipv4SkipRanges,
		AllowlistCaseInsensitive: f.allowlistCaseInsensitive,
		ExtraInternalTLDs:        f.extraInternalTLDs,
		Profiles:                 splitProfiles(f.profiles),
		AuditEnabled:             f.audit,
		Strict:                   f.strict,
		DryRun:                   f.dryRun,
		Verbose:                  f.verbose,
		ToolVersion:              version,
	}

	if !f.quiet {
		opts.Progress = stderr
	}
	result, err := sanitize.Sanitize(opts)
	if err != nil {
		return reportError(err, stderr)
	}
	for _, w := range result.HostlistWarnings {
		fmt.Fprintf(stderr, "sas-log-sanitize: hostlist: %s\n", w)
	}

	if !f.quiet {
		fmt.Fprintf(stdout, "Processed %d files (%d skipped), %d bytes\n", result.FilesProcessed, len(result.FilesSkipped), result.BytesProcessed)
		if len(result.FilesSkipped) > 0 {
			fmt.Fprintln(stdout, "Skipped files:")
			for _, s := range result.FilesSkipped {
				fmt.Fprintf(stdout, "  %s: %s\n", s.RelPath, s.Reason)
			}
		}
		if !f.dryRun {
			fmt.Fprintf(stdout, "Output: %s\n", result.OutputDir)
			fmt.Fprintf(stdout, "Mapping: %s\n", result.MappingPath)
		}
		if len(result.AuditFindings) > 0 {
			fmt.Fprintf(stdout, "Audit: %d findings (see %s/_audit.txt)\n", len(result.AuditFindings), result.OutputDir)
		}
	}

	code := result.ExitStatus()
	reportExitReason(code, result.AuditFindings, f.strict, stderr)
	return code
}

func runReverse(f *flags, positional []string, stdout, stderr io.Writer) int {
	mappingPath := f.mapping
	args := positional
	if mappingPath == "" && len(args) > 0 {
		mappingPath = args[0]
		args = args[1:]
	}
	if mappingPath == "" || len(args) == 0 {
		fmt.Fprintln(stderr, "sas-log-sanitize --reverse: usage: --reverse <mapping-file> <text-or-file>")
		return exitConfigError
	}

	text := args[0]
	if data, err := os.ReadFile(args[0]); err == nil {
		text = string(data)
	}

	out, err := sanitize.Reverse(mappingPath, text)
	if err != nil {
		return reportError(err, stderr)
	}
	fmt.Fprintln(stdout, out)
	return exitOK
}

func runAuditOnly(f *flags, positional []string, stdout, stderr io.Writer) int {
	dir := f.input
	if dir == "" && len(positional) > 0 {
		dir = positional[0]
	}
	if dir == "" {
		fmt.Fprintln(stderr, "sas-log-sanitize --audit-only: usage: --audit-only <sanitized-dir> [--mapping <mapping-file>]")
		return exitConfigError
	}

	findings, err := sanitize.AuditDirectory(dir, f.ignorelist, f.ipv4SkipRanges, f.mapping)
	if err != nil {
		return reportError(err, stderr)
	}

	fmt.Fprint(stdout, audit.Report(findings))
	code := sanitize.ExitStatusFor(findings, f.strict)
	reportExitReason(code, findings, f.strict, stderr)
	return code
}

// reportExitReason explains a non-zero findings exit on stderr.
func reportExitReason(code int, findings []audit.Finding, strict bool, stderr io.Writer) {
	if code == exitOK {
		return
	}
	if audit.HasHigh(findings) {
		fmt.Fprintln(stderr, "sas-log-sanitize: High-severity audit findings present")
	} else if strict {
		fmt.Fprintln(stderr, "sas-log-sanitize: --strict mode: audit findings present")
	}
}

func reportError(err error, stderr io.Writer) int {
	fmt.Fprintf(stderr, "sas-log-sanitize: %v\n", err)
	var sanitizeErr *sanitize.Error
	if errors.As(err, &sanitizeErr) {
		switch sanitizeErr.Kind {
		case sanitize.KindInput:
			return exitInputError
		case sanitize.KindConfig:
			return exitConfigError
		default:
			return exitProcessingError
		}
	}
	return exitProcessingError
}

func splitProfiles(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

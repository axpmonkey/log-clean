package sanitize

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"sas-log-sanitize/internal/pipeline"
)

// Options configures a sanitization run.
type Options struct {
	// InputDir is the directory containing the support log bundle. Required.
	InputDir string
	// OutputDir is where sanitized output, the mapping file, audit report,
	// summary, and runlog are written. Defaults to "<InputDir>-sanitized" if
	// empty (set by DefaultOptions/Validate).
	OutputDir string
	// MappingPath overrides the mapping file location. Defaults to
	// "<OutputDir>.mapping.json" -- a sibling of the output directory, never
	// inside it, so zipping and attaching the sanitized folder can't ship the
	// mapping with it. A path inside OutputDir is refused unless
	// AllowMappingInOutput is set.
	MappingPath string
	// URLMode is "host" (default; tokenize only a URL's userinfo and host,
	// keeping scheme, port, path and parameter names) or "whole" (one
	// URL_NNN token per URL, the old behavior). --url-mode.
	URLMode string
	// KeepHARBodies keeps HAR response bodies (content.text), scanned like
	// any other value, instead of dropping them (--keep-har-bodies).
	KeepHARBodies bool
	// Workers is how many files are processed in parallel in each pass;
	// 0 means one per CPU (--workers).
	Workers int
	// Progress, if set, receives progress lines (files, MB, MB/s, ETA).
	Progress io.Writer
	// MaxExtractBytes caps the total bytes extracted from .zip/.tar archives
	// in one run, a guard against decompression bombs (0 = 20 GiB).
	MaxExtractBytes int64
	// IPClass tokenizes IPv4 addresses as IPV4_PRIV_NNN (private,
	// loopback, link-local, CGNAT) or IPV4_PUB_NNN instead of IPV4_NNN
	// (--ip-class).
	IPClass bool
	// AllowMappingInOutput permits MappingPath to resolve inside OutputDir
	// (--allow-mapping-in-output).
	AllowMappingInOutput bool
	// HostlistPath, if set, points to a customer hostname allowlist file
	// (see detect.LoadAllowlist for format).
	HostlistPath string
	// IgnorelistPath, if set, points to a file of hostnames/domains that
	// should never be tokenized or redacted, even if a detector would
	// otherwise match them (e.g. "*.sas.com" for a noisy but non-sensitive
	// vendor domain). See detect.LoadIgnoreList for format. This is the
	// inverse of HostlistPath, which forces tokenization.
	IgnorelistPath string
	// IPv4SkipRanges are CIDR blocks (e.g. "10.0.0.0/8") whose addresses are
	// left untokenized, from the config's detectors.ipv4.skip_ranges. Invalid
	// CIDRs are a config error.
	IPv4SkipRanges []string
	// AllowlistCaseInsensitive makes the hostname allowlist (HostlistPath)
	// match regardless of case, from detectors.allowlist.case_insensitive.
	AllowlistCaseInsensitive bool
	// ExtraInternalTLDs are additional pseudo-TLDs to treat as valid hosts,
	// from detectors.fqdn.extra_internal_tlds. They are unioned with the
	// extras contributed by the active Profiles.
	ExtraInternalTLDs []string
	// Profiles selects which built-in profiles' extra_internal_tlds get
	// merged into the FQDN detector. ["auto"] (the default) merges every
	// built-in profile's extras for the whole run -- per-file profile
	// auto-detection exists (internal/profile) but per-file detector
	// chains are not wired up; see doc.go for the scope note.
	Profiles []string
	// AuditEnabled runs the audit pass after sanitization and writes
	// _audit.txt. The CLI's --audit flag defaults to true (set explicitly
	// in cmd/sanitize/main.go's flag definition) -- this struct's own zero
	// value is false, like any bool, since "defaults to true" can't be
	// expressed by silently flipping an unset bool without also making it
	// impossible for a caller to explicitly request false.
	AuditEnabled bool
	// Strict causes Sanitize to report a high-severity-findings condition
	// the CLI maps to exit code 1 with a clear stderr message.
	Strict bool
	// DryRun computes everything but writes nothing to OutputDir.
	DryRun bool
	// Verbose enables per-file DEBUG-level runlog output.
	Verbose bool
	// ToolVersion is recorded in the mapping file and runlog.
	ToolVersion string
}

// DefaultOptions returns Options with the plan's documented CLI defaults
// applied for the given input directory.
func DefaultOptions(inputDir string) Options {
	return Options{
		InputDir:     inputDir,
		OutputDir:    inputDir + "-sanitized",
		Profiles:     []string{"auto"},
		AuditEnabled: true,
		ToolVersion:  "dev",
	}
}

// applyDefaults fills in any zero-valued fields that have a documented
// default, without overriding values the caller explicitly set.
func (o Options) applyDefaults() Options {
	if o.OutputDir == "" {
		o.OutputDir = o.InputDir + "-sanitized"
	}
	if o.MappingPath == "" {
		o.MappingPath = DefaultMappingPath(o.OutputDir)
	}
	if len(o.Profiles) == 0 {
		o.Profiles = []string{"auto"}
	}
	if o.URLMode == "" {
		o.URLMode = pipeline.URLModeHost
	}
	if o.ToolVersion == "" {
		o.ToolVersion = "dev"
	}
	return o
}

// Validate checks for required fields and inconsistent flag combinations,
// returning a config-kind Error (CLI exit code 4) on failure.
func (o Options) Validate() error {
	if o.InputDir == "" {
		return configErrorf("input directory is required")
	}
	if o.URLMode != "" && o.URLMode != pipeline.URLModeHost && o.URLMode != pipeline.URLModeWhole {
		return configErrorf("invalid url mode %q (want %q or %q)", o.URLMode, pipeline.URLModeHost, pipeline.URLModeWhole)
	}
	return nil
}

// DefaultMappingPath is the mapping file location for an output directory
// when none is given: "<outputDir>.mapping.json", next to the directory
// rather than inside it.
func DefaultMappingPath(outputDir string) string {
	return filepath.Clean(outputDir) + ".mapping.json"
}

// checkMappingLocation refuses a mapping path that resolves inside the
// output directory (config error, CLI exit 4) unless explicitly allowed.
// Both paths are made absolute and symlink-resolved first, so "out/../out/m"
// or a symlinked parent can't slip past the check.
func (o Options) checkMappingLocation() error {
	if o.AllowMappingInOutput {
		return nil
	}
	inside, err := pathInside(o.MappingPath, o.OutputDir)
	if err != nil {
		return configErrorf("checking mapping path %s: %w", o.MappingPath, err)
	}
	if inside {
		return configErrorf("mapping file %s is inside the output directory %s, which is the folder that gets shared; "+
			"write it elsewhere (default: %s) or pass --allow-mapping-in-output",
			o.MappingPath, o.OutputDir, DefaultMappingPath(o.OutputDir))
	}
	return nil
}

// pathInside reports whether path is dir itself or anywhere beneath it.
func pathInside(path, dir string) (bool, error) {
	p, err := resolvePath(path)
	if err != nil {
		return false, err
	}
	d, err := resolvePath(dir)
	if err != nil {
		return false, err
	}
	rel, err := filepath.Rel(d, p)
	if err != nil {
		return false, nil // different volumes: not inside
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))), nil
}

// resolvePath returns an absolute, cleaned path with symlinks resolved in
// its longest existing prefix (the rest may not exist yet).
func resolvePath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	existing, rest := abs, ""
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return abs, nil
		}
		rest = filepath.Join(filepath.Base(existing), rest)
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, rest), nil
}

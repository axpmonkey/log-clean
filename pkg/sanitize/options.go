package sanitize

// Options configures a sanitization run.
type Options struct {
	// InputDir is the directory containing the support log bundle. Required.
	InputDir string
	// OutputDir is where sanitized output, the mapping file, audit report,
	// summary, and runlog are written. Defaults to "<InputDir>-sanitized" if
	// empty (set by DefaultOptions/Validate).
	OutputDir string
	// MappingPath overrides the mapping file location. Defaults to
	// "<OutputDir>/_mapping.json".
	MappingPath string
	// HostlistPath, if set, points to a customer hostname allowlist file
	// (see detect.LoadAllowlist for format).
	HostlistPath string
	// IgnorelistPath, if set, points to a file of hostnames/domains that
	// should never be tokenized or redacted, even if a detector would
	// otherwise match them (e.g. "*.sas.com" for a noisy but non-sensitive
	// vendor domain). See detect.LoadIgnoreList for format. This is the
	// inverse of HostlistPath, which forces tokenization.
	IgnorelistPath string
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
		o.MappingPath = o.OutputDir + "/_mapping.json"
	}
	if len(o.Profiles) == 0 {
		o.Profiles = []string{"auto"}
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
	return nil
}

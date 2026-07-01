package profile

import "gopkg.in/yaml.v3"

// Config is the optional --config YAML file format, per the plan's
// configuration file spec. In the "detectors" advanced overrides section,
// ipv4.skip_ranges and allowlist.case_insensitive are wired into detector
// behavior (see pkg/sanitize.Sanitize). fqdn.extra_internal_tlds is parsed
// but not yet consumed from the config file -- extra FQDN TLDs currently
// come only from the built-in profiles' extra_internal_tlds. See
// pkg/sanitize/doc.go's scope note.
type Config struct {
	Output     string   `yaml:"output"`
	Hostlist   string   `yaml:"hostlist"`
	Ignorelist string   `yaml:"ignorelist"`
	Profiles   []string `yaml:"profiles"`
	Audit      *bool    `yaml:"audit"`
	Strict     bool     `yaml:"strict"`
	Verbose    bool     `yaml:"verbose"`
	Detectors  struct {
		FQDN struct {
			ExtraInternalTLDs []string `yaml:"extra_internal_tlds"`
		} `yaml:"fqdn"`
		IPv4 struct {
			SkipRanges []string `yaml:"skip_ranges"`
		} `yaml:"ipv4"`
		Allowlist struct {
			CaseInsensitive bool `yaml:"case_insensitive"`
		} `yaml:"allowlist"`
	} `yaml:"detectors"`
}

// ParseConfig parses a --config YAML file's contents.
func ParseConfig(data []byte) (Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return Config{}, err
	}
	return c, nil
}

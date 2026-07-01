// Package profile loads per-log-format profiles (filename/first-line
// heuristics plus light detector tuning hooks) and picks the best-matching
// one for a given file.
//
// Scope note: most detection logic in this tool is format-agnostic -- the
// same detector chain runs regardless of which profile is active. A
// profile's main jobs are (1) auto-detection, so the runlog/summary can
// label which format a file looked like, and (2) the one additive detector
// override actually wired through so far: ExtraInternalTLDs, merged into the
// FQDN detector's TLD allowlist (see detect.NewFQDNDetectorWithExtraTLDs).
// The plan's example config also shows ipv4.skip_ranges and
// allowlist.case_insensitive overrides; those are not implemented yet --
// flagging that explicitly rather than silently no-op-ing them.
package profile

import (
	"embed"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Profile describes how to recognize a specific log format.
type Profile struct {
	Name string `yaml:"name"`
	// FilenamePatterns are substrings matched case-insensitively against a
	// file's base name for auto-detection (e.g. "catalina" for Tomcat).
	FilenamePatterns []string `yaml:"filename_patterns"`
	// FirstLinePattern, if non-empty, is a regular expression checked
	// against a file's first line for auto-detection.
	FirstLinePattern string `yaml:"first_line_pattern"`
	// ExtraInternalTLDs are appended to the FQDN detector's TLD allowlist
	// when this profile is active.
	ExtraInternalTLDs []string `yaml:"extra_internal_tlds"`

	firstLineRe *regexp.Regexp // compiled by compile(), nil if FirstLinePattern is empty
}

func (p *Profile) compile() error {
	if p.FirstLinePattern == "" {
		return nil
	}
	re, err := regexp.Compile(p.FirstLinePattern)
	if err != nil {
		return fmt.Errorf("profile %q: invalid first_line_pattern: %w", p.Name, err)
	}
	p.firstLineRe = re
	return nil
}

// Matches reports whether this profile's filename or first-line heuristic
// fits the given file. firstLine may be empty (e.g. an empty file), in
// which case only the filename heuristic is checked.
func (p *Profile) Matches(filename, firstLine string) bool {
	base := strings.ToLower(filepath.Base(filename))
	for _, pat := range p.FilenamePatterns {
		if strings.Contains(base, strings.ToLower(pat)) {
			return true
		}
	}
	return p.firstLineRe != nil && p.firstLineRe.MatchString(firstLine)
}

// LoadBuiltin parses every embedded builtin/*.yaml profile, sorted by
// filename (deterministic order; "default.yaml" sorts first).
func LoadBuiltin() ([]Profile, error) {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil, fmt.Errorf("reading builtin profiles: %w", err)
	}
	var profiles []Profile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("reading builtin profile %s: %w", e.Name(), err)
		}
		var p Profile
		if err := yaml.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("parsing builtin profile %s: %w", e.Name(), err)
		}
		if err := p.compile(); err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}

// Detect picks the best-matching profile for a file from candidates. Falls
// back to the profile named "default" (or the first candidate, if there is
// no "default") when nothing matches.
func Detect(candidates []Profile, filename, firstLine string) Profile {
	var fallback Profile
	haveFallback := false
	for _, p := range candidates {
		if p.Name == "default" {
			fallback = p
			haveFallback = true
		}
		if p.Matches(filename, firstLine) {
			return p
		}
	}
	if haveFallback {
		return fallback
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return Profile{Name: "default"}
}

// ByName returns the profile with the given name from candidates.
func ByName(candidates []Profile, name string) (Profile, bool) {
	for _, p := range candidates {
		if p.Name == name {
			return p, true
		}
	}
	return Profile{}, false
}

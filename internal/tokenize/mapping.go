package tokenize

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// MappingSchemaVersion is the current mapping file schema version, written
// to every mapping file so future tool versions can detect and migrate
// older formats.
const MappingSchemaVersion = 1

// Stats summarizes a sanitization run for the mapping file's "stats" field.
type Stats struct {
	FilesProcessed         int            `json:"files_processed"`
	BytesProcessed         int64          `json:"bytes_processed"`
	ReplacementsByCategory map[string]int `json:"replacements_by_category"`
}

// MappingFile is the on-disk JSON format for the reverse mapping, per the
// plan's mapping file format spec. It is the single most sensitive artifact
// the tool produces -- WriteMappingFile writes it with owner-only
// permissions, and it must never contain a password, key, token, or other
// secret (plan Decision 5: those are only ever redacted, never recorded).
type MappingFile struct {
	SchemaVersion int                          `json:"schema_version"`
	GeneratedAt   time.Time                    `json:"generated_at"`
	ToolVersion   string                       `json:"tool_version"`
	InputDir      string                       `json:"input_dir"`
	Categories    map[string]map[string]string `json:"categories"`
	Stats         Stats                        `json:"stats"`
}

// ToMappingFile builds a MappingFile from the registry's current state.
func (r *Registry) ToMappingFile(toolVersion, inputDir string, stats Stats) MappingFile {
	return MappingFile{
		SchemaVersion: MappingSchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		ToolVersion:   toolVersion,
		InputDir:      inputDir,
		Categories:    r.Mapping(),
		Stats:         stats,
	}
}

// WriteMappingFile writes mf to path as indented JSON with owner-only
// (0600) permissions -- the mapping file contains real internal hostnames,
// IPs, and usernames, and is the most sensitive artifact this tool produces.
func WriteMappingFile(path string, mf MappingFile) error {
	data, err := json.MarshalIndent(mf, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding mapping file: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing mapping file %s: %w", path, err)
	}
	return nil
}

// LoadMappingFile reads and parses a mapping file previously written by
// WriteMappingFile, for use in reverse mode.
func LoadMappingFile(path string) (MappingFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return MappingFile{}, fmt.Errorf("reading mapping file %s: %w", path, err)
	}
	var mf MappingFile
	if err := json.Unmarshal(data, &mf); err != nil {
		return MappingFile{}, fmt.Errorf("parsing mapping file %s: %w", path, err)
	}
	return mf, nil
}

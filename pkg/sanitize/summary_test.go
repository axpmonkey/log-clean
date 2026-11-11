package sanitize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// P1.6: _summary.json lets other tools (sas-casefile build) read a run's
// result without parsing text.
func TestSummaryJSON(t *testing.T) {
	in := t.TempDir()
	writeTestFile(t, in, "app.log", "user=jdoe on db01.corp.example.com\nconnecting to sasapp01 now\n")
	writeTestFile(t, in, "heap.hprof", "\x00\x01")
	out := filepath.Join(t.TempDir(), "out")
	result, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(out, "_summary.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		SchemaVersion          int            `json:"schema_version"`
		ToolVersion            string         `json:"tool_version"`
		FilesProcessed         int            `json:"files_processed"`
		BytesProcessed         int64          `json:"bytes_processed"`
		ReplacementsByCategory map[string]int `json:"replacements_by_category"`
		UniqueValuesByCategory map[string]int `json:"unique_values_by_category"`
		SkippedFiles           []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"skipped_files"`
		Audit struct {
			Enabled bool `json:"enabled"`
			High    int  `json:"high"`
			Medium  int  `json:"medium"`
		} `json:"audit"`
		ExitStatus int `json:"exit_status"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("_summary.json is not valid JSON: %v\n%s", err, data)
	}
	if s.SchemaVersion != 1 || s.ToolVersion != "test" || s.FilesProcessed != 1 || s.BytesProcessed == 0 {
		t.Errorf("header fields wrong: %s", data)
	}
	if s.ReplacementsByCategory["USER"] != 1 || s.UniqueValuesByCategory["HOST"] != 1 {
		t.Errorf("category counts wrong: %s", data)
	}
	if len(s.SkippedFiles) != 1 || s.SkippedFiles[0].Path != "heap.hprof" || s.SkippedFiles[0].Reason == "" {
		t.Errorf("skipped_files wrong: %s", data)
	}
	if !s.Audit.Enabled || s.Audit.Medium == 0 || s.Audit.High != 0 {
		t.Errorf("audit counts wrong: %s", data)
	}
	// Medium findings only: exit 0 unless --strict.
	if s.ExitStatus != 0 || s.ExitStatus != result.ExitStatus() {
		t.Errorf("exit_status = %d, Result.ExitStatus() = %d, want 0 (Medium only, not strict)", s.ExitStatus, result.ExitStatus())
	}
	if strings.Contains(string(data), "jdoe") || strings.Contains(string(data), "db01") {
		t.Errorf("_summary.json contains an original value: %s", data)
	}
	if !ownArtifactNames["_summary.json"] {
		t.Errorf("--audit-only would scan _summary.json")
	}
}

// --strict makes Medium-only findings exit 1 too.
func TestSummaryJSONStrictExitStatus(t *testing.T) {
	in := t.TempDir()
	writeTestFile(t, in, "app.log", "connecting to sasapp01 now\n")
	out := filepath.Join(t.TempDir(), "out")
	result, err := Sanitize(Options{InputDir: in, OutputDir: out, AuditEnabled: true, Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitStatus() != 1 {
		t.Errorf("strict, Medium findings: ExitStatus() = %d, want 1", result.ExitStatus())
	}
	data, _ := os.ReadFile(filepath.Join(out, "_summary.json"))
	if !strings.Contains(string(data), `"exit_status": 1`) {
		t.Errorf("_summary.json exit_status not 1:\n%s", data)
	}
}

package tokenize

import (
	"os"
	"path/filepath"
	"testing"
)

func TestToMappingFileReflectsRegistry(t *testing.T) {
	r := NewRegistry()
	r.TokenFor("HOST", "db-prod-01.acme.internal")
	r.TokenFor("USER", "jdoe")

	mf := r.ToMappingFile("0.1.0-dev", "/path/to/bundle", Stats{FilesProcessed: 2, BytesProcessed: 1024})

	if mf.SchemaVersion != MappingSchemaVersion {
		t.Errorf("SchemaVersion = %d, want %d", mf.SchemaVersion, MappingSchemaVersion)
	}
	if mf.ToolVersion != "0.1.0-dev" || mf.InputDir != "/path/to/bundle" {
		t.Errorf("mf = %+v", mf)
	}
	if mf.Categories["HOST"]["HOST_001"] != "db-prod-01.acme.internal" {
		t.Errorf("HOST_001 = %q", mf.Categories["HOST"]["HOST_001"])
	}
	if mf.Stats.FilesProcessed != 2 {
		t.Errorf("FilesProcessed = %d, want 2", mf.Stats.FilesProcessed)
	}
	if mf.GeneratedAt.IsZero() {
		t.Error("GeneratedAt not set")
	}
}

func TestWriteAndLoadMappingFileRoundTrip(t *testing.T) {
	r := NewRegistry()
	r.TokenFor("HOST", "db-prod-01.acme.internal")
	r.TokenFor("USER", "jdoe")
	mf := r.ToMappingFile("0.1.0-dev", "/bundle", Stats{FilesProcessed: 1})

	dir := t.TempDir()
	path := filepath.Join(dir, "_mapping.json")
	if err := WriteMappingFile(path, mf); err != nil {
		t.Fatalf("WriteMappingFile: %v", err)
	}

	loaded, err := LoadMappingFile(path)
	if err != nil {
		t.Fatalf("LoadMappingFile: %v", err)
	}
	if loaded.Categories["HOST"]["HOST_001"] != "db-prod-01.acme.internal" {
		t.Errorf("loaded HOST_001 = %q", loaded.Categories["HOST"]["HOST_001"])
	}
	if loaded.Categories["USER"]["USER_001"] != "jdoe" {
		t.Errorf("loaded USER_001 = %q", loaded.Categories["USER"]["USER_001"])
	}
	if loaded.ToolVersion != "0.1.0-dev" {
		t.Errorf("loaded ToolVersion = %q", loaded.ToolVersion)
	}
}

func TestWriteMappingFileUsesOwnerOnlyPermissions(t *testing.T) {
	r := NewRegistry()
	mf := r.ToMappingFile("0.1.0-dev", "/bundle", Stats{})

	dir := t.TempDir()
	path := filepath.Join(dir, "_mapping.json")
	if err := WriteMappingFile(path, mf); err != nil {
		t.Fatalf("WriteMappingFile: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mapping file permissions = %o, want 0600", perm)
	}
}

func TestLoadMappingFileMissingFile(t *testing.T) {
	_, err := LoadMappingFile(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Error("expected an error loading a nonexistent mapping file")
	}
}

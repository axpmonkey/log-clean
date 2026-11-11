package archive

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeZip(t *testing.T, entries map[string]string) string {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for name, data := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(data))
	}
	zw.Close()
	p := filepath.Join(t.TempDir(), "x.zip")
	os.WriteFile(p, b.Bytes(), 0o644)
	return p
}

func TestKindOfAndTrimExt(t *testing.T) {
	cases := map[string]Kind{"a.log.gz": Gzip, "b.ZIP": Zip, "c.tar": Tar, "d.tar.gz": TarGz, "e.tgz": TarGz, "f.log": None, "g.jar": None}
	for name, want := range cases {
		if got := KindOf(name); got != want {
			t.Errorf("KindOf(%q) = %v, want %v", name, got, want)
		}
	}
	for in, want := range map[string]string{"bundle.zip": "bundle", "logs.tar.gz": "logs", "x.tgz": "x", "plain.log": "plain.log"} {
		if got := TrimExt(in); got != want {
			t.Errorf("TrimExt(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractRefusesUnsafeNames(t *testing.T) {
	src := writeZip(t, map[string]string{
		"ok/a.log":       "fine",
		`..\win.log`:     "x",
		`sub\..\..\up`:   "x",
		"C:/drive.log":   "x",
		"/abs.log":       "x",
		"inner/deep.tgz": "x",
	})
	root := t.TempDir()
	dest := filepath.Join(root, "dest")
	os.Mkdir(dest, 0o700)
	skipped, err := Extract(src, Zip, dest, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(filepath.Join(dest, "ok", "a.log")); err != nil || string(data) != "fine" {
		t.Errorf("safe entry not extracted: %q %v", data, err)
	}
	if len(skipped) != 5 {
		t.Errorf("skipped %d entries, want 5: %+v", len(skipped), skipped)
	}
	var written []string
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			written = append(written, p)
		}
		return nil
	})
	if len(written) != 1 {
		t.Errorf("files written: %v, want only ok/a.log", written)
	}
}

func TestExtractEnforcesSizeCap(t *testing.T) {
	src := writeZip(t, map[string]string{"big.log": string(bytes.Repeat([]byte("a"), 1000))})
	dest := t.TempDir()
	if _, err := Extract(src, Zip, dest, 999); err != ErrTooLarge {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
	if _, err := Extract(src, Zip, t.TempDir(), 1000); err != nil {
		t.Errorf("exactly at the cap: %v", err)
	}
}

package io

import "testing"

func TestIsSkippedExtension(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"heap.hprof", true},
		{"trace.jfr", true},
		{"screenshot.png", true},
		{"archive.tar", true},
		{"lib.so", true},
		{"app.dll", true},
		{"core", true},
		{"core.12345", true},
		{"server.log", false},
		{"sas.log", false},
		{"catalina.out", false},
	}
	for _, c := range cases {
		if got := IsSkippedExtension(c.path); got != c.want {
			t.Errorf("IsSkippedExtension(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

func TestIsBinary(t *testing.T) {
	textLine := []byte("2026-06-30 12:00:00.123 INFO Connected to db-prod-01\n")
	if IsBinary(textLine) {
		t.Error("plain text line classified as binary")
	}

	binary := make([]byte, 512)
	for i := range binary {
		if i%2 == 0 {
			binary[i] = 0x00 // NUL bytes, common in genuinely binary content
		} else {
			binary[i] = 'a'
		}
	}
	if !IsBinary(binary) {
		t.Error("dense binary content not classified as binary")
	}

	if IsBinary(nil) {
		t.Error("empty input classified as binary")
	}
}

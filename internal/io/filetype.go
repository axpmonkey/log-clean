package io

import (
	"path/filepath"
	"strings"
)

// binaryExtensions are skipped without even sniffing content, per Decision 9.
var binaryExtensions = map[string]bool{
	".hprof": true, ".jfr": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
	".zip": true, ".gz": true, ".tar": true,
	".jar": true, ".war": true, ".ear": true, ".class": true,
	".so": true, ".dll": true, ".exe": true,
}

// IsSkippedExtension reports whether path's extension (or, for extensionless
// "core" / "core.<pid>" dump files, its base name) marks it as binary.
func IsSkippedExtension(path string) bool {
	base := filepath.Base(path)
	if base == "core" || strings.HasPrefix(base, "core.") {
		return true
	}
	ext := strings.ToLower(filepath.Ext(path))
	return binaryExtensions[ext]
}

// sniffWindow is the number of leading bytes inspected to decide binary-ness.
const sniffWindow = 512

// IsBinary reports whether the leading bytes of a file look binary: more than
// 30% non-printable bytes in the first 512-byte window, per Decision 9.
// "Printable" includes common whitespace (tab, LF, CR) plus the printable
// ASCII range and any byte >= 0x20, since UTF-8/UTF-16/Windows-1252 text all
// use those high bytes for legitimate characters.
func IsBinary(b []byte) bool {
	if len(b) > sniffWindow {
		b = b[:sniffWindow]
	}
	if len(b) == 0 {
		return false
	}
	nonPrintable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' {
			continue
		}
		if c < 0x20 {
			nonPrintable++
		}
	}
	return float64(nonPrintable)/float64(len(b)) > 0.30
}

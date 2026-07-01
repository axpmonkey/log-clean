// Package io provides encoding detection and large-buffer line I/O for SAS log
// bundles, which may arrive as UTF-8, UTF-16 (Windows tooling), or legacy
// Windows-1252 text, with either CRLF or LF line endings.
package io

import (
	"encoding/binary"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"
)

// Encoding identifies the byte-level text encoding of a source file.
type Encoding int

const (
	UTF8 Encoding = iota
	UTF16LE
	UTF16BE
	Windows1252
)

func (e Encoding) String() string {
	switch e {
	case UTF8:
		return "UTF-8"
	case UTF16LE:
		return "UTF-16LE"
	case UTF16BE:
		return "UTF-16BE"
	case Windows1252:
		return "Windows-1252"
	default:
		return "unknown"
	}
}

// DetectBOM inspects the leading bytes of a file and returns the encoding implied
// by a byte-order mark, plus the number of BOM bytes to skip. If no BOM is
// present it returns UTF8 with 0 bytes to skip; the caller should then fall back
// to DetectNoBOM to decide between UTF-8 and Windows-1252.
func DetectBOM(b []byte) (enc Encoding, skip int) {
	switch {
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return UTF8, 3
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return UTF16LE, 2
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return UTF16BE, 2
	default:
		return UTF8, 0
	}
}

// DetectNoBOM decides between UTF-8 and Windows-1252 for a file with no BOM, per
// Decision 8: assume UTF-8, fall back to Windows-1252 only if the bytes are not
// valid UTF-8.
func DetectNoBOM(b []byte) Encoding {
	if utf8.Valid(b) {
		return UTF8
	}
	return Windows1252
}

// DecodeUTF16 converts raw UTF-16 bytes (no BOM) to a UTF-8 string.
func DecodeUTF16(b []byte, big bool) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("decoding UTF-16: odd byte length %d", len(b))
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		if big {
			units[i] = binary.BigEndian.Uint16(b[i*2:])
		} else {
			units[i] = binary.LittleEndian.Uint16(b[i*2:])
		}
	}
	return string(utf16.Decode(units)), nil
}

// EncodeUTF16 converts a UTF-8 string to raw UTF-16 bytes (no BOM) in the given byte order.
func EncodeUTF16(s string, big bool) []byte {
	units := utf16.Encode([]rune(s))
	out := make([]byte, len(units)*2)
	for i, u := range units {
		if big {
			binary.BigEndian.PutUint16(out[i*2:], u)
		} else {
			binary.LittleEndian.PutUint16(out[i*2:], u)
		}
	}
	return out
}

// windows1252High maps bytes 0x80-0x9F to their Windows-1252 code points. Bytes
// 0xA0-0xFF are identical to Unicode code points U+00A0-U+00FF (same as Latin-1),
// but 0x80-0x9F diverge from the ISO-8859-1 control-code range and must be
// looked up explicitly.
var windows1252High = [32]rune{
	0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
	0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
	0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
	0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

// DecodeWindows1252 converts Windows-1252 bytes to a UTF-8 string.
func DecodeWindows1252(b []byte) string {
	runes := make([]rune, len(b))
	for i, c := range b {
		if c >= 0x80 && c <= 0x9F {
			runes[i] = windows1252High[c-0x80]
		} else {
			runes[i] = rune(c)
		}
	}
	return string(runes)
}

// EncodeWindows1252 converts a UTF-8 string back to Windows-1252 bytes. Runes
// with no Windows-1252 representation are replaced with '?'.
func EncodeWindows1252(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r < 0x80 || (r >= 0xA0 && r <= 0xFF) {
			out = append(out, byte(r))
			continue
		}
		found := false
		for i, hr := range windows1252High {
			if hr == r {
				out = append(out, byte(0x80+i))
				found = true
				break
			}
		}
		if !found {
			out = append(out, '?')
		}
	}
	return out
}

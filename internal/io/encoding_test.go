package io

import "testing"

func TestDetectBOM(t *testing.T) {
	cases := []struct {
		name     string
		input    []byte
		wantEnc  Encoding
		wantSkip int
	}{
		{"utf8 bom", []byte{0xEF, 0xBB, 0xBF, 'h', 'i'}, UTF8, 3},
		{"utf16le bom", []byte{0xFF, 0xFE, 'h', 0x00}, UTF16LE, 2},
		{"utf16be bom", []byte{0xFE, 0xFF, 0x00, 'h'}, UTF16BE, 2},
		{"no bom plain ascii", []byte("plain text"), UTF8, 0},
		{"empty", []byte{}, UTF8, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc, skip := DetectBOM(c.input)
			if enc != c.wantEnc || skip != c.wantSkip {
				t.Errorf("DetectBOM(%v) = (%v, %d), want (%v, %d)", c.input, enc, skip, c.wantEnc, c.wantSkip)
			}
		})
	}
}

func TestDetectNoBOM(t *testing.T) {
	if got := DetectNoBOM([]byte("hello world")); got != UTF8 {
		t.Errorf("valid UTF-8 -> %v, want UTF8", got)
	}
	invalid := []byte{0xFF, 0xFE, 0xFD, 0x80, 0x81}
	if got := DetectNoBOM(invalid); got != Windows1252 {
		t.Errorf("invalid UTF-8 -> %v, want Windows1252", got)
	}
}

func TestUTF16RoundTrip(t *testing.T) {
	original := "Connected to db-prod-01.acme.internal as jdoe"
	for _, big := range []bool{false, true} {
		encoded := EncodeUTF16(original, big)
		decoded, err := DecodeUTF16(encoded, big)
		if err != nil {
			t.Fatalf("DecodeUTF16 error: %v", err)
		}
		if decoded != original {
			t.Errorf("round trip (big=%v) = %q, want %q", big, decoded, original)
		}
	}
}

func TestDecodeUTF16OddLength(t *testing.T) {
	if _, err := DecodeUTF16([]byte{0x00}, false); err == nil {
		t.Error("expected error for odd-length UTF-16 input, got nil")
	}
}

func TestWindows1252RoundTrip(t *testing.T) {
	// 0x80 is the Euro sign in Windows-1252, distinct from ISO-8859-1's control code.
	raw := []byte{'p', 'r', 'i', 'c', 'e', ':', ' ', 0x80, '5', '0'}
	decoded := DecodeWindows1252(raw)
	if decoded != "price: €50" {
		t.Errorf("DecodeWindows1252 = %q, want price: €50", decoded)
	}
	reEncoded := EncodeWindows1252(decoded)
	if string(reEncoded) != string(raw) {
		t.Errorf("EncodeWindows1252 round trip = %v, want %v", reEncoded, raw)
	}
}

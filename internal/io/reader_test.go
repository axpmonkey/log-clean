package io

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func readAllLines(t *testing.T, lr *LineReader) []string {
	t.Helper()
	var lines []string
	for {
		line, _, err := lr.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("ReadLine: %v", err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestLineReaderUTF8LF(t *testing.T) {
	lr := NewLineReader(strings.NewReader("first line\nsecond line\nthird\n"), UTF8)
	got := readAllLines(t, lr)
	want := []string{"first line", "second line", "third"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLineReaderCRLFDetection(t *testing.T) {
	lr := NewLineReader(strings.NewReader("alpha\r\nbeta\r\n"), UTF8)
	_, ending, err := lr.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if ending != CRLF {
		t.Errorf("ending = %v, want CRLF", ending)
	}
}

func TestLineReaderUnterminatedFinalLine(t *testing.T) {
	lr := NewLineReader(strings.NewReader("only line, no trailing newline"), UTF8)
	line, _, err := lr.ReadLine()
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if line != "only line, no trailing newline" {
		t.Errorf("line = %q", line)
	}
	if _, _, err := lr.ReadLine(); err != io.EOF {
		t.Errorf("second ReadLine err = %v, want io.EOF", err)
	}
}

func TestLineReaderUTF16LEWithBOM(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0xFF, 0xFE}) // UTF-16 LE BOM
	buf.Write(EncodeUTF16("hostname: db-prod-01\r\nuser: jdoe\r\n", false))

	all := buf.Bytes()
	enc, skip := DetectBOM(all)
	if enc != UTF16LE {
		t.Fatalf("DetectBOM = %v, want UTF16LE", enc)
	}

	lr := NewLineReader(bytes.NewReader(all[skip:]), UTF16LE)
	got := readAllLines(t, lr)
	want := []string{"hostname: db-prod-01", "user: jdoe"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLineReaderMaxLineBytesExceeded(t *testing.T) {
	huge := strings.Repeat("x", MaxLineBytes+10)
	lr := NewLineReader(strings.NewReader(huge+"\n"), UTF8)
	if _, _, err := lr.ReadLine(); err == nil {
		t.Error("expected error for line exceeding MaxLineBytes, got nil")
	}
}

func TestLineWriterUTF16LERoundTrip(t *testing.T) {
	var buf bytes.Buffer
	lw := NewLineWriter(&buf, UTF16LE)
	if err := lw.WriteBOM(); err != nil {
		t.Fatalf("WriteBOM: %v", err)
	}
	if err := lw.WriteLine("hostname: HOST_001", CRLF); err != nil {
		t.Fatalf("WriteLine: %v", err)
	}
	if err := lw.WriteLine("user: USER_001", CRLF); err != nil {
		t.Fatalf("WriteLine: %v", err)
	}
	if err := lw.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}

	all := buf.Bytes()
	enc, skip := DetectBOM(all)
	if enc != UTF16LE {
		t.Fatalf("round-tripped file BOM detected as %v, want UTF16LE", enc)
	}
	lr := NewLineReader(bytes.NewReader(all[skip:]), UTF16LE)
	got := readAllLines(t, lr)
	want := []string{"hostname: HOST_001", "user: USER_001"}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestLineWriterPreservesLineEndingStyle(t *testing.T) {
	var buf bytes.Buffer
	lw := NewLineWriter(&buf, UTF8)
	lw.WriteLine("one", LF)
	lw.WriteLine("two", LF)
	lw.Flush()
	if buf.String() != "one\ntwo\n" {
		t.Errorf("got %q, want LF-terminated lines", buf.String())
	}
}

func TestLineReaderReportsFinalLineTerminators(t *testing.T) {
	// A file whose last line has no trailing newline must report None on that
	// line, and CRLF/LF must survive round-trips, so the writer can reproduce
	// the original bytes rather than appending a newline the source lacked.
	lr := NewLineReader(strings.NewReader("a\r\nb\nc"), UTF8)
	want := []struct {
		text   string
		ending LineEnding
	}{
		{"a", CRLF},
		{"b", LF},
		{"c", None},
	}
	for i, w := range want {
		line, ending, err := lr.ReadLine()
		if err != nil {
			t.Fatalf("ReadLine %d: %v", i, err)
		}
		if line != w.text || ending != w.ending {
			t.Errorf("line %d = (%q, %v), want (%q, %v)", i, line, ending, w.text, w.ending)
		}
	}
	if _, _, err := lr.ReadLine(); err != io.EOF {
		t.Errorf("final ReadLine err = %v, want io.EOF", err)
	}
}

func TestLineWriterNoneEndingWritesNoTerminator(t *testing.T) {
	var buf bytes.Buffer
	lw := NewLineWriter(&buf, UTF8)
	lw.WriteLine("a", CRLF)
	lw.WriteLine("b", None)
	lw.Flush()
	if buf.String() != "a\r\nb" {
		t.Errorf("got %q, want %q (no trailing newline on final line)", buf.String(), "a\r\nb")
	}
}

package io

import (
	"bufio"
	"io"
)

// LineWriter writes lines back out in the source file's encoding and line
// ending, so sanitized output stays compatible with whatever downstream
// tooling the customer was already using on the original bundle.
type LineWriter struct {
	bw       *bufio.Writer
	enc      Encoding
	ending   LineEnding
	wroteBOM bool
}

// NewLineWriter wraps w, encoding each line as enc and terminating it with ending.
func NewLineWriter(w io.Writer, enc Encoding, ending LineEnding) *LineWriter {
	return &LineWriter{bw: bufio.NewWriter(w), enc: enc, ending: ending}
}

// WriteBOM writes the byte-order mark for the writer's encoding, if it has one.
// Call this once before any WriteLine calls, only if the source file had a BOM.
func (lw *LineWriter) WriteBOM() error {
	lw.wroteBOM = true
	switch lw.enc {
	case UTF8:
		_, err := lw.bw.Write([]byte{0xEF, 0xBB, 0xBF})
		return err
	case UTF16LE:
		_, err := lw.bw.Write([]byte{0xFF, 0xFE})
		return err
	case UTF16BE:
		_, err := lw.bw.Write([]byte{0xFE, 0xFF})
		return err
	default:
		return nil
	}
}

// WriteLine encodes line to the writer's source encoding and appends the
// configured line ending, encoded in that same byte width (e.g. a UTF-16
// file's "\r\n" is four bytes, not two — using ASCII terminator bytes on a
// UTF-16 stream would corrupt the output).
func (lw *LineWriter) WriteLine(line string) error {
	encoded := lw.encode(line)
	if _, err := lw.bw.Write(encoded); err != nil {
		return err
	}
	nl, cr := lw.enc.newlineBytes()
	if lw.ending == CRLF {
		if _, err := lw.bw.Write(cr); err != nil {
			return err
		}
	}
	_, err := lw.bw.Write(nl)
	return err
}

func (lw *LineWriter) encode(s string) []byte {
	switch lw.enc {
	case UTF16LE:
		return EncodeUTF16(s, false)
	case UTF16BE:
		return EncodeUTF16(s, true)
	case Windows1252:
		return EncodeWindows1252(s)
	default: // UTF8
		return []byte(s)
	}
}

// Flush flushes any buffered output to the underlying writer.
func (lw *LineWriter) Flush() error {
	return lw.bw.Flush()
}

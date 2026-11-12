package io

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// MaxLineBytes is the buffer ceiling for a single raw (pre-decode) line, per
// Decision 7. Java stack traces and SAS PROC output can produce single lines
// well over 1 MB; bufio.Scanner's default 64 KB token limit would silently
// truncate those, so LineReader scans manually instead.
const MaxLineBytes = 16 * 1024 * 1024

// LineEnding identifies the line terminator that followed a line in the
// source file. None means the line had no terminator at all -- it can only
// occur on a file's final line when the file does not end with a newline,
// and it exists so the writer can reproduce that byte-for-byte instead of
// silently appending a trailing newline the original didn't have.
type LineEnding int

const (
	LF LineEnding = iota
	CRLF
	None
)

// LineReader reads lines from an underlying byte stream, decoding each line
// from the source Encoding to a UTF-8 string and reporting the line-ending
// style observed. Encoding and line-ending are properties of the whole file
// (per Decision 8, detected once from the first line) rather than re-detected
// per line.
type LineReader struct {
	br  *bufio.Reader
	enc Encoding
}

// NewLineReader wraps r, decoding each line as enc.
func NewLineReader(r io.Reader, enc Encoding) *LineReader {
	return &LineReader{br: bufio.NewReaderSize(r, 64*1024), enc: enc}
}

func (e Encoding) newlineBytes() (nl, cr []byte) {
	switch e {
	case UTF16LE:
		return []byte{0x0A, 0x00}, []byte{0x0D, 0x00}
	case UTF16BE:
		return []byte{0x00, 0x0A}, []byte{0x00, 0x0D}
	default: // UTF8, Windows1252
		return []byte{0x0A}, []byte{0x0D}
	}
}

// ReadLine returns the next decoded line (without its terminator) and the
// LineEnding it was terminated with. At end of stream it returns the final
// line (if any trailing unterminated bytes exist) followed by io.EOF on the
// next call, matching bufio.Scanner-like semantics but without its size limit.
func (lr *LineReader) ReadLine() (line string, ending LineEnding, err error) {
	nl, cr := lr.enc.newlineBytes()
	if len(nl) == 1 {
		return lr.readLineByte(nl[0], cr[0])
	}
	return lr.readLineBytewise(nl, cr)
}

// readLineBytewise is the general ReadLine loop, for multi-byte newlines
// (UTF-16).
func (lr *LineReader) readLineBytewise(nl, cr []byte) (line string, ending LineEnding, err error) {
	var buf []byte
	for {
		b, readErr := lr.br.ReadByte()
		if readErr != nil {
			if len(buf) > 0 {
				// Trailing bytes with no terminator: this is the file's final
				// line and it did not end with a newline. Report None so the
				// writer reproduces the missing terminator exactly.
				decoded, decErr := lr.decode(buf)
				if decErr != nil {
					return "", None, decErr
				}
				return decoded, None, nil
			}
			return "", None, readErr
		}
		buf = append(buf, b)
		if len(buf) > MaxLineBytes {
			return "", LF, fmt.Errorf("line exceeds maximum buffer size of %d bytes", MaxLineBytes)
		}
		if bytes.HasSuffix(buf, nl) {
			body := buf[:len(buf)-len(nl)]
			ending := LF
			if bytes.HasSuffix(body, cr) {
				ending = CRLF
				body = body[:len(body)-len(cr)]
			}
			decoded, decErr := lr.decode(body)
			if decErr != nil {
				return "", LF, decErr
			}
			return decoded, ending, nil
		}
	}
}

// readLineByte is ReadLine for encodings whose newline is a single byte
// (UTF-8, Windows-1252): bufio's ReadSlice finds the terminator with one
// IndexByte scan instead of a ReadByte call per byte. Same results as the
// byte loop, including the MaxLineBytes limit (counted with the newline).
func (lr *LineReader) readLineByte(nl, cr byte) (string, LineEnding, error) {
	var buf []byte
	for {
		frag, readErr := lr.br.ReadSlice(nl)
		if readErr == bufio.ErrBufferFull {
			buf = append(buf, frag...)
			if len(buf) > MaxLineBytes {
				return "", LF, fmt.Errorf("line exceeds maximum buffer size of %d bytes", MaxLineBytes)
			}
			continue
		}
		// frag is only valid until the next read; decode copies it.
		line := frag
		if buf != nil {
			buf = append(buf, frag...)
			line = buf
		}
		if len(line) > MaxLineBytes {
			return "", LF, fmt.Errorf("line exceeds maximum buffer size of %d bytes", MaxLineBytes)
		}
		if readErr != nil {
			if len(line) > 0 {
				// Trailing bytes with no terminator: the file's final line.
				decoded, decErr := lr.decode(line)
				if decErr != nil {
					return "", None, decErr
				}
				return decoded, None, nil
			}
			return "", None, readErr
		}
		body := line[:len(line)-1]
		ending := LF
		if len(body) > 0 && body[len(body)-1] == cr {
			ending = CRLF
			body = body[:len(body)-1]
		}
		decoded, decErr := lr.decode(body)
		if decErr != nil {
			return "", LF, decErr
		}
		return decoded, ending, nil
	}
}

func (lr *LineReader) decode(b []byte) (string, error) {
	switch lr.enc {
	case UTF16LE:
		return DecodeUTF16(b, false)
	case UTF16BE:
		return DecodeUTF16(b, true)
	case Windows1252:
		return DecodeWindows1252(b), nil
	default: // UTF8
		return string(b), nil
	}
}

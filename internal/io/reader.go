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

// LineEnding identifies the line terminator style of a source file.
type LineEnding int

const (
	LF LineEnding = iota
	CRLF
)

func (e LineEnding) Bytes() []byte {
	if e == CRLF {
		return []byte("\r\n")
	}
	return []byte("\n")
}

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
	var buf []byte
	for {
		b, readErr := lr.br.ReadByte()
		if readErr != nil {
			if len(buf) > 0 {
				decoded, decErr := lr.decode(buf)
				if decErr != nil {
					return "", LF, decErr
				}
				return decoded, LF, nil
			}
			return "", LF, readErr
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

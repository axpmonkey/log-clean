package pipeline

import (
	"bufio"
	"encoding/binary"
	"hash/maphash"
	"io"
	"os"
)

// Pass 1 records each line's DetectorMask in a per-file sidecar in the
// run's temporary directory; Pass 2 reads it back chunk by chunk, in order,
// and runs only the detectors that found something on that line in Pass 1
// (plus the known-values sweep). This roughly halves Pass 2's detection
// work without holding anything per line in memory.
//
// A sidecar record is one chunk: its line count, a hash of its lines, and a
// uvarint mask per line (one byte for the common no-match line). Pass 2
// uses a chunk's masks only if its own line count and hash agree, so a file
// that changed between passes, or any misalignment, falls back to running
// every detector -- never to running fewer.

// chunkHash hashes a chunk's line texts (length-prefixed) and PEM flags.
func chunkHash(seed maphash.Seed, c *chunk) uint64 {
	var h maphash.Hash
	h.SetSeed(seed)
	var n [binary.MaxVarintLen64 + 1]byte
	for _, it := range c.lines {
		k := binary.PutUvarint(n[:], uint64(len(it.text)))
		if it.pem {
			n[k] = 1
		} else {
			n[k] = 0
		}
		h.Write(n[:k+1])
		h.WriteString(it.text)
	}
	return h.Sum64()
}

type maskWriter struct {
	f   *os.File
	bw  *bufio.Writer
	buf []byte
	err error
}

func newMaskWriter(dir string) (*maskWriter, error) {
	f, err := os.CreateTemp(dir, "masks-*")
	if err != nil {
		return nil, err
	}
	return &maskWriter{f: f, bw: bufio.NewWriterSize(f, 64*1024)}, nil
}

// writeChunk appends c's record. Errors are sticky and reported by close.
func (w *maskWriter) writeChunk(c *chunk) {
	if w.err != nil {
		return
	}
	b := binary.AppendUvarint(w.buf[:0], uint64(len(c.masks)))
	b = binary.LittleEndian.AppendUint64(b, c.hash)
	for _, m := range c.masks {
		b = binary.AppendUvarint(b, uint64(m))
	}
	w.buf = b
	_, w.err = w.bw.Write(b)
}

// close finishes the sidecar and returns its path, or removes it and
// returns the first error.
func (w *maskWriter) close() (string, error) {
	err := w.err
	if err == nil {
		err = w.bw.Flush()
	}
	if cerr := w.f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(w.f.Name())
		return "", err
	}
	return w.f.Name(), nil
}

type maskReader struct {
	f    *os.File
	br   *bufio.Reader
	dead bool
}

func openMaskReader(path string) (*maskReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	return &maskReader{f: f, br: bufio.NewReaderSize(f, 64*1024)}, nil
}

// readChunk reads the next record into c.masks and c.wantHash, which the
// worker checks against the chunk it actually read. Any read error or a
// line-count mismatch leaves c.masks nil (run every detector) for this and
// every later chunk.
func (r *maskReader) readChunk(c *chunk) {
	if r.dead {
		return
	}
	n, err := binary.ReadUvarint(r.br)
	if err != nil || n != uint64(len(c.lines)) {
		r.dead = true
		return
	}
	var h [8]byte
	if _, err := io.ReadFull(r.br, h[:]); err != nil {
		r.dead = true
		return
	}
	masks := make([]DetectorMask, n)
	for i := range masks {
		m, err := binary.ReadUvarint(r.br)
		if err != nil || m > uint64(^DetectorMask(0)) {
			r.dead = true
			return
		}
		masks[i] = DetectorMask(m)
	}
	c.masks, c.wantHash = masks, binary.LittleEndian.Uint64(h[:])
}

func (r *maskReader) close() { r.f.Close() }

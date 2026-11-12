package pipeline

import (
	"fmt"
	"hash/maphash"
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"sas-log-sanitize/internal/audit"
	ioenc "sas-log-sanitize/internal/io"
	"sas-log-sanitize/internal/runlog"
	"sas-log-sanitize/internal/tokenize"
)

// forkForScan returns a Pipeline for scanning one file in Pass 1: the same
// detectors and ignore rules, but its own empty registry. Each file's
// first-seen values land in its own registry and are merged into the real
// one in sorted-path order (mergeRegistry), so token numbering is identical
// to a sequential run no matter which file finishes first.
func (p *Pipeline) forkForScan() *Pipeline {
	return &Pipeline{
		Detectors:         p.Detectors,
		Registry:          tokenize.NewRegistry(),
		Ignore:            p.Ignore,
		IPv4SkipRanges:    p.IPv4SkipRanges,
		replacementCounts: make(map[string]int),
		scanDetectors:     p.scanDetectors,
		sweepEnabled:      p.sweepEnabled,
	}
}

// forkForReplace returns a Pipeline for one file in Pass 2: it shares the
// (now complete and read-only) registry, and counts its own replacements so
// no map is written concurrently.
func (p *Pipeline) forkForReplace() *Pipeline {
	f := p.forkForScan()
	f.Registry = p.Registry
	return f
}

// mergeCounts adds a fork's replacement counts into p.
func (p *Pipeline) mergeCounts(f *Pipeline) {
	for k, v := range f.replacementCounts {
		p.replacementCounts[k] += v
	}
}

// workerCount resolves RunOptions.Workers (0 = one per CPU).
func workerCount(n int) int {
	if n <= 0 {
		n = runtime.GOMAXPROCS(0)
	}
	return n
}

// forEachFile runs fn(i) for i in [0, n) on up to workers goroutines and
// returns the error of the lowest-indexed failing call, so the error a user
// sees doesn't depend on scheduling.
func forEachFile(n, workers int, fn func(i int) error) error {
	errs := make([]error, n)
	next := int64(-1)
	var wg sync.WaitGroup
	for w := 0; w < workers && w < n; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				i := int(atomic.AddInt64(&next, 1))
				if i >= n {
					return
				}
				errs[i] = fn(i)
			}
		}()
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// progressInterval is how often a running pass reports progress.
const progressInterval = 2 * time.Second

// progress reports one pass's progress (files, MB, MB/s, ETA) to w. A nil
// *progress is valid and reports nothing.
type progress struct {
	w          io.Writer
	pass       int
	totalFiles int
	totalBytes int64
	doneFiles  atomic.Int64
	doneBytes  atomic.Int64
	start      time.Time
	stop       chan struct{}
	stopped    sync.WaitGroup
	mu         sync.Mutex
}

func startProgress(w io.Writer, pass, totalFiles int, totalBytes int64) *progress {
	if w == nil {
		return nil
	}
	pr := &progress{w: w, pass: pass, totalFiles: totalFiles, totalBytes: totalBytes, start: time.Now(), stop: make(chan struct{})}
	pr.stopped.Add(1)
	go func() {
		defer pr.stopped.Done()
		t := time.NewTicker(progressInterval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				pr.report()
			case <-pr.stop:
				return
			}
		}
	}()
	return pr
}

// addBytes records raw input bytes read (called as lines are read).
func (pr *progress) addBytes(n int) {
	if pr != nil {
		pr.doneBytes.Add(int64(n))
	}
}

// fileDone records a finished file.
func (pr *progress) fileDone() {
	if pr != nil {
		pr.doneFiles.Add(1)
	}
}

// finish stops the ticker and prints the final line for the pass.
func (pr *progress) finish() {
	if pr == nil {
		return
	}
	close(pr.stop)
	pr.stopped.Wait()
	pr.doneBytes.Store(pr.totalBytes)
	pr.report()
}

func (pr *progress) report() {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	const mb = 1024 * 1024
	elapsed := time.Since(pr.start).Seconds()
	done := pr.doneBytes.Load()
	rate := 0.0
	if elapsed > 0 {
		rate = float64(done) / mb / elapsed
	}
	eta := "?"
	if done >= pr.totalBytes {
		eta = "0s"
	} else if rate > 0 {
		eta = (time.Duration(float64(pr.totalBytes-done)/mb/rate) * time.Second).Round(time.Second).String()
	}
	fmt.Fprintf(pr.w, "pass %d: %d/%d files, %.1f of %.1f MB, %.1f MB/s, ETA %s\n",
		pr.pass, pr.doneFiles.Load(), pr.totalFiles, float64(done)/mb, float64(pr.totalBytes)/mb, rate, eta)
}

// countingReader feeds bytes read to a progress reporter.
type countingReader struct {
	r  io.Reader
	pr *progress
}

func (c countingReader) Read(b []byte) (int, error) {
	n, err := c.r.Read(b)
	c.pr.addBytes(n)
	return n, err
}

// ---- intra-file chunking ----------------------------------------------------

// chunkLines is how many lines one unit of parallel work holds. Small enough
// that in-flight chunks stay a few MB per file, large enough that scheduling
// overhead is negligible next to the detector regexes.
const chunkLines = 1024

// windowPerWorker is how many chunks per worker may be in flight per file.
const windowPerWorker = 4

// runEnv carries the per-run state the file-level functions share.
type runEnv struct {
	opts RunOptions
	prog *progress
	log  *runlog.Logger
	// sem bounds CPU-bound chunk work across all files to Workers at once.
	sem chan struct{}
	// window bounds how many chunks of one file are in flight (read but not
	// yet emitted), which bounds memory per file. Chunks are emitted in
	// order, so one slow chunk (e.g. on an efficiency core of a hybrid CPU,
	// or a busy vCPU) stalls emission; several chunks per worker of slack
	// keeps the other workers busy meanwhile. Memory stays bounded:
	// windowPerWorker*Workers chunks of chunkLines lines.
	window int
	// tmpDir returns the run's private temporary directory (created on
	// first use); seed hashes chunks for the detector-mask sidecars.
	tmpDir func() (string, error)
	seed   maphash.Seed
}

func newRunEnv(opts RunOptions, log *runlog.Logger) *runEnv {
	w := workerCount(opts.Workers)
	return &runEnv{opts: opts, log: log, sem: make(chan struct{}, w), window: windowPerWorker*w + 2, seed: maphash.MakeSeed()}
}

// lineItem is one input line plus what the sequential reader decided about
// it before handing it to a worker.
type lineItem struct {
	text   string
	ending ioenc.LineEnding
	// pem marks a line inside a multi-line private-key block. PEM state
	// spans lines (and so chunks), so it is computed by the single reader,
	// in order, never by the parallel workers.
	pem bool
}

// chunk is a run of consecutive lines processed as one unit of work.
type chunk struct {
	start int // 1-based line number of lines[0]
	lines []lineItem
	done  chan struct{}

	// masks are the lines' DetectorMasks: computed in Pass 1 (with hash,
	// for the sidecar), read back from it in Pass 2 (with wantHash, the
	// Pass 1 hash the chunk must still have for them to apply).
	masks          []DetectorMask
	hash, wantHash uint64

	reg      *tokenize.Registry // Pass 1 result
	out      []string           // Pass 2 results
	findings []audit.Finding
	fork     *Pipeline
}

// processChunks reads lr sequentially into chunks, runs work on each chunk
// in parallel (bounded by env.sem), and calls emit on each chunk in input
// order. It returns the number of lines read.
//
// This is what lets a single huge file (one multi-GB catalina.out) use every
// core: Pass 1 chunks scan into their own registries and are merged in chunk
// order, Pass 2 chunks are replaced in parallel and written in order, so
// the result is identical to reading the file line by line.
//
// prepare, if non-nil, is called on each chunk by the reader, in order,
// before the chunk is handed to a worker.
func processChunks(lr *ioenc.LineReader, env *runEnv, prepare, work func(*chunk), emit func(*chunk) error) (int, error) {
	ordered := make(chan *chunk, env.window)
	stop := make(chan struct{})
	var readErr error
	lines := 0

	go func() {
		defer close(ordered)
		var pem pemBlockRedactor
		for eof := false; !eof; {
			c := &chunk{start: lines + 1, done: make(chan struct{})}
			for len(c.lines) < chunkLines {
				text, ending, err := lr.ReadLine()
				if err == io.EOF {
					eof = true
					break
				}
				if err != nil {
					readErr = err
					eof = true
					break
				}
				lines++
				c.lines = append(c.lines, lineItem{text: text, ending: ending, pem: pem.redacts(text)})
			}
			if len(c.lines) == 0 {
				return
			}
			if prepare != nil {
				prepare(c)
			}
			go func(c *chunk) {
				env.sem <- struct{}{}
				work(c)
				<-env.sem
				close(c.done)
			}(c)
			select {
			case ordered <- c:
			case <-stop:
				<-c.done
				return
			}
		}
	}()

	var emitErr error
	for c := range ordered {
		<-c.done
		if emitErr == nil {
			if emitErr = emit(c); emitErr != nil {
				close(stop)
			}
		}
	}
	if emitErr != nil {
		return lines, emitErr
	}
	return lines, readErr
}

// Package runlog is the application's own structured log, written to
// _runlog.txt in the output directory. Format: timestamped, one event per
// line, grep-friendly. It must never contain real PII values -- only counts,
// file paths, and tokens (plan: "Do not log original PII values to the
// runlog. Log counts, file paths, and tokens -- never the values being
// protected."). The mapping file is sensitive; this log is not, and callers
// must take care that no real value ever flows from the mapping into a log
// call here.
package runlog

import (
	"fmt"
	"io"
	"time"
)

// Logger writes timestamped, leveled events to an underlying writer.
type Logger struct {
	w       io.Writer
	verbose bool
	now     func() time.Time // overridable for deterministic tests
}

// New returns a Logger writing to w. When verbose is false, Verbose() calls
// are silently dropped.
func New(w io.Writer, verbose bool) *Logger {
	return &Logger{w: w, verbose: verbose, now: time.Now}
}

func (l *Logger) write(level, format string, args ...any) {
	fmt.Fprintf(l.w, "%s [%s] %s\n", l.now().UTC().Format(time.RFC3339), level, fmt.Sprintf(format, args...))
}

// Info logs a normal informational event (file discovered, pass completed, etc).
func (l *Logger) Info(format string, args ...any) { l.write("INFO", format, args...) }

// Warn logs a recoverable problem (a file skipped, an unexpected but non-fatal condition).
func (l *Logger) Warn(format string, args ...any) { l.write("WARN", format, args...) }

// Error logs a failure that affected this run's correctness or completeness.
func (l *Logger) Error(format string, args ...any) { l.write("ERROR", format, args...) }

// Verbose logs a detailed, high-volume event (e.g. per-detector match
// counts), only emitted when the Logger was constructed with verbose=true
// (the --verbose CLI flag).
func (l *Logger) Verbose(format string, args ...any) {
	if l.verbose {
		l.write("DEBUG", format, args...)
	}
}

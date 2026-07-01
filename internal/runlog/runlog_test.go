package runlog

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

func TestLoggerWritesLevelAndMessage(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	l.now = fixedClock(time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC))

	l.Info("processed %d files", 5)

	out := buf.String()
	if !strings.Contains(out, "[INFO]") || !strings.Contains(out, "processed 5 files") {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "2026-06-30T12:00:00Z") {
		t.Errorf("output missing expected timestamp: %q", out)
	}
}

func TestLoggerVerboseSuppressedByDefault(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	l.Verbose("detector match counts: %d", 3)
	if buf.Len() != 0 {
		t.Errorf("expected no output, got %q", buf.String())
	}
}

func TestLoggerVerboseEmittedWhenEnabled(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, true)
	l.Verbose("detector match counts: %d", 3)
	if !strings.Contains(buf.String(), "detector match counts: 3") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestLoggerWarnAndError(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf, false)
	l.Warn("skipped %s: binary", "core.1234")
	l.Error("failed to write %s", "out.log")
	out := buf.String()
	if !strings.Contains(out, "[WARN] skipped core.1234: binary") {
		t.Errorf("output = %q", out)
	}
	if !strings.Contains(out, "[ERROR] failed to write out.log") {
		t.Errorf("output = %q", out)
	}
}

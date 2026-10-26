package handler

import (
	"bytes"
	"context"
	"log/slog"
	"sync"
	"testing"
)

// newTestLogger returns a logger that writes text at info level, the
// collector's default, into the returned buffer.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	return newTestLoggerAtLevel(slog.LevelInfo)
}

func newTestLoggerAtLevel(level slog.Level) (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})), &buf
}

// logEntry is one record captured by a logRecorder.
type logEntry struct {
	Level   slog.Level
	Message string
	Data    Fields
}

// logRecorder captures log records so tests can compare each one's fields
// as a whole instead of matching substrings of the formatted output.
type logRecorder struct {
	level   slog.Level
	mu      sync.Mutex
	entries []logEntry
}

// newRecordingLogger returns a logger whose records at or above level are
// captured by the returned recorder.
func newRecordingLogger(level slog.Level) (*slog.Logger, *logRecorder) {
	rec := &logRecorder{level: level}
	return slog.New(rec), rec
}

func (r *logRecorder) Entries() []logEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]logEntry(nil), r.entries...)
}

func (r *logRecorder) Enabled(_ context.Context, level slog.Level) bool {
	return level >= r.level
}

func (r *logRecorder) Handle(_ context.Context, record slog.Record) error {
	data := Fields{}
	record.Attrs(func(a slog.Attr) bool {
		v := a.Value.Resolve().Any()
		// slog stores every int as an int64. Turn it back into an int so
		// expectations can be written with plain integer literals.
		if i, ok := v.(int64); ok {
			v = int(i)
		}
		data[a.Key] = v
		return true
	})

	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, logEntry{Level: record.Level, Message: record.Message, Data: data})
	return nil
}

func (r *logRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }

func (r *logRecorder) WithGroup(string) slog.Handler { return r }

// urlFields picks the named fields from the only logged entry, so a test can
// compare every URL it truncates exactly.
func urlFields(t *testing.T, rec *logRecorder, keys ...string) Fields {
	t.Helper()
	entries := rec.Entries()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1: %+v", len(entries), entries)
	}
	got := Fields{}
	for _, k := range keys {
		got[k] = entries[0].Data[k]
	}
	return got
}

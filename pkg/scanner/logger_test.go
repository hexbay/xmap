package scanner

import (
	"context"
	"sync"
	"testing"
)

type recordingLogger struct {
	mu      sync.Mutex
	message string
	fields  []any
}

func (l *recordingLogger) Debug(_ context.Context, message string, fields ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.message, l.fields = message, fields
}
func (*recordingLogger) Info(context.Context, string, ...any)         {}
func (*recordingLogger) Warn(context.Context, string, ...any)         {}
func (*recordingLogger) Error(context.Context, error, string, ...any) {}

func TestScannerUsesStructuredLogger(t *testing.T) {
	logger := &recordingLogger{}
	logger.Debug(context.Background(), "probe sent", "probe", "NULL", "request_bytes", 4)
	if logger.message != "probe sent" || len(logger.fields) != 4 {
		t.Fatalf("unexpected log: %q %#v", logger.message, logger.fields)
	}
}

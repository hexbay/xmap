package scanner

import "context"

// Logger is the only logging dependency of the scanner. Fields are alternating
// key/value pairs and should be safe for concurrent use.
type Logger interface {
	Debug(context.Context, string, ...any)
	Info(context.Context, string, ...any)
	Warn(context.Context, string, ...any)
	Error(context.Context, error, string, ...any)
}

type noopLogger struct{}

func (noopLogger) Debug(context.Context, string, ...any)        {}
func (noopLogger) Info(context.Context, string, ...any)         {}
func (noopLogger) Warn(context.Context, string, ...any)         {}
func (noopLogger) Error(context.Context, error, string, ...any) {}

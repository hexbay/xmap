package types

import "context"

// SemaphoreLimiter is a process-local, shareable in-flight scan limiter.
type SemaphoreLimiter struct{ sem chan struct{} }

func NewConcurrencyLimiter(limit int) *SemaphoreLimiter {
	if limit <= 0 {
		panic("concurrency limit must be positive")
	}
	return &SemaphoreLimiter{sem: make(chan struct{}, limit)}
}

func (l *SemaphoreLimiter) Acquire(ctx context.Context) error {
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *SemaphoreLimiter) Release() {
	select {
	case <-l.sem:
	default:
	}
}

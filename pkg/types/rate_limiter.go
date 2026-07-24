package types

import (
	"context"
	"sync"
	"time"
)

// TokenBucketRateLimiter is safe to share among any number of engine
// instances. ratePerSecond must be positive; burst controls initial and peak
// capacity.
type TokenBucketRateLimiter struct {
	mu            sync.Mutex
	ratePerSecond float64
	burst         float64
	tokens        float64
	lastRefill    time.Time
}

func NewRateLimiter(ratePerSecond float64, burst int) *TokenBucketRateLimiter {
	if ratePerSecond <= 0 {
		panic("ratePerSecond must be positive")
	}
	if burst <= 0 {
		burst = 1
	}
	return &TokenBucketRateLimiter{
		ratePerSecond: ratePerSecond,
		burst:         float64(burst),
		tokens:        float64(burst),
		lastRefill:    time.Now(),
	}
}

func (l *TokenBucketRateLimiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens = min(l.burst, l.tokens+now.Sub(l.lastRefill).Seconds()*l.ratePerSecond)
		l.lastRefill = now
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		wait := time.Duration((1 - l.tokens) / l.ratePerSecond * float64(time.Second))
		l.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

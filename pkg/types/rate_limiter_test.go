package types

import (
	"context"
	"testing"
	"time"
)

func TestRateLimiterSharesOneGlobalBudget(t *testing.T) {
	limiter := NewRateLimiter(20, 1)
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 35*time.Millisecond {
		t.Fatalf("shared limiter did not enforce rate: waited %s", elapsed)
	}
}

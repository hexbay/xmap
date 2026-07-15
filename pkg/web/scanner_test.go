package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/xmap/pkg/types"
)

func TestNewScannerCreatesAppFingerScanner(t *testing.T) {
	rules, err := rule.ScanRuleDirectory(t.TempDir())
	if err != nil {
		t.Fatalf("load empty rule directory: %v", err)
	}

	scanner, err := NewScanner(&types.Options{Timeout: 20}, rules)
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}
	if scanner == nil {
		t.Fatal("expected scanner")
	}
}

func TestNewScannerRejectsInvalidOptions(t *testing.T) {
	rules, err := rule.ScanRuleDirectory(t.TempDir())
	if err != nil {
		t.Fatalf("load empty rule directory: %v", err)
	}

	_, err = NewScanner(&types.Options{HttpRetry: -1}, rules)
	if err == nil || !strings.Contains(err.Error(), "retries must not be negative") {
		t.Fatalf("expected invalid retries error, got %v", err)
	}
}

func TestScannerUsesRuleProviderOnEachScan(t *testing.T) {
	rules, err := rule.ScanRuleDirectory(t.TempDir())
	if err != nil {
		t.Fatalf("load empty rule directory: %v", err)
	}

	var calls int32
	scanner, err := NewScannerWithRuleProvider(&types.Options{Timeout: 1}, func() *rule.RuleSet {
		atomic.AddInt32(&calls, 1)
		return rules
	})
	if err != nil {
		t.Fatalf("new scanner with provider: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	for i := 0; i < 2; i++ {
		if _, err := scanner.Scan(context.Background(), server.URL); err != nil {
			t.Fatalf("scan %d: %v", i, err)
		}
	}

	if got := atomic.LoadInt32(&calls); got < 2 {
		t.Fatalf("expected rule provider to be called for each scan, got %d", got)
	}
}

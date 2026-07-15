package web

import (
	"strings"
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

package web

import (
	"reflect"
	"testing"
	"time"
	"unsafe"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/xmap/pkg/types"
)

func TestNewScannerAppliesTimeoutToFetcher(t *testing.T) {
	if err := rule.GetRuleManager().LoadRules(t.TempDir()); err != nil {
		t.Fatalf("load empty rule directory: %v", err)
	}

	scanner, err := NewScanner(&types.Options{Timeout: 20})
	if err != nil {
		t.Fatalf("new scanner: %v", err)
	}

	fetchOptions := fetcherOptions(t, scanner.fetcher)
	if fetchOptions.Timeout != 20*time.Second {
		t.Fatalf("expected fetch timeout 20s, got %s", fetchOptions.Timeout)
	}
}

func fetcherOptions(t *testing.T, fetcher *fetch.Fetcher) *fetch.Options {
	t.Helper()

	field := reflect.ValueOf(fetcher).Elem().FieldByName("options")
	return *(**fetch.Options)(unsafe.Pointer(field.UnsafeAddr()))
}

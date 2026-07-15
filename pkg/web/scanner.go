package web

import (
	"fmt"
	"time"

	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
	appscanner "github.com/hexbay/appfinger/pkg/scanner"
	"github.com/hexbay/xmap/pkg/types"
)

// Scanner Web应用指纹扫描器
type Scanner = appscanner.Scanner

// Result Web扫描结果
type Result = appscanner.Result

type ruleProviderFunc func() *rule.RuleSet

func (f ruleProviderFunc) Snapshot() *rule.RuleSet {
	return f()
}

// NewScanner 创建新的Web扫描器
func NewScanner(options *types.Options, rules *rule.RuleSet) (*Scanner, error) {
	return NewScannerWithRuleProvider(options, func() *rule.RuleSet {
		return rules
	})
}

// NewScannerWithRuleProvider 创建一个会在每次扫描时读取最新规则快照的扫描器。
func NewScannerWithRuleProvider(options *types.Options, ruleProvider func() *rule.RuleSet) (*Scanner, error) {
	if options == nil {
		options = types.DefaultOptions()
	}
	if ruleProvider == nil {
		return nil, fmt.Errorf("规则提供器未设置")
	}
	if ruleProvider() == nil {
		return nil, fmt.Errorf("规则库未加载")
	}
	fetchOptions := fetch.DefaultOption()
	fetchOptions.Retries = options.HttpRetry
	if options.Timeout > 0 {
		fetchOptions.Timeout = time.Duration(options.Timeout) * time.Second
	}
	fetchOptions.Proxy = options.Proxy
	fetchOptions.DebugReq = options.DebugRequest
	fetchOptions.DebugResp = options.DebugResponse
	fetchOptions.DisableIcon = options.DisableIcon
	fetchOptions.DisableJavaScript = options.DisableJS
	fetchOptions.MaxBodySize = options.MaxBodySize
	if fetchOptions.MaxBodySize <= 0 {
		fetchOptions.MaxBodySize = types.DefaultMaxBodySize
	}
	fetchOptions.MaxIconSize = options.MaxIconSize
	if fetchOptions.MaxIconSize <= 0 {
		fetchOptions.MaxIconSize = types.DefaultMaxIconSize
	}
	fetcher, err := fetch.NewFetcher(fetchOptions)
	if err != nil {
		return nil, fmt.Errorf("创建Web请求器失败: %w", err)
	}
	appScanner, err := appscanner.New(appscanner.Config{
		Fetcher: fetcher,
		RuleProvider: ruleProviderFunc(ruleProvider),
	})
	if err != nil {
		return nil, fmt.Errorf("创建Web扫描器失败: %w", err)
	}
	return appScanner, nil
}

// ShouldScan 判断是否应该进行Web扫描
func ShouldScan(service string) bool {
	return service == "http" || service == "https" ||
		service == "http-alt" || service == "https-alt" ||
		service == "http-proxy" || service == "ssl/http"
}

package web

import (
	"context"
	"fmt"
	"github.com/hexbay/appfinger/pkg/fetch"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/hexbay/appfinger/pkg/runner"
	"github.com/hexbay/xmap/pkg/types"
)

// Scanner Web应用指纹扫描器
type Scanner struct {
	options *types.Options
	fetcher *fetch.Fetcher
}

// NewScanner 创建新的Web扫描器
func NewScanner(options *types.Options) (*Scanner, error) {
	// 获取规则管理器实例
	ruleManager := rule.GetRuleManager()
	if !ruleManager.IsLoaded() {
		return nil, fmt.Errorf("规则库未加载")
	}
	fetchOptions := fetch.DefaultOption()
	fetchOptions.RetryMax = options.HttpRetry
	fetchOptions.Proxy = options.Proxy
	fetchOptions.DebugReq = options.DebugRequest
	fetchOptions.DebugResp = options.DebugResponse
	fetchOptions.DisableIcon = options.DisableIcon
	fetcher := fetch.NewFetcher(fetchOptions)
	scanner := &Scanner{
		options: options,
		fetcher: fetcher,
	}
	// 创建默认选项
	return scanner, nil
}

// ReloadWebRules 重新加载Web指纹库规则
func ReloadWebRules() error {
	return rule.GetRuleManager().ReloadRules()
}

// ReloadRules 重新加载指纹库规则 (兼容旧版API)
func ReloadRules() error {
	return ReloadWebRules()
}

// ScanResult Web扫描结果
type ScanResult struct {
	URL        string
	Components map[string]map[string]string
	Error      error
	Banner     *fetch.Banner
}

// ShouldScan 判断是否应该进行Web扫描
func ShouldScan(service string) bool {
	return service == "http" || service == "https" ||
		service == "http-alt" || service == "https-alt" ||
		service == "http-proxy" || service == "ssl/http"
}

// ScanWithContext 带上下文的Web扫描
func (s *Scanner) ScanWithContext(ctx context.Context, url string) (*ScanResult, error) {
	sdk, err := runner.NewRunner(s.fetcher, rule.GetRuleManager(), nil)
	if err != nil {
		return nil, fmt.Errorf("create Runner Error~")
	}
	// 执行匹配
	result, err := sdk.ScanWithContext(ctx, url)
	if err != nil {
		return &ScanResult{
			URL:   url,
			Error: err,
		}, err
	}
	// 返回结果
	return &ScanResult{
		URL:        url,
		Components: result.Components,
		Banner:     result.Banner,
	}, nil
}

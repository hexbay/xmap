package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hexbay/xmap/pkg/scanner"

	"github.com/hexbay/xmap/pkg/types"
	"github.com/hexbay/xmap/pkg/web"
	"github.com/projectdiscovery/gologger"
)

// XMap 是核心扫描引擎，负责协调各种扫描器
type XMap struct {
	// 服务扫描器 - 负责基础网络服务探测
	serviceScanner *scanner.ServiceScanner
	// Web扫描器 - 负责Web应用指纹识别
	webScanner *web.Scanner
	// 配置选项
	options *types.Options
	// 初始化锁
	closed             atomic.Bool
	concurrencyLimiter types.ConcurrencyLimiter
}

// EngineConfig is the sole configuration surface for embedded engines.
// RateLimiter may be shared by multiple Engine instances to enforce one global
// connection rate across the process.
type EngineConfig struct {
	Options            *types.Options
	Transport          scanner.Transport
	RateLimiter        types.RateLimiter
	ConcurrencyLimiter types.ConcurrencyLimiter
	Logger             scanner.Logger
}

func DefaultEngineConfig() EngineConfig {
	return EngineConfig{Options: types.DefaultOptions()}
}

// ScanEvent is emitted once for every target submitted to ScanMany.
type ScanEvent struct {
	Index  int
	Target *types.ScanTarget
	Result *types.ScanResult
	Err    error
}

// NewEngine constructs an embeddable engine. It snapshots options so callers
// may safely reuse or modify their own Options after construction.
func NewEngine(config EngineConfig) (*XMap, error) {
	if config.Options == nil {
		return nil, fmt.Errorf("engine options are required")
	}
	x := &XMap{
		options:            config.Options.Clone(),
		concurrencyLimiter: config.ConcurrencyLimiter,
	}
	err := x.init(config)
	return x, err
}

// init 初始化XMap扫描引擎
func (x *XMap) init(config EngineConfig) error {
	// 使用sync.Once确保只初始化一次
	var initErr error
	// 创建服务扫描器
	x.serviceScanner, initErr = scanner.NewServiceScannerWithDependencies(x.options, config.Transport, config.RateLimiter, config.Logger)
	if initErr != nil {
		return initErr
	}
	// 初始化Web规则库
	initErr = InitWebRuleManager(x.options.AppFingerHome)
	if initErr != nil {
		return initErr
	}
	// 创建Web扫描器
	x.webScanner, initErr = web.NewScannerWithRuleProvider(x.options, webRuleManager.Snapshot)

	return initErr
}

// Scan 扫描单个目标
func (x *XMap) Scan(ctx context.Context, target *types.ScanTarget) (*types.ScanResult, error) {
	if x.closed.Load() {
		return nil, fmt.Errorf("xmap engine is closed")
	}
	if target == nil {
		return nil, fmt.Errorf("nil scan target")
	}
	if x.concurrencyLimiter != nil {
		if err := x.concurrencyLimiter.Acquire(ctx); err != nil {
			return nil, err
		}
		defer x.concurrencyLimiter.Release()
	}
	// 1. 执行服务扫描
	if web.ShouldScan(target.Scheme) {
		// 构建URL
		result := types.NewScanResult(target)
		url := x.buildTargetURL(target, target.Scheme)
		// 执行Web扫描
		webResult, err := x.webScanner.Scan(ctx, url)
		result.Service = target.Scheme
		result.SSL = target.Scheme == "https"
		x.enrichResultWithWebData(result, webResult)
		// 完成扫描,计算耗时
		result.Complete(err)
		return result, err
	}
	result, err := x.serviceScanner.ScanWithContext(ctx, target)
	if err != nil && result != nil && result.Service == "" {
		return result, err
	}
	if result == nil {
		return nil, err
	}
	// 2. 标准化结果格式
	x.normalizeResult(result)
	// 3. 如果是Web服务，执行Web扫描
	if web.ShouldScan(result.Service) && x.webScanner != nil {
		// 构建URL
		url := x.buildTargetURL(target, result.Service)
		// 执行Web扫描
		webResult, err := x.webScanner.Scan(ctx, url)
		if err != nil {
			gologger.Debug().Msgf("Web扫描失败: %v", err)
		} else {
			// 合并Web扫描结果
			x.enrichResultWithWebData(result, webResult)
		}
	}

	return result, nil
}

// Close releases resources retained by the engine. It is idempotent.
func (x *XMap) Close() error {
	if !x.closed.CompareAndSwap(false, true) {
		return nil
	}
	if x.serviceScanner != nil {
		return x.serviceScanner.Close()
	}
	return nil
}

// Config returns an independent snapshot of the engine's scan configuration.
func (x *XMap) Config() EngineConfig {
	return EngineConfig{Options: x.options.Clone()}
}

// ScanMany scans a finite target slice and streams one event per completed
// target. Events may arrive out of order; Index preserves input ordering.
func (x *XMap) ScanMany(ctx context.Context, targets []*types.ScanTarget) <-chan ScanEvent {
	output := make(chan ScanEvent)
	workers := x.options.Threads
	if workers <= 0 {
		workers = 10
	}
	go func() {
		defer close(output)
		jobs := make(chan int)
		var wg sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for index := range jobs {
					target := targets[index]
					result, err := x.Scan(ctx, target)
					event := ScanEvent{Index: index, Target: target, Result: result, Err: err}
					select {
					case output <- event:
					case <-ctx.Done():
						return
					}
				}
			}()
		}
		for index := range targets {
			select {
			case jobs <- index:
			case <-ctx.Done():
				close(jobs)
				wg.Wait()
				return
			}
		}
		close(jobs)
		wg.Wait()
	}()
	return output
}

// buildTargetURL 构建目标URL
func (x *XMap) buildTargetURL(target *types.ScanTarget, service string) string {
	if target.Host == "" {
		return fmt.Sprintf("%s://%s:%d", service, target.IP, target.Port)
	} else {
		return fmt.Sprintf("%s://%s:%d", service, target.Host, target.Port)
	}
}

// enrichResultWithWebData 使用Web扫描数据丰富扫描结果
func (x *XMap) enrichResultWithWebData(result *types.ScanResult, webResult *web.Result) {
	if result == nil || webResult == nil {
		return
	}
	// 确保Metadata已初始化
	if result.Banner == nil {
		result.Banner = make(map[string]interface{})
	}
	result.URL = webResult.Target
	// 添加Banner信息到Metadata
	if webResult.Banner != nil {
		// 添加标题
		if webResult.Banner.Title != "" {
			result.Banner["title"] = webResult.Banner.Title
		}
		// 添加状态码
		if webResult.Banner.StatusCode > 0 {
			result.Banner["status_code"] = webResult.Banner.StatusCode
		}
		// 如果有HTTP响应体，添加到Metadata
		if webResult.Banner.Body != "" {
			result.Banner["body"] = webResult.Banner.Body
			result.Banner["body_length"] = len(webResult.Banner.Body)
		}
		if webResult.Banner.IconBytes != nil {
			result.Banner["icon"] = base64.StdEncoding.EncodeToString(webResult.Banner.IconBytes)
		}
		if webResult.Banner.Cert != nil {
			result.Certificate = types.FromTlsConnectionState(webResult.Banner.Cert)
			result.Certificate.RawData = webResult.Banner.Certificate
		}
		if webResult.Banner.Charset != "" {
			result.Banner["charset"] = webResult.Banner.Charset
		}
		if webResult.Banner.Header != "" {
			result.Banner["header"] = webResult.Banner.Header
		}
		if webResult.Banner.IconType != "" {
			result.Banner["icon_type"] = webResult.Banner.IconType
		}
		if webResult.Banner.IconHash > 0 {
			result.Banner["icon_hash"] = webResult.Banner.IconHash
		}
		if webResult.Banner.BodyHash > 0 {
			result.Banner["body_hash"] = webResult.Banner.BodyHash
		}
	}
	// 添加指纹信息
	if len(webResult.Components) > 0 {
		for _, component := range webResult.Components {
			// 创建新的map[string]interface{}
			componentInfo := make(map[string]interface{})
			componentInfo["name"] = component.Name
			// 复制其他属性
			for k, v := range component.Values {
				componentInfo[k] = v
			}
			if component.Rule != "" {
				componentInfo["rule"] = component.Rule
			}
			if component.URL != "" {
				componentInfo["url"] = component.URL
			}
			result.Components = append(result.Components, componentInfo)
		}
	}
}

// normalizeResult 标准化扫描结果
func (x *XMap) normalizeResult(result *types.ScanResult) {
	result.Protocol = result.Target.Protocol
	result.Hostname = result.Target.Host
	// 设置端口
	result.Port = result.Target.Port
	if result.IP == "" && result.Target.IP != "" {
		result.IP = result.Target.IP
	}
	if result.Extra != nil && len(result.Extra) > 0 {
		// fix product to name
		if name, ok := result.Extra["product"]; ok {
			result.Extra["name"] = name
			delete(result.Extra, "product")
			result.Components = append(result.Components, result.Extra)
		}
	}
	if result.Service == "http" && result.SSL {
		result.Service = "https"
	}
	// 设置原始响应数据
	if result.RawResponse != nil && len(result.RawResponse) > 0 {
		result.Banner["banner"] = base64.StdEncoding.EncodeToString(result.RawResponse)
	}
}

// ParseTargetsString 将目标字符串解析为ScanTarget切片
func (x *XMap) ParseTargetsString(targetsStr string) ([]*types.ScanTarget, error) {
	lines := strings.Split(targetsStr, "\n")
	targets := make([]*types.ScanTarget, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Keep the historical host:port/tcp notation while using the strict
		// parser for URL and IPv6 correctness.
		if slash := strings.LastIndex(line, "/"); slash > 0 && !strings.Contains(line, "://") {
			protocol := strings.ToLower(line[slash+1:])
			if protocol == "tcp" || protocol == "udp" {
				line = protocol + "://" + line[:slash]
			}
		}
		target, err := types.ParseTarget(line)
		if err != nil {
			return nil, err
		}
		targets = append(targets, target)
	}

	return targets, nil
}

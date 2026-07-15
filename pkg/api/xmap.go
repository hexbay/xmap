package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/hexbay/xmap/pkg/input"
	"github.com/hexbay/xmap/pkg/scanner"

	"github.com/hexbay/xmap/pkg/types"
	"github.com/hexbay/xmap/pkg/web"
	"github.com/projectdiscovery/gologger"
)

// ScannerConfig 扫描器配置接口
type ScannerConfig interface {
	GetOptions() *types.Options
}

// XMap 是核心扫描引擎，负责协调各种扫描器
type XMap struct {
	// 服务扫描器 - 负责基础网络服务探测
	serviceScanner *scanner.ServiceScanner
	// Web扫描器 - 负责Web应用指纹识别
	webScanner *web.Scanner
	// 配置选项
	options *types.Options
	// 初始化锁
	initOnce sync.Once
}

type semaphoreLimiter struct {
	sem chan struct{}
}

// NewLimiter creates a target-level concurrency limiter.
func NewLimiter(limit int) types.Limiter {
	if limit <= 0 {
		limit = 10
	}
	return &semaphoreLimiter{sem: make(chan struct{}, limit)}
}

func (l *semaphoreLimiter) Acquire(ctx context.Context) error {
	select {
	case l.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *semaphoreLimiter) Release() {
	select {
	case <-l.sem:
	default:
	}
}

// New 创建新的XMap实例
func New(options *types.Options) (*XMap, error) {
	// 创建XMap实例
	x := &XMap{
		options: options,
	}
	// 初始化扫描引擎
	err := x.init()
	return x, err
}

// NewWithLimiter creates a new XMap instance with a shared concurrency limiter.
func NewWithLimiter(options *types.Options, limiter types.Limiter) (*XMap, error) {
	if options == nil {
		options = types.DefaultOptions()
	}
	options.Limiter = limiter
	return New(options)
}

// init 初始化XMap扫描引擎
func (x *XMap) init() error {
	// 使用sync.Once确保只初始化一次
	var initErr error
	// 创建服务扫描器
	x.serviceScanner, initErr = scanner.NewServiceScanner(x.options)
	if initErr != nil {
		return initErr
	}
	// 初始化Web规则库
	_, initErr = InitWebRuleManager(x.options.AppFingerHome)
	if initErr != nil {
		return initErr
	}
	// 创建Web扫描器
	x.webScanner, initErr = web.NewScannerWithRuleProvider(x.options, webRuleManager.Snapshot)

	return initErr
}

// Scan 扫描单个目标
func (x *XMap) Scan(ctx context.Context, target *types.ScanTarget) (*types.ScanResult, error) {
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

		// 解析目标格式: IP:Port/Protocol
		parts := strings.Split(line, ":")
		if len(parts) < 1 {
			continue
		}

		host := parts[0]
		port := 0
		protocol := "tcp"

		if len(parts) > 1 {
			portProto := strings.Split(parts[1], "/")
			if len(portProto) > 0 {
				portStr := portProto[0]
				portInt, err := strconv.Atoi(portStr)
				if err == nil {
					port = portInt
				}
			}

			if len(portProto) > 1 {
				protocol = strings.ToLower(portProto[1])
			}
		}

		target := &types.ScanTarget{
			Host:     host,
			Port:     port,
			Protocol: protocol,
		}

		targets = append(targets, target)
	}

	return targets, nil
}

// ScanWithCallback 使用回调函数扫描多个目标
// 每完成一个目标的扫描就调用回调函数，适用于需要实时处理结果的场景
func (x *XMap) ScanWithCallback(ctx context.Context, targets input.Provider, callback func(*types.ScanResult)) error {
	return x.ScanWithCallbackWithLimiter(ctx, targets, callback, x.options.Limiter)
}

// ScanWithCallbackWithLimiter 使用可共享的限流器扫描多个目标。
// limiter 控制 target-level concurrency；每个 target 调用 Scan 前 acquire，完成后 release。
func (x *XMap) ScanWithCallbackWithLimiter(ctx context.Context, targets input.Provider, callback func(*types.ScanResult), limiter types.Limiter) error {
	// 设置默认并行数
	if x.options.Threads <= 0 {
		x.options.Threads = 10
	}
	if limiter == nil {
		limiter = NewLimiter(x.options.Threads)
	}
	// 创建上下文，支持取消
	scanCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	// 处理每个目标
	targets.Scan(func(target *types.ScanTarget) bool {
		if err := limiter.Acquire(scanCtx); err != nil {
			return false
		}
		// 添加到等待组
		wg.Add(1)
		// 为每个目标启动一个goroutine
		go func(target *types.ScanTarget) {
			defer func() {
				limiter.Release()
				wg.Done()
			}()
			// 检查上下文是否已取消
			if scanCtx.Err() != nil {
				x.handleScanError(callback, target, scanCtx.Err())
				return
			}
			// 执行扫描
			result, err := x.Scan(scanCtx, target)
			if err != nil {
				if result != nil {
					if callback != nil {
						callback(result)
					}
					return
				}
				x.handleScanError(callback, target, err)
				return
			}
			// 调用回调函数
			if callback != nil {
				callback(result)
			}
		}(target)

		return true // 继续处理下一个目标
	})

	// 等待所有扫描完成
	wg.Wait()
	return scanCtx.Err()
}

// handleScanError 处理扫描错误
func (x *XMap) handleScanError(callback func(*types.ScanResult), target *types.ScanTarget, err error) {
	if callback != nil {
		callback(&types.ScanResult{
			Target: target,
			Error:  err,
		})
	}
}

// GetOptions 获取选项
func (x *XMap) GetOptions() *types.Options {
	return x.options
}

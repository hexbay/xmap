package scanner

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hexbay/xmap/pkg/probe"
	"github.com/hexbay/xmap/pkg/types"
	"github.com/hexbay/xmap/pkg/utils"
)

// ServiceScanner 默认扫描器实现
type ServiceScanner struct {
	// 版本强度
	probeStore *probe.Store
	transport  Transport
	logger     Logger
	options    *types.Options
}

// NewServiceScanner 创建新的扫描器
func NewServiceScanner(options *types.Options) (*ServiceScanner, error) {
	return NewServiceScannerWithDependencies(options, nil, nil, nil)
}

// NewServiceScannerWithDependencies is the composition root for scanner I/O.
func NewServiceScannerWithDependencies(options *types.Options, transport Transport, limiter types.RateLimiter, logger Logger) (*ServiceScanner, error) {
	// 创建默认选项
	probeStore, err := probe.GetStoreWithOptions(options.NmapProneName, options.VersionIntensity, false)
	if err != nil {
		return nil, fmt.Errorf("create probe store failed: %v", err)
	}
	if transport == nil {
		transport, err = newDialerTransport()
		if err != nil {
			return nil, fmt.Errorf("create dialer failed: %w", err)
		}
	}
	transport = NewRateLimitedTransport(transport, limiter)
	if logger == nil {
		logger = noopLogger{}
	}
	return &ServiceScanner{
		probeStore: probeStore,
		transport:  transport,
		logger:     logger,
		options:    options,
	}, nil
}

// NewServiceScannerWithTransport constructs a scanner with a caller-owned
// transport. This supports custom DNS, proxies, network namespaces and test
// harnesses without exposing scanner internals.
func NewServiceScannerWithTransport(options *types.Options, transport Transport) (*ServiceScanner, error) {
	return NewServiceScannerWithDependencies(options, transport, nil, nil)
}

func (s *ServiceScanner) Close() error {
	if transport, ok := s.transport.(ClosableTransport); ok {
		return transport.Close()
	}
	return nil
}

// Scan 扫描单个目标
func (s *ServiceScanner) Scan(target *types.ScanTarget) (*types.ScanResult, error) {
	return s.ScanWithContext(context.Background(), target)
}

// ScanWithContext 带上下文的扫描
func (s *ServiceScanner) ScanWithContext(ctx context.Context, target *types.ScanTarget) (*types.ScanResult, error) {
	// 创建扫描结果
	result := types.NewScanResult(target)
	// 对探针进行排序，优先使用适合当前端口的探针
	probes := s.selectProbes(target.Protocol, target.Port, false)
	if len(probes) == 0 {
		err := errors.New("no suitable probes found for target")
		result.Complete(err)
		return result, err
	}
	s.logger.Debug(ctx, "scan started", "target", target.String())
	if s.options.MaxTimeout > 0 {
		// ctx 包裹
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.options.MaxTimeout)*time.Second)
		defer cancel()
	}

	// 执行扫描
	err := s.executeProbes(ctx, target, probes, false, result)
	if err != nil {
		s.logger.Error(ctx, err, "scan failed", "target", target.String())
	}
	if result.Service == "ssl" {
		certInfo, err := utils.ParseCertificatesFromServerHello(result.RawResponse)
		if err == nil {
			result.Certificate = certInfo
		}
		probes = s.selectProbes(target.Protocol, target.Port, true)
		if tlsErr := s.executeProbes(ctx, target, probes, true, result); tlsErr != nil {
			s.logger.Debug(ctx, "tls inner-service scan failed", "target", target.String(), "error", tlsErr)
			// A successful TLS outer-layer fingerprint remains a valid result even
			// when the encrypted application protocol cannot be identified.
			err = nil
		}
	}
	result.Complete(err)
	return result, err
}

// selectProbes keeps the scanner-facing compatibility wrapper around the pure
// planning component.
func (s *ServiceScanner) selectProbes(protocol string, port int, ssl bool) []*probe.Probe {
	return NewProbePlanner(s.probeStore, s.options.UseAllProbes).Plan(protocol, port, ssl)
}

// executeProbes 执行探针扫描
func (s *ServiceScanner) executeProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, useSSL bool, result *types.ScanResult) error {
	// 根据协议类型选择不同的处理逻辑
	switch target.Protocol {
	case "udp":
		return s.executeUDPProbes(ctx, target, probes, result)
	default: // TCP
		return s.executeTCPProbes(ctx, target, probes, useSSL, result)
	}
}

// executeUDPProbes 执行 UDP 探针扫描
func (s *ServiceScanner) executeUDPProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, result *types.ScanResult) error {
	// 对每个探针执行扫描
	observer := NewPortObserverEntry(target)
	for _, pb := range probes {
		if ext, reason := observer.IsTerminate(); ext && !s.options.UseAllProbes {
			return errors.New(reason)
		}
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 继续处理
		}
		// 执行 UDP 探针
		// UDP 不支持 SSL/TLS
		response, err := s.executeUDPProbeWithRetries(ctx, target, pb, result)
		observer.watch(response, err)
		fields := []any{"target", target.String(), "probe", pb.Name, "response_bytes", len(response)}
		if s.options.DebugResponse {
			fields = append(fields, "response", append([]byte(nil), response...))
		}
		s.logger.Debug(ctx, "probe response", fields...)
		if len(response) > 0 {
			matchResult, err := pb.Match(response)
			if err != nil {
				s.logger.Error(ctx, err, "probe match failed", "target", target.String(), "probe", pb.Name)
				continue
			}
			if matchResult != nil {
				// 设置服务信息
				result.Service = matchResult.Match.Service
				result.RawResponse = response
				result.MatchedProbe = pb.Name
				// 如果是通过回退匹配的，记录日志
				s.logger.Debug(ctx, "probe matched", "target", target.String(), "probe", pb.Name, "service", matchResult.Match.Service)

				// 设置额外信息
				if matchResult.VersionInfo != nil {
					if result.Extra == nil {
						result.Extra = make(map[string]interface{})
					}
					// 直接将 VersionInfo 中的键值对添加到 result.Extra 中
					for k, v := range matchResult.VersionInfo {
						result.Extra[k] = v
					}
				}
				return nil
			}
		}
	}
	return ErrNotMatched
}

// executeTCPProbes 执行 TCP 探针扫描
func (s *ServiceScanner) executeTCPProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, useSSL bool, result *types.ScanResult) error {
	// 对每个探针执行扫描
	observer := NewPortObserverEntry(target)
	scheduler := newTCPProbeScheduler(probes, s.options)
	for {
		pb, ok := scheduler.nextProbe()
		if !ok {
			break
		}
		// 处理错误
		if ext, reason := observer.IsTerminate(); ext && !s.options.UseAllProbes {
			return errors.New(reason)
		}
		// 检查上下文是否已取消
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			// 继续处理
		}
		// 执行 TCP 探针
		response, err := s.executeTCPProbeWithRetries(ctx, target, pb, useSSL, scheduler.remaining(), result)
		observer.watch(response, err)
		scheduler.observe(response, err)
		fields := []any{"target", target.String(), "probe", pb.Name, "tls", useSSL, "response_bytes", len(response)}
		if s.options.DebugResponse {
			fields = append(fields, "response", append([]byte(nil), response...))
		}
		s.logger.Debug(ctx, "probe response", fields...)
		if len(response) > 0 {
			matchResult, err := pb.Match(response)
			if err != nil {
				s.logger.Error(ctx, err, "probe match failed", "target", target.String(), "probe", pb.Name, "tls", useSSL)
				continue
			}
			// 如果匹配成功
			if matchResult != nil {
				s.logger.Debug(ctx, "probe matched", "target", target.String(), "probe", pb.Name, "service", matchResult.Match.Service, "tls", useSSL)
				// 如果是通过回退匹配的，记录日志
				// 设置服务信息
				result.Extra = matchResult.VersionInfo
				result.Service = matchResult.Match.Service
				result.RawResponse = response
				result.MatchedProbe = pb.Name
				result.SSL = useSSL
				return nil
			}
		}
	}
	// 如果没有匹配到任何服务
	return ErrNotMatched
}

func (s *ServiceScanner) executeTCPProbeWithRetries(ctx context.Context, target *types.ScanTarget, probe *probe.Probe, useSSL bool, budget time.Duration, result *types.ScanResult) ([]byte, error) {
	// A TCP read timeout means the peer accepted the connection but chose not
	// to speak this protocol. Repeating the identical payload is almost never
	// useful and was the source of 5s * (retries + 1) stalls per probe. Keep
	// retries for connection/write failures, where a transient network failure
	// is still plausible.
	return retryProbeUntil(ctx, s.options.Retries, func(err error) bool {
		return !errors.Is(err, ReadTimeoutError)
	}, func() ([]byte, error) {
		return s.executeTCPProbe(ctx, target, probe, useSSL, budget, result)
	})
}

// executeTCPProbe 执行 tcp 探针
func (s *ServiceScanner) executeTCPProbe(ctx context.Context, target *types.ScanTarget, probe *probe.Probe, useSSL bool, budget time.Duration, result *types.ScanResult) ([]byte, error) {
	// 创建连接超时上下文
	timeout := s.probeTimeout(probe)
	if budget > 0 && budget < timeout {
		timeout = budget
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 创建 TCP 连接
	conn, err := s.transport.Open(timeoutCtx, target, useSSL, timeout)
	if err != nil {
		return nil, ConnectionError
	}
	defer conn.Close()
	s.setResolvedIP(result, conn)

	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw, WritePolicy{Timeout: timeout})
	fields := []any{"target", target.String(), "probe", probe.Name, "tls", useSSL, "request_bytes", len(raw)}
	if s.options.DebugRequest {
		fields = append(fields, "request", append([]byte(nil), raw...))
	}
	s.logger.Debug(ctx, "probe sent", fields...)

	if err != nil {
		s.logger.Error(ctx, err, "probe write failed", "target", target.String(), "probe", probe.Name, "tls", useSSL)
		return nil, WriteDataError
	}
	response, err := conn.Read(ReadPolicy{OverallTimeout: timeout, IdleTimeout: 50 * time.Millisecond, MaxBytes: 4096})

	if len(response) > 0 {
		return response, nil
	}

	if err != nil {
		return response, classifyReadError(err)
	}
	return response, nil
}

// probeTimeout honors a probe's Nmap totalwaitms directive without allowing a
// custom fingerprint to exceed the user's configured timeout.
func (s *ServiceScanner) probeTimeout(pb *probe.Probe) time.Duration {
	timeout := time.Duration(s.options.Timeout) * time.Second
	if pb.TotalWaitMS > 0 && pb.TotalWaitMS < timeout {
		return pb.TotalWaitMS
	}
	return timeout
}

// executeUDPProbe 执行 UDP 探针
func (s *ServiceScanner) executeUDPProbe(ctx context.Context, target *types.ScanTarget, probe *probe.Probe, result *types.ScanResult) ([]byte, error) {
	// 创建连接超时上下文
	timeout := time.Duration(s.options.Timeout) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 创建 UDP 连接（UDP 不支持 SSL/TLS）
	conn, err := s.transport.Open(timeoutCtx, target, false, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	s.setResolvedIP(result, conn)

	// 发送探针数据
	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw, WritePolicy{Timeout: timeout / 2})
	fields := []any{"target", target.String(), "probe", probe.Name, "request_bytes", len(raw)}
	if s.options.DebugRequest {
		fields = append(fields, "request", append([]byte(nil), raw...))
	}
	s.logger.Debug(ctx, "probe sent", fields...)

	if err != nil {
		s.logger.Error(ctx, err, "probe write failed", "target", target.String(), "probe", probe.Name)
		return nil, err
	}

	// 读取响应（UDP 可能不会有响应，所以要特别处理）
	response, err := conn.Read(ReadPolicy{OverallTimeout: timeout / 2, MaxBytes: 4096, SingleRead: true})

	if len(response) > 0 {
		return response, nil
	}

	if err != nil {
		return response, classifyReadError(err)
	}

	return response, nil
}

func (s *ServiceScanner) executeUDPProbeWithRetries(ctx context.Context, target *types.ScanTarget, probe *probe.Probe, result *types.ScanResult) ([]byte, error) {
	return retryProbe(ctx, s.options.Retries, func() ([]byte, error) {
		return s.executeUDPProbe(ctx, target, probe, result)
	})
}

func (s *ServiceScanner) setResolvedIP(result *types.ScanResult, conn Session) {
	if result.IP == "" {
		result.IP = conn.RemoteIP()
	}
}

func retryProbe(ctx context.Context, retries int, run func() ([]byte, error)) ([]byte, error) {
	return retryProbeUntil(ctx, retries, func(error) bool { return true }, run)
}

func retryProbeUntil(ctx context.Context, retries int, shouldRetry func(error) bool, run func() ([]byte, error)) ([]byte, error) {
	if retries < 0 {
		retries = 0
	}
	attempts := retries + 1
	var lastResponse []byte
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		select {
		case <-ctx.Done():
			return lastResponse, ctx.Err()
		default:
		}

		response, err := run()
		if len(response) > 0 || err == nil {
			return response, err
		}
		lastResponse = response
		lastErr = err
		if !shouldRetry(err) {
			break
		}
	}
	return lastResponse, lastErr
}

// formatProbeData 格式化探针数据以便于日志输出
func formatProbeData(data []byte) string {
	if len(data) == 0 {
		return "<NULL>"
	}

	var result strings.Builder
	result.WriteString("b'")

	for _, b := range data {
		if b >= 32 && b <= 126 { // 可打印 ASCII 字符
			if b == '\\' || b == '\'' { // 转义反斜杠和单引号
				result.WriteByte('\\')
			}
			result.WriteByte(b)
		} else {
			// 特殊字符使用 \x 格式
			switch b {
			case '\n':
				result.WriteString("\\n")
			case '\r':
				result.WriteString("\\r")
			case '\t':
				result.WriteString("\\t")
			default:
				result.WriteString(fmt.Sprintf("\\x%02x", b))
			}
		}
	}

	result.WriteString("'")
	return result.String()
}

// replaceProbeRaw 替换探针原始数据中的占位符
func replaceProbeRaw(raw []byte, target *types.ScanTarget) []byte {
	var host string
	if target.Host != "" {
		host = target.Host
	} else {
		host = target.IP
	}
	return []byte(strings.ReplaceAll(string(raw), "{Host}", fmt.Sprintf("%s:%d", host, target.Port)))
}

// normalizeSMB2Frame keeps a probe's NetBIOS session-service length and its
// payload in agreement. SMB servers commonly reject a negotiate request when
// bytes remain after the declared frame; this also protects hand-authored
// service probes from accidental trailing escape sequences.

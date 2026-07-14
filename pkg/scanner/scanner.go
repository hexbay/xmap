package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/hexbay/xmap/pkg/probe"
	"github.com/hexbay/xmap/pkg/types"
	"github.com/hexbay/xmap/pkg/utils"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
)

// ServiceScanner 默认扫描器实现
type ServiceScanner struct {
	// 版本强度
	probeStore *probe.Store
	dialer     *fastdialer.Dialer
	options    *types.Options
}

// NewServiceScanner 创建新的扫描器
func NewServiceScanner(options *types.Options) (*ServiceScanner, error) {
	// 创建默认选项
	probeStore, err := probe.GetStoreWithOptions(options.NmapProneName, options.VersionIntensity, false)
	if err != nil {
		return nil, fmt.Errorf("create probe store failed: %v", err)
	}
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return nil, fmt.Errorf("create dialer failed: %v", err)
	}
	return &ServiceScanner{
		probeStore: probeStore,
		dialer:     dialer,
		options:    options,
	}, nil
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
	probes := s.probeStore.GetProbeForPort(target.Protocol, target.Port, false)
	if len(probes) == 0 {
		err := errors.New("no suitable probes found for target")
		result.Complete(err)
		return result, err
	}
	gologger.Debug().Msgf("start scan %s", target.String())
	if s.options.MaxTimeout > 0 {
		// ctx 包裹
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(s.options.MaxTimeout)*time.Second)
		defer cancel()
	}

	// 执行扫描
	err := s.executeProbes(ctx, target, probes, false, result)
	if err != nil {
		gologger.Debug().Msgf("TCP scan failed: %v", err)
	}
	if result.Service == "ssl" {
		certInfo, err := utils.ParseCertificatesFromServerHello(result.RawResponse)
		if err == nil {
			result.Certificate = certInfo
			gologger.Debug().Msgf("parse certificates from server hello success: %v", certInfo)
		}
		probes = s.probeStore.GetProbeForPort(target.Protocol, target.Port, true)
		err = s.executeProbes(ctx, target, probes, true, result)
		if err != nil {
			gologger.Debug().Msgf("SSL scan failed: %v", err)
		}
	}
	result.Complete(err)
	return result, err
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
		if ext, reason := observer.IsTerminate(); ext {
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
		response, err := s.executeUDPProbe(ctx, target, pb)
		observer.watch(response, err)
		if err != nil {
			if s.options.DebugResponse && len(response) > 0 {
				gologger.Print().Msgf("Read (%d bytes) for UDP probe %s on %s:%d:\n%s", len(response), pb.Name, target.IP, target.Port, formatProbeData(response))
			}
			if len(response) > 0 {
				matchResult, err := pb.Match(response)
				if err != nil {
					gologger.Debug().Msgf("匹配错误: %v", err)
					continue
				}
				if matchResult != nil {
					// 设置服务信息
					result.Service = matchResult.Match.Service
					result.RawResponse = response
					result.MatchedProbe = pb.Name
					// 如果是通过回退匹配的，记录日志
					if matchResult.IsFallback {
						gologger.Debug().Msgf("通过回退匹配成功: %s -> %s, 路径: %v",
							pb.Name, matchResult.Probe.Name, matchResult.FallbackPath)
					}

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
	}
	return nil
}

// executeTCPProbes 执行 TCP 探针扫描
func (s *ServiceScanner) executeTCPProbes(ctx context.Context, target *types.ScanTarget, probes []*probe.Probe, useSSL bool, result *types.ScanResult) error {
	// 对每个探针执行扫描
	observer := NewPortObserverEntry(target)
	for _, pb := range probes {
		// 处理错误
		if ext, reason := observer.IsTerminate(); ext {
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
		response, err := s.executeTCPProbe(ctx, target, pb, useSSL)
		observer.watch(response, err)
		if s.options.DebugResponse && len(response) > 0 {
			gologger.Print().Msgf("Read (%d bytes) for TCP probe %s on %s:%d:\n%s", len(response), pb.Name, target.IP, target.Port, formatProbeData(response))
		}
		if len(response) > 0 {
			matchResult, err := pb.Match(response)
			if err != nil {
				gologger.Debug().Msgf("匹配错误: %v", err)
				continue
			}
			// 如果匹配成功
			if matchResult != nil {
				if useSSL {
					gologger.Debug().Msgf("Matched probe %s on (ssl)%s://%s:%d", pb.Name, matchResult.Match.Service, target.IP, target.Port)
				} else {
					gologger.Debug().Msgf("Matched probe %s on %s://%s:%d", pb.Name, matchResult.Match.Service, target.IP, target.Port)
				}
				// 如果是通过回退匹配的，记录日志
				if matchResult.IsFallback {
					gologger.Debug().Msgf("通过回退匹配成功: %s -> %s, 路径: %v",
						pb.Name, matchResult.Probe.Name, matchResult.FallbackPath)
				}
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
	return errors.New("not matched")
}

// executeTCPProbe 执行 tcp 探针
func (s *ServiceScanner) executeTCPProbe(ctx context.Context, target *types.ScanTarget, probe *probe.Probe, useSSL bool) ([]byte, error) {
	// 创建连接超时上下文
	timeout := time.Duration(s.options.Timeout) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if s.options.DebugRequest {
		gologger.Debug().Msgf("Sending TCP probe %s to %s", probe.Name, target.Host)
	}

	// 创建 TCP 连接
	conn, err := s.createConnection(timeoutCtx, target, useSSL, timeout)
	if err != nil {
		return nil, ConnectionError
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw)
	if useSSL {
		gologger.Debug().Msgf("Send %s %d bytes to [ssl://%s:%d]", probe.Name, len(raw), target.Host, target.Port)
	} else {
		gologger.Debug().Msgf("Send %s %d bytes to [tcp://%s:%d]", probe.Name, len(raw), target.Host, target.Port)
	}

	if err != nil {
		gologger.Debug().Msgf("TCP write failed for [%s:%d]: %v", target.IP, target.Port, err)
		return nil, WriteDataError
	}
	response, err := s.readResponse(conn, timeout)

	// 检查是否是 SSL 探针
	isSSLProbe := strings.Contains(strings.ToLower(probe.Name), "ssl") || strings.Contains(strings.ToLower(probe.Name), "tls")

	// 如果是 SSL 探针且有响应数据，尝试直接从响应中解析证书
	if isSSLProbe && len(response) > 0 {
		// 尝试从响应数据中解析证书
		certInfo, certErr := utils.ParseCertificatesFromServerHello(response)
		if certErr == nil && certInfo != nil {
			// 如果成功解析到证书信息，将其保存到目标对象中
			// 将结构化证书信息保存到目标对象中
			target.Certificate = certInfo.CertInfo
			// 将可读性信息临时存储，稍后会在 executeTCPProbes 中将其添加到 result.Extra
			gologger.Debug().Msgf("成功从 SSL 探针响应数据中直接解析证书信息")
		}
	}

	if len(response) > 0 {
		return response, nil
	}

	if err != nil {
		gologger.Debug().Msgf("TCP read failed for [%s:%d]: %v", target.Host, target.Port, err)
		return response, ReadTimeoutError
	}
	return response, nil
}

// executeUDPProbe 执行 UDP 探针
func (s *ServiceScanner) executeUDPProbe(ctx context.Context, target *types.ScanTarget, probe *probe.Probe) ([]byte, error) {
	// 创建连接超时上下文
	timeout := time.Duration(s.options.Timeout) * time.Second
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if s.options.DebugRequest {
		gologger.Debug().Msgf("Sending UDP probe %s to %s", probe.Name, target.String())
	}
	// 创建 UDP 连接（UDP 不支持 SSL/TLS）
	conn, err := s.createConnection(timeoutCtx, target, false, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 从 UDP 连接中获取实际的远程 IP 地址
	if udpConn, ok := conn.(*net.UDPConn); ok {
		if remoteAddr, ok := udpConn.RemoteAddr().(*net.UDPAddr); ok {
			resolvedIP := remoteAddr.IP.String()
			if target.IP == "" {
				target.IP = resolvedIP
				gologger.Debug().Msgf("%s:%d", resolvedIP, target.Port)
			}
		}
	}

	// 设置读写超时（UDP 需要更短的超时，因为它是无连接的）
	_ = conn.SetDeadline(time.Now().Add(timeout / 2))

	// 发送探针数据
	raw := replaceProbeRaw(probe.SendData, target)
	_, err = conn.Write(raw)
	gologger.Debug().Msgf("Sent %d bytes to [udp://%s:%d]", len(raw), target.Host, target.Port)

	if err != nil {
		gologger.Debug().Msgf("UDP write failed for [%s:%d]: %v", target.Host, target.Port, err)
		return nil, err
	}

	// 读取响应（UDP 可能不会有响应，所以要特别处理）
	response, err := s.readResponse(conn, timeout/2)

	if len(response) > 0 {
		return response, nil
	}

	if err != nil {
		return response, err
	}

	return response, nil
}

// createConnection 创建网络连接
func (s *ServiceScanner) createConnection(ctx context.Context, target *types.ScanTarget, useSSL bool, timeout time.Duration) (net.Conn, error) {
	host := target.Host
	if host == "" {
		host = target.IP
	}
	address := fmt.Sprintf("%s:%d", host, target.Port)
	// 使用fastdialer处理连接
	var conn net.Conn
	var err error
	// 根据协议类型创建不同类型的连接
	var network string
	switch target.Protocol {
	case "udp":
		network = "udp"
	default:
		network = "tcp" // 默认使用 TCP
	}
	// 设置超时上下文
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// 检查是否需要 TLS 连接
	if useSSL {
		// 使用fastdialer的DialTLS方法进行TLS连接
		conn, err = s.dialer.DialTLS(dialCtx, network, address)
		if err != nil {
			return nil, err
		}
		// todo 获取证书
		// 获取目标IP
		if target.IP == "" && target.Host != "" {
			dnsData, err := s.dialer.GetDNSData(target.Host)
			if err == nil && dnsData != nil && len(dnsData.A) > 0 {
				target.IP = dnsData.A[0]
			}
		}
		return conn, nil
	}

	// 普通连接（TCP 或 UDP）
	conn, err = s.dialer.Dial(dialCtx, network, address)
	if err != nil {
		return nil, err
	}

	// 获取目标IP
	if target.IP == "" && target.Host != "" {
		dnsData, err := s.dialer.GetDNSData(target.Host)
		if err == nil && dnsData != nil && len(dnsData.A) > 0 {
			target.IP = dnsData.A[0]
			gologger.Debug().Msgf("Resolved %s IP %s", target.Host, target.IP)
		} else {
			// 如果无法从 DNS 获取数据，尝试从连接中获取
			if remoteAddr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
				target.IP = remoteAddr.IP.String()
				gologger.Debug().Msgf("从连接获取IP: %s", target.IP)
			}
		}
	}

	return conn, nil
}

// readResponse 从连接中读取响应数据
func (s *ServiceScanner) readResponse(conn net.Conn, timeout time.Duration) ([]byte, error) {
	var responseData []byte
	buffer := make([]byte, 1024)
	// 设置最大读取时间
	maxReadTime := time.Now().Add(timeout)
	for {
		// 检查是否超过最大读取时间
		if time.Now().After(maxReadTime) {
			// 如果已经读取到了一些数据，则返回这些数据
			if len(responseData) > 0 {
				return responseData, nil
			}
			// 否则返回超时错误
			return responseData, fmt.Errorf(fmt.Sprintf("max read timeout: %s", timeout.String()))
		}
		// 设置单次读取超时
		remainingTime := maxReadTime.Sub(time.Now())
		if remainingTime <= 0 {
			remainingTime = 2 * time.Second // 最小超时时间
		}
		_ = conn.SetReadDeadline(time.Now().Add(remainingTime))
		// 读取数据
		n, err := conn.Read(buffer)
		// 如果读取到数据，追加到响应中
		if n > 0 {
			responseData = append(responseData, buffer[:n]...)
			// 如果缓冲区未满，可能表示数据已经读取完毕
			if n < len(buffer) {
				break
			}
			// 如果响应数据已经足够大，停止读取
			if len(responseData) >= 4096 {
				break
			}
		}
		// 处理错误
		if err != nil {
			if errors.Is(err, io.EOF) {
				return responseData, err
			}
		}
	}
	return responseData, nil
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

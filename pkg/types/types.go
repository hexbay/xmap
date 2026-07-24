package types

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ScanStatus 扫描结果状态
type ScanStatus int

const (
	StatusUnknown ScanStatus = iota
	StatusMatched
	StatusNoMatch
	StatusError
	StatusClosed
	StatusInvalid    // 无效目标（如连续多次连接失败）
	StatusFirewalled // 可能被防火墙阻止
)

func (s ScanStatus) String() string {
	switch s {
	case StatusMatched:
		return "matched"
	case StatusNoMatch:
		return "no_match"
	case StatusError:
		return "error"
	case StatusClosed:
		return "closed"
	case StatusInvalid:
		return "invalid"
	case StatusFirewalled:
		return "firewalled"
	default:
		return "unknown"
	}
}

func (s ScanStatus) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ScanTarget 表示扫描目标
type ScanTarget struct {
	// Web 场景下的协议（http/https），与 Protocol (tcp/udp) 区分
	Scheme string `json:"-"`
	// 原始输入（用户提供的字符串）
	Raw string `json:"raw,omitempty"`
	// 解析后的信息
	Host     string `json:"host,omitempty"`     // 主机名或IP
	IP       string `json:"ip,omitempty"`       // IP地址
	Port     int    `json:"port,omitempty"`     // 端口
	Protocol string `json:"protocol,omitempty"` // 协议 (TCP/UDP)
	Path     string `json:"path,omitempty"`     // URL路径
	// 解析状态，不输出到JSON
	Parsed bool `json:"-"`
	// TLS证书，不输出到JSON
	TLSCertificates []*x509.Certificate `json:"-"`
	// 证书信息，用于临时存储解析的证书数据
	Certificate map[string]interface{} `json:"-"`
}

func NewTarget(raw string) *ScanTarget {
	target, err := ParseTarget(raw)
	if err == nil {
		return target
	}
	// Preserve the CLI's forgiving behavior while ParseTarget remains strict
	// for SDK callers that need validation errors.
	if !strings.Contains(raw, "://") && strings.Count(raw, ":") == 1 {
		host, _, _ := strings.Cut(raw, ":")
		return &ScanTarget{Raw: raw, Host: host, Port: 80, Protocol: "tcp", Parsed: true}
	}
	return &ScanTarget{Raw: raw, Host: raw, Port: 80, Protocol: "tcp", Parsed: false}
}

// ParseTarget parses TCP/UDP endpoints and HTTP URLs, including bracketed
// IPv6 addresses. It is the strict API intended for third-party callers.
func ParseTarget(raw string) (*ScanTarget, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty target")
	}
	target := &ScanTarget{Raw: raw, Protocol: "tcp"}
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" {
			return nil, fmt.Errorf("invalid target %q", raw)
		}
		switch strings.ToLower(u.Scheme) {
		case "http", "https":
			target.Scheme = strings.ToLower(u.Scheme)
		case "tcp", "udp":
			target.Protocol = strings.ToLower(u.Scheme)
		default:
			return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
		}
		target.Host = u.Hostname()
		target.Path = u.EscapedPath()
		if port := u.Port(); port != "" {
			value, err := strconv.Atoi(port)
			if err != nil || value < 1 || value > 65535 {
				return nil, fmt.Errorf("invalid port in %q", raw)
			}
			target.Port = value
		}
	} else {
		if host, port, err := net.SplitHostPort(raw); err == nil {
			target.Host = host
			value, err := strconv.Atoi(port)
			if err != nil || value < 1 || value > 65535 {
				return nil, fmt.Errorf("invalid port in %q", raw)
			}
			target.Port = value
		} else {
			target.Host = strings.Trim(raw, "[]")
		}
	}
	if target.Port == 0 {
		if target.Scheme == "https" {
			target.Port = 443
		} else {
			target.Port = 80
		}
	}
	if ip := net.ParseIP(target.Host); ip != nil {
		target.IP = ip.String()
	}
	target.Parsed = true
	return target, nil
}

// String 返回目标的字符串表示
func (t *ScanTarget) String() string {
	return fmt.Sprintf("%s:%d", t.Host, t.Port)
}

// ScanResult 表示扫描结果
type ScanResult struct {
	// 目标信息
	Target *ScanTarget `json:"-"`
	// Protocol
	Protocol string `json:"protocol"`
	// 主机名
	Hostname string `json:"hostname"` // 域名或IP
	Port     int    `json:"port"`
	IP       string `json:"ip,omitempty"` // 解析IP，可能为空
	// Web 扫描相关字段
	URL    string                 `json:"url,omitempty"`
	Banner map[string]interface{} `json:"banner,omitempty"`
	// 通用组件信息
	Components []map[string]interface{} `json:"components,omitempty"`
	// 服务名称
	Service string `json:"service"`
	// 是否使用SSL
	SSL bool `json:"ssl,omitempty"`
	// 证书信息
	Certificate *SSLResponse `json:"certificate,omitempty"`
	// 附加信息
	Extra       map[string]interface{} `json:"extra,omitempty"`
	RawResponse []byte                 `json:"raw_response,omitempty"`
	// 匹配的探针名称
	MatchedProbe string `json:"matched_probe"`
	// 匹配的正则表达式
	MatchedPattern string `json:"matched_pattern"`
	// 扫描耗时
	Duration float64 `json:"duration"`
	// 错误信息
	Error        error  `json:"-"`
	ErrorCode    string `json:"error_code,omitempty"`
	ErrorMessage string `json:"error_message,omitempty"`
	// 扫描状态
	Status    ScanStatus `json:"status"`
	startTime time.Time
	endTime   time.Time
}

// NewScanResult 创建新的扫描结果
func NewScanResult(target *ScanTarget) *ScanResult {
	return &ScanResult{
		Target:    target,
		startTime: time.Now(),
		IP:        target.IP,
		Port:      target.Port,
		Hostname:  target.Host,
		Protocol:  target.Protocol,
		Banner:    make(map[string]interface{}),
		Status:    StatusUnknown,
	}
}

// JSON 返回扫描结果的 JSON 字符串
func (r *ScanResult) JSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Complete 完成扫描结果
func (r *ScanResult) Complete(err error) {
	r.Error = err
	if err != nil {
		r.ErrorMessage = err.Error()
		switch {
		case errors.Is(err, context.Canceled):
			r.ErrorCode = "canceled"
		case errors.Is(err, context.DeadlineExceeded):
			r.ErrorCode = "deadline_exceeded"
		case err.Error() == "not matched":
			r.ErrorCode = "not_matched"
		default:
			r.ErrorCode = "scan_error"
		}
	}
	r.endTime = time.Now()
	r.Duration = r.endTime.Sub(r.startTime).Seconds()
	// 根据错误类型设置状态
	if err != nil && r.Service == "" {
		if err.Error() == "invalid target" {
			r.Status = StatusInvalid
		} else {
			r.Status = StatusError
		}
	} else if r.Service != "" {
		r.Status = StatusMatched
	} else {
		r.Status = StatusNoMatch
	}
	if r.Service == "ssl" || r.Service == "tls" {
		r.SSL = true
	}
}

// SetMatchResult 设置匹配结果
func (r *ScanResult) SetMatchResult(probeName, service, pattern string, softMatch bool) {
	r.MatchedProbe = probeName
	r.MatchedPattern = pattern
}

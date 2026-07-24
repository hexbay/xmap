package types

import (
	"context"

	"github.com/projectdiscovery/goflags"
)

const (
	DefaultMaxBodySize int64 = 512 * 1024
	DefaultMaxIconSize int64 = 128 * 1024
)

// Limiter controls target-level scan concurrency.
type Limiter interface {
	Acquire(ctx context.Context) error
	Release()
}

// Options 包含XMap全局初始化选项
type Options struct {
	// target
	Target     goflags.StringSlice
	TargetFile string
	Ports      string

	// scan
	// 扫描选项
	MaxTimeout int
	// ServiceProbeBudget is the maximum time spent identifying one open TCP
	// service in normal mode. Zero selects the scanner's adaptive default.
	ServiceProbeBudget int
	Timeout            int
	Retries            int
	HttpRetry          int
	Threads            int
	Limiter            Limiter
	FastMode           bool
	UseAllProbes       bool
	NmapProneName      string
	UseSSL             bool
	VersionIntensity   int
	ServiceVersion     bool // 是否探测服务版本
	VersionTrace       bool // 是否跟踪版本

	Silent     bool // 是否启用静默模式
	NoProgress bool // 是否不显示进度条

	// 网络选项
	Proxy string // 代理设置

	// 指纹库选项
	AppFingerHome string // 指纹库路径
	UpdateRule    bool   // 是否更新指纹规则
	Update        bool   // 是否更新xmap程序

	// Web扫描选项
	DisableIcon bool  // 禁用图标请求匹配
	DisableJS   bool  // 禁用JavaScript规则匹配
	MaxBodySize int64 // Web响应body最大读取字节数
	MaxIconSize int64 // 图标最大读取字节数

	// 其他选项
	EnablePprof bool // 是否启用性能分析

	// config
	Version bool   // 版本信息
	Banner  string // Banner信息
	// Debug
	Debug         bool
	DebugResponse bool // 是否打印响应数据
	DebugRequest  bool
	// output
	OutType    string // 输出格式
	Output     string // 输出文件路径
	OutputType string // 输出格式 (json, csv, console)

}

func DefaultOptions() *Options {
	return &Options{
		Timeout:            6,
		MaxTimeout:         180,
		ServiceProbeBudget: 10,
		Silent:             false,
		NoProgress:         false,
		OutputType:         "json",
		Banner:             "",
		VersionIntensity:   7,
		MaxBodySize:        DefaultMaxBodySize,
		MaxIconSize:        DefaultMaxIconSize,
	}
}

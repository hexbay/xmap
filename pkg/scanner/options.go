package scanner

import (
	"github.com/hexbay/xmap/pkg/types"
	"net/url"
	"time"
)

// ExecuteOptions 扫描选项
type ExecuteOptions struct {
	Options *types.Options
	// 单个端口识别最大超时时间
	MaxTimeout time.Duration
	// 超时时间 单个探针
	Timeout time.Duration
	// 版本检测强度(0-9)
	VersionIntensity int
	// 最大并行扫描数
	MaxParallelism int
	// 指定要使用的端口
	Ports []int
	// 是否使用所有探针
	UseAllProbes bool
	// 是否打印请求数据
	DebugRequest bool
	// 是否打印响应数据
	DebugResponse bool
	// 是否打印详细的调试信息
	Verbose bool
	Proxy   *url.URL
}

// DefaultScanOptions 返回默认扫描选项
func DefaultScanOptions() *ExecuteOptions {
	return &ExecuteOptions{
		Options: types.DefaultOptions(),
		
		Timeout:          6 * time.Second,
		VersionIntensity: 7,
		MaxParallelism:   100,
		UseAllProbes:     false,
		DebugRequest:     false,
		DebugResponse:    false,
		Verbose:          false,
	}
}

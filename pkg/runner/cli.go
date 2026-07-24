package runner

import (
	"fmt"
	"github.com/hexbay/xmap/pkg/types"
	"github.com/projectdiscovery/goflags"
	"os"
)

// Version 版本信息，由 release workflow 通过 ldflags 注入。
var Version = "dev"

// Banner 程序的banner
var Banner = fmt.Sprintf(`
__  ____  ___           
\ \/ /  \/  / __ _ _ __  
 \  /| |\/| |/ _' | '_ \ 
 /  \| |  | | (_| | |_) |
/_/\_\_|  |_|\__,_| .__/ 
                  |_|    %s
`, Version)

// ParseOptions 解析命令行选项
func ParseOptions() (*types.Options, error) {
	options := types.DefaultOptions()
	maxBodySize := goflags.Size(options.MaxBodySize)
	maxIconSize := goflags.Size(options.MaxIconSize)
	// 设置版本和banner
	options.Banner = Banner
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("XMap - 一个快速可靠的网络扫描和指纹识别工具")
	// 创建目标参数组
	flagSet.CreateGroup("目标", "目标设置",
		flagSet.StringSliceVarP(&options.Target, "target", "t", goflags.StringSlice{}, "扫描目标，格式: ip:port 或 ip (使用默认端口)", goflags.Options{}),
		flagSet.StringVarP(&options.TargetFile, "target-file", "l", "", "包含扫描目标的文件，每行一个目标"),
		flagSet.StringVarP(&options.Ports, "ports", "p", "80,443,8080", "要扫描的端口，逗号分隔"),
	)
	// 创建扫描选项组
	flagSet.CreateGroup("扫描", "扫描选项",
		flagSet.IntVar(&options.Timeout, "timeout", 5, "扫描超时时间(秒)"),
		flagSet.IntVar(&options.MaxTimeout, "max-timeout", 180, "最大扫描超时时间(秒)"),
		flagSet.IntVar(&options.ServiceProbeBudget, "service-probe-budget", 10, "单个TCP服务版本识别的时间预算(秒)"),
		flagSet.IntVarP(&options.Retries, "retries", "r", 2, "扫描重试次数"),
		flagSet.IntVarP(&options.Threads, "threads", "c", 64, "最大并行扫描数"),
		flagSet.BoolVarP(&options.FastMode, "fast", "f", false, "使用快速模式"),
		flagSet.BoolVar(&options.UseAllProbes, "all-probes", false, "使用所有探针（包括与端口无关的通用探针，速度较慢）"),
		flagSet.StringVarP(&options.NmapProneName, "probes", "np", "", "要使用的探针名称"),
		flagSet.BoolVar(&options.UseSSL, "ssl", false, "使用SSL"),
		flagSet.IntVar(&options.VersionIntensity, "version-intensity", 7, "版本检测强度(0-9)"),
		flagSet.BoolVarP(&options.ServiceVersion, "service-version", "sv", true, "显示服务版本"),
		flagSet.BoolVar(&options.VersionTrace, "version-trace", false, "跟踪版本检测过程"),
	)

	// 创建Web扫描选项组
	flagSet.CreateGroup("Web扫描", "Web扫描选项",
		flagSet.StringVarP(&options.AppFingerHome, "fingerprint-path", "d", "", "指纹库路径，默认使用内置路径"),

		flagSet.StringVarP(&options.Proxy, "proxy", "x", "", "HTTP代理，格式: http://host:port"),
		flagSet.BoolVarP(&options.DisableIcon, "disable-icon", "di", false, "禁用图标请求匹配"),
		flagSet.BoolVarP(&options.DisableJS, "disable-js", "dj", false, "禁用JavaScript规则匹配"),
		flagSet.SizeVar(&maxBodySize, "max-body-size", "512kb", "Web响应body最大读取大小，支持 kb/mb/gb"),
		flagSet.SizeVar(&maxIconSize, "max-icon-size", "128kb", "图标最大读取大小，支持 kb/mb/gb"),
	)
	// Debug
	flagSet.CreateGroup("Debug", "Debug选项",
		flagSet.BoolVar(&options.EnablePprof, "pprof", false, "启用pprof"),
		flagSet.BoolVar(&options.Debug, "debug", false, "启用调试模式"),
		flagSet.BoolVar(&options.DebugResponse, "debug-resp", false, "显示响应体"),
		flagSet.BoolVar(&options.DebugRequest, "debug-req", false, "显示请求体"),
	)

	// 创建输出选项组
	flagSet.CreateGroup("输出", "输出选项",
		flagSet.StringVarP(&options.Output, "output", "o", "", "输出结果到文件"),
		flagSet.StringVarP(&options.OutType, "output-type", "ot", "json", "输出格式 (json, csv, console)"),
		flagSet.BoolVarP(&options.Silent, "silent", "s", false, "静默模式"),
		flagSet.BoolVar(&options.NoProgress, "no-progress", false, "不显示进度条"),
	)

	// 创建其他选项组
	flagSet.CreateGroup("其他", "其他选项",
		flagSet.BoolVar(&options.Update, "update", false, "更新xmap到最新版本"),
		flagSet.BoolVarP(&options.UpdateRule, "update-rule", "ur", false, "更新指纹规则库"),
		flagSet.BoolVarP(&options.Version, "version", "V", false, "显示版本信息"),
		flagSet.BoolVar(&options.EnablePprof, "enable-pprof", false, "启用性能分析"),
	)

	// 解析命令行参数
	if err := flagSet.Parse(); err != nil {
		return nil, fmt.Errorf("解析命令行参数失败: %v", err)
	}
	// 显示版本信息
	if options.Version {
		fmt.Printf("XMap 版本: %s\n", Version)
		os.Exit(0)
	}
	options.MaxBodySize = int64(maxBodySize)
	options.MaxIconSize = int64(maxIconSize)
	return options, nil
}

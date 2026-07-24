package runner

import (
	"context"
	"fmt"
	"github.com/hexbay/xmap/pkg/api"
	"github.com/hexbay/xmap/pkg/input"
	"github.com/hexbay/xmap/pkg/output"
	"github.com/hexbay/xmap/pkg/types"
	"github.com/hexbay/xmap/pkg/utils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"os"
	"os/signal"
)

// Runner 结构体专注于命令行界面和用户交互
type Runner struct {
	// 全局选项
	options *types.Options
	// XMap API 实例
	xmap *api.XMap
}

// New 创建一个新的Runner实例
func New(options *types.Options) (*Runner, error) {
	// 初始化日志
	configureLogger(options)

	// 创建 XMap 实例
	xmapInstance, err := api.NewEngine(api.EngineConfig{Options: options})
	if err != nil {
		return nil, err
	}

	// 创建并返回 Runner 实例
	return &Runner{
		options: options,
		xmap:    xmapInstance,
	}, nil
}

// configureLogger 配置日志级别
func configureLogger(options *types.Options) {
	if options.Debug {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)
	} else {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	}
	if options.Silent {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	}
}

// ShowBanner 显示程序的banner
func (r *Runner) ShowBanner() {
	if !r.options.Silent {
		fmt.Print(r.options.Banner)
	}
}

// RunEnumeration 执行扫描
func (r *Runner) RunEnumeration() error {
	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 处理中断信号
	setupInterruptHandler(cancel)
	// 创建输出处理器
	outputHandler, err := setupOutputHandlers(r.options)
	if err != nil {
		return err
	}
	defer outputHandler.Close()
	// 创建进度跟踪器
	var progressTracker *utils.Progress
	if !r.options.Silent && !r.options.NoProgress {
		// TODO: 实现进度跟踪器
		// progressTracker = utils.NewProgress()
		// go progressTracker.Start()
	}
	// 创建输入提供者
	inputProvider, err := input.CreateProviderFromOptions(r.options)
	if err != nil {
		return fmt.Errorf("create input provider failed: %v", err)
	}
	var targets []*types.ScanTarget
	inputProvider.Scan(func(target *types.ScanTarget) bool {
		targets = append(targets, target)
		return true
	})
	for event := range r.xmap.ScanMany(ctx, targets) {
		if event.Result == nil {
			continue
		}
		if progressTracker != nil {
			progressTracker.Increment()
		}
		outputHandler.HandleResult(event.Result)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("扫描失败: %w", err)
	}
	return nil
}

// setupInterruptHandler 设置中断信号处理
func setupInterruptHandler(cancel context.CancelFunc) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt)
	go func() {
		<-signalChan
		cancel()
	}()
}

// OutputHandler 输出处理器
type OutputHandler struct {
	consoleOutput output.Outer
	fileOutput    output.Outer
}

// HandleResult 处理扫描结果
func (h *OutputHandler) HandleResult(result *types.ScanResult) {
	// 控制台输出
	if h.consoleOutput != nil {
		outputErr := h.consoleOutput.Output(result)
		if outputErr != nil {
			gologger.Error().Msgf("控制台输出失败: %v", outputErr)
		}
	}

	// 文件输出
	if h.fileOutput != nil {
		fileErr := h.fileOutput.Output(result)
		if fileErr != nil {
			gologger.Error().Msgf("文件输出失败: %v", fileErr)
		}
	}
}

// Close flushes and closes output resources that need explicit cleanup.
func (h *OutputHandler) Close() {
	for _, outer := range []output.Outer{h.consoleOutput, h.fileOutput} {
		if closer, ok := outer.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				gologger.Error().Msgf("关闭输出失败: %v", err)
			}
		}
	}
}

// setupOutputHandlers 设置输出处理器
func setupOutputHandlers(options *types.Options) (*OutputHandler, error) {
	handler := &OutputHandler{
		consoleOutput: output.NewConsoleOuter("", options.Silent),
	}

	// 创建文件输出器（如果需要）
	if options.Output != "" {
		switch options.OutputType {
		case "json":
			handler.fileOutput = output.NewJSONOuter(options.Output)
		case "csv":
			handler.fileOutput = output.NewCSVOuter(options.Output)
		default:
			handler.fileOutput = output.NewConsoleOuter(options.Output, false) // 文件输出不需要静默模式
		}
	}

	return handler, nil
}

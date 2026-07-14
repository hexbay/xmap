package main

import (
	"context"
	"fmt"
	"github.com/hexbay/xmap/pkg/api"
	"os"

	"github.com/hexbay/xmap/pkg/runner"
	"github.com/hexbay/xmap/pkg/updater"
	"github.com/projectdiscovery/gologger"
)

func main() {
	// 创建 runner
	options, err := runner.ParseOptions()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if options.Update {
		if err := updater.UpdateToLatest(context.Background(), runner.Version); err != nil {
			gologger.Fatal().Msgf("更新xmap失败: %v", err)
		}
		return
	}
	xmapRunner, err := runner.New(options)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	// 显示 banner
	xmapRunner.ShowBanner()
	// 更新指纹规则库
	if options.UpdateRule {
		err = api.UpdateWebRules()
		if err != nil {
			gologger.Fatal().Msgf("更新指纹规则库失败: %v", err)
		}
		return
	}
	// 执行扫描
	err = xmapRunner.RunEnumeration()
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}
}

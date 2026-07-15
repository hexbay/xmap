package api

import (
	"context"
	"fmt"

	"github.com/hexbay/appfinger/pkg/external/customrules"
	"github.com/hexbay/appfinger/pkg/rule"
	"github.com/projectdiscovery/gologger"
)

var webRuleManager = rule.NewManager()

// InitWebRuleManager 初始化Web指纹规则管理器
func InitWebRuleManager(fingerprintsPath string) (*rule.RuleSet, error) {
	// 检查规则库是否已加载
	if webRuleManager.IsLoaded() {
		gologger.Debug().Msgf("Web指纹库已加载，上次加载时间: %s", webRuleManager.GetLastLoadTime().Format("2006-01-02 15:04:05"))
		return webRuleManager.GetRuleSet(), nil
	}
	// 如果未指定指纹库路径，使用默认路径
	if fingerprintsPath == "" {
		var err error
		fingerprintsPath, err = customrules.EnsureDefaultDirectory(context.Background())
		if err != nil {
			return nil, fmt.Errorf("初始化默认Web指纹库失败: %v", err)
		}
	}
	// 加载指定路径的指纹库
	if err := webRuleManager.LoadRules(fingerprintsPath); err != nil {
		return nil, fmt.Errorf("加载Web指纹库失败: %v", err)
	}
	return webRuleManager.GetRuleSet(), nil
}

// ReloadWebRules 重新加载Web指纹库规则
func ReloadWebRules() error {
	return webRuleManager.ReloadRules()
}

// UpdateWebRules 从远程更新Web指纹库规则
func UpdateWebRules() error {
	gologger.Info().Msg("正在从远程更新Web指纹库规则...")
	// 直接使用git拉取最新规则
	rulesDir := customrules.GetDefaultDirectory()
	gologger.Info().Msgf("Web指纹库路径: %s", rulesDir)
	customrules.DefaultProvider.Update(context.Background(), rulesDir)
	// 重新加载规则
	return ReloadWebRules()
}

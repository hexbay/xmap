package input

import (
	"errors"
	"fmt"
	"github.com/hexbay/xmap/pkg/types"
	"os"
	"path/filepath"
)

// Provider 定义了输入提供者接口
type Provider interface {
	// Count 返回输入项的总数
	Count() int
	// Scan 扫描所有输入项
	Scan(callback func(value *types.ScanTarget) bool)
	// Close 关闭输入提供者
	Close()
}

// SimpleInputProvider 是一个简单的输入提供者实现
type SimpleInputProvider struct {
	inputs []*types.ScanTarget
}

// NewSimpleInputProvider 创建一个新的简单输入提供者
func NewSimpleInputProvider(inputs []*types.ScanTarget) *SimpleInputProvider {
	return &SimpleInputProvider{inputs: inputs}
}

// Count 返回输入项的总数
func (s *SimpleInputProvider) Count() int {
	return len(s.inputs)
}

// Scan 扫描所有输入项
func (s *SimpleInputProvider) Scan(callback func(value *types.ScanTarget) bool) {
	for _, input := range s.inputs {
		if !callback(input) {
			break
		}
	}
}

// Close 关闭输入提供者
func (s *SimpleInputProvider) Close() {
	// 简单实现不需要关闭任何资源
}

// MultiInputProvider 是一个多输入提供者实现
type MultiInputProvider struct {
	providers []Provider
	count     int
}

// NewMultiInputProvider 创建一个新的多输入提供者
func NewMultiInputProvider(providers ...Provider) *MultiInputProvider {
	count := 0
	for _, provider := range providers {
		count += provider.Count()
	}

	return &MultiInputProvider{
		providers: providers,
		count:     count,
	}
}

// Count 返回输入项的总数
func (m *MultiInputProvider) Count() int {
	return m.count
}

// Scan 扫描所有输入项
func (m *MultiInputProvider) Scan(callback func(value *types.ScanTarget) bool) {
	for _, provider := range m.providers {
		provider.Scan(callback)
	}
}

// Close 关闭输入提供者
func (m *MultiInputProvider) Close() {
	for _, provider := range m.providers {
		provider.Close()
	}
}

// CreateProviderFromOptions 从选项创建输入提供者
func CreateProviderFromOptions(options *types.Options) (Provider, error) {
	var providers []Provider
	// 处理命令行目标
	if len(options.Target) > 0 {
		targets := make([]*types.ScanTarget, 0, len(options.Target))
		for _, target := range options.Target {
			targets = append(targets, types.NewTarget(target))
		}
		providers = append(providers, NewSimpleInputProvider(targets))
	}
	// 处理目标文件
	if options.TargetFile != "" {
		absPath, err := filepath.Abs(options.TargetFile)
		if err != nil {
			return nil, fmt.Errorf("无法获取目标文件的绝对路径: %v", err)
		}

		fileInfo, err := os.Stat(absPath)
		if err != nil {
			return nil, fmt.Errorf("无法获取目标文件信息: %v", err)
		}

		if fileInfo.IsDir() {
			return nil, fmt.Errorf("目标文件不能是目录: %s", absPath)
		}

		fileProvider, err := NewFileInputProvider(absPath)
		if err != nil {
			return nil, fmt.Errorf("无法创建文件输入提供者: %v", err)
		}

		providers = append(providers, fileProvider)
	}

	if len(providers) == 0 {
		return nil, errors.New("未指定任何输入源")
	}

	if len(providers) == 1 {
		return providers[0], nil
	}

	return NewMultiInputProvider(providers...), nil
}

func FromSliceString(targets []string) Provider {
	input := &SimpleInputProvider{}
	for _, target := range targets {
		input.inputs = append(input.inputs, types.NewTarget(target))
	}
	return input
}

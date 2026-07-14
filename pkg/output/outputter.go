package output

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/gologger"

	"github.com/hexbay/xmap/pkg/types"
)

// Outer 定义结果输出接口
type Outer interface {
	// Output 输出扫描结果
	Output(results *types.ScanResult) error
}

// ConsoleOuter 控制台输出实现
type ConsoleOuter struct {
	OutputFile string
	Silent     bool

	// 文件写入相关
	file   *os.File
	writer *bufio.Writer
	mutex  *sync.Mutex
}

// NewConsoleOuter 创建一个新的控制台输出器
func NewConsoleOuter(outputFile string, silent bool) *ConsoleOuter {
	outer := &ConsoleOuter{
		OutputFile: outputFile,
		Silent:     silent,
		mutex:      &sync.Mutex{},
	}

	// 如果指定了输出文件，初始化文件写入器
	if outputFile != "" {
		// 使用 O_TRUNC 模式，如果文件存在则先清空
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			outer.file = file
			outer.writer = bufio.NewWriter(file)
		} else {
			gologger.Error().Msgf("Could not create output file '%s': %s", outputFile, err)
		}
	}

	return outer
}

// Output 实现Outer接口
func (o *ConsoleOuter) Output(results *types.ScanResult) error {
	if o.Silent {
		return nil
	}

	// 格式化组件信息
	var componentsList []string
	for _, component := range results.Components {
		// 格式化单个组件
		componentStr := formatComponent(component)
		if componentStr != "" {
			componentsList = append(componentsList, componentStr)
		}
	}
	componentsStr := strings.Join(componentsList, aurora.Gray(12, " │ ").String())

	// 构建目标URL
	targetURL := fmt.Sprintf("%s://%s:%d", results.Service, results.Target.Host, results.Target.Port)

	// 构建输出字符串
	var outputParts []string

	// URL部分 - 使用亮绿色
	outputParts = append(outputParts, aurora.BrightGreen(targetURL).String())

	// 组件信息 - 如果有的话
	if componentsStr != "" {
		outputParts = append(outputParts, componentsStr)
	}

	// 标题 - 使用白色加粗
	if title, ok := results.Banner["title"]; ok {
		outputParts = append(outputParts, aurora.Bold(aurora.White(fmt.Sprintf("[%s]", title))).String())
	}

	// 状态码 - 根据状态码使用不同颜色并添加描述
	if statusCode, ok := results.Banner["status_code"]; ok {
		statusInt, _ := statusCode.(int)
		statusText := getStatusText(statusInt)
		var statusStr string
		switch {
		case statusInt >= 200 && statusInt < 300:
			statusStr = aurora.BrightGreen(fmt.Sprintf("[%d %s]", statusInt, statusText)).String()
		case statusInt >= 300 && statusInt < 400:
			statusStr = aurora.BrightYellow(fmt.Sprintf("[%d %s]", statusInt, statusText)).String()
		case statusInt >= 400 && statusInt < 500:
			statusStr = aurora.BrightRed(fmt.Sprintf("[%d %s]", statusInt, statusText)).String()
		case statusInt >= 500:
			statusStr = aurora.Red(fmt.Sprintf("[%d %s]", statusInt, statusText)).String()
		default:
			statusStr = aurora.Gray(12, fmt.Sprintf("[%d %s]", statusInt, statusText)).String()
		}
		outputParts = append(outputParts, statusStr)
	}

	// 响应长度 - 使用青色,并格式化为易读的大小
	if bodyLength, ok := results.Banner["body_length"]; ok {
		lengthInt, _ := bodyLength.(int)
		sizeStr := formatSize(lengthInt)
		outputParts = append(outputParts, aurora.Cyan(fmt.Sprintf("[%s]", sizeStr)).String())
	} else if body, ok := results.Banner["body"]; ok {
		// 如果有body但没有body_length,计算长度
		if bodyStr, ok := body.(string); ok {
			sizeStr := formatSize(len(bodyStr))
			outputParts = append(outputParts, aurora.Cyan(fmt.Sprintf("[%s]", sizeStr)).String())
		}
	}

	// 耗时 - 使用蓝色
	durationStr := formatDuration(results.Duration)
	outputParts = append(outputParts, aurora.Blue(fmt.Sprintf("[%s]", durationStr)).String())

	outputStr := strings.Join(outputParts, " ")
	// 如果有输出文件，写入文件
	if o.file != nil && o.writer != nil {
		o.mutex.Lock()
		defer o.mutex.Unlock()

		// 写入到缓冲区
		_, err := o.writer.WriteString(outputStr + "\n")
		if err != nil {
			return err
		}

		// 立即刷新缓冲区到文件
		err = o.writer.Flush()
		if err != nil {
			return err
		}
	} else {
		// 输出到控制台
		fmt.Println(outputStr)
	}

	return nil
}

// Close 关闭输出器
func (o *ConsoleOuter) Close() error {
	if o.file != nil {
		// 先刷新缓冲区
		if o.writer != nil {
			o.mutex.Lock()
			err := o.writer.Flush()
			o.mutex.Unlock()
			if err != nil {
				return err
			}
		}

		// 关闭文件
		err := o.file.Close()
		o.file = nil
		o.writer = nil
		return err
	}
	return nil
}

// JSONOuter JSON输出实现
type JSONOuter struct {
	OutputFile string

	// 文件写入相关
	file   *os.File
	writer *bufio.Writer
	mutex  *sync.Mutex
}

// NewJSONOuter 创建一个新的JSON输出器
func NewJSONOuter(outputFile string) *JSONOuter {
	outer := &JSONOuter{
		OutputFile: outputFile,
		mutex:      &sync.Mutex{},
	}

	// 如果指定了输出文件，初始化文件写入器
	if outputFile != "" {
		// 使用 O_TRUNC 模式，如果文件存在则先清空
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			outer.file = file
			outer.writer = bufio.NewWriter(file)
		} else {
			gologger.Error().Msgf("Could not create output file '%s': %s", outputFile, err)
		}
	}

	return outer
}

// Output 实现Outputter接口
func (o *JSONOuter) Output(results *types.ScanResult) error {
	// 获取JSON字符串
	jsonStr := results.JSON() + "\n"

	// 如果有输出文件，写入文件
	if o.file != nil && o.writer != nil {
		o.mutex.Lock()
		defer o.mutex.Unlock()

		// 写入到缓冲区
		_, err := o.writer.WriteString(jsonStr)
		if err != nil {
			return err
		}

		// 立即刷新缓冲区到文件
		err = o.writer.Flush()
		if err != nil {
			return err
		}
	} else {
		// 输出到控制台
		fmt.Print(jsonStr)
	}

	return nil
}

// Close 关闭输出器
func (o *JSONOuter) Close() error {
	if o.file != nil {
		// 先刷新缓冲区
		if o.writer != nil {
			o.mutex.Lock()
			err := o.writer.Flush()
			o.mutex.Unlock()
			if err != nil {
				return err
			}
		}

		// 关闭文件
		err := o.file.Close()
		o.file = nil
		o.writer = nil
		return err
	}
	return nil
}

// CSVOuter CSV输出实现
type CSVOuter struct {
	OutputFile string
	file       *os.File
	writer     *csv.Writer
	mutex      *sync.Mutex
	wroteHead  bool
}

// NewCSVOuter 创建一个新的CSV输出器
func NewCSVOuter(outputFile string) *CSVOuter {
	outer := &CSVOuter{
		OutputFile: outputFile,
		mutex:      &sync.Mutex{},
	}

	if outputFile != "" {
		file, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err == nil {
			outer.file = file
			outer.writer = csv.NewWriter(file)
		} else {
			gologger.Error().Msgf("Could not create output file '%s': %s", outputFile, err)
		}
	} else {
		outer.writer = csv.NewWriter(os.Stdout)
	}

	return outer
}

// Output 实现Outer接口
func (o *CSVOuter) Output(results *types.ScanResult) error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.writer == nil {
		return fmt.Errorf("csv writer is not initialized")
	}
	if !o.wroteHead {
		if err := o.writer.Write([]string{"IP", "Port", "Protocol", "Service", "MatchedProbe", "Components", "Duration"}); err != nil {
			return err
		}
		o.wroteHead = true
	}
	if err := o.writer.Write([]string{
		results.IP,
		fmt.Sprintf("%d", results.Port),
		results.Protocol,
		results.Service,
		results.MatchedProbe,
		ComponentsToString(results.Components),
		fmt.Sprintf("%.6f", results.Duration),
	}); err != nil {
		return err
	}
	o.writer.Flush()
	return o.writer.Error()
}

// Close 关闭输出器
func (o *CSVOuter) Close() error {
	o.mutex.Lock()
	defer o.mutex.Unlock()

	if o.writer != nil {
		o.writer.Flush()
		if err := o.writer.Error(); err != nil {
			return err
		}
	}
	if o.file != nil {
		err := o.file.Close()
		o.file = nil
		o.writer = nil
		return err
	}
	return nil
}

// truncateString 截断字符串
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func ComponentsToString(components []map[string]interface{}) string {
	var result string
	for i, component := range components {
		if i > 0 {
			result += ", "
		}

		name, hasName := component["name"]
		version, hasVersion := component["version"]

		if hasName {
			result += fmt.Sprintf("%v", name)
			if hasVersion {
				result += fmt.Sprintf(" %v", version)
			}
		}
	}
	return result
}

// formatSize 格式化文件大小为易读格式
func formatSize(bytes int) string {
	const (
		KB = 1024
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.2fGB", float64(bytes)/float64(GB))
	case bytes >= MB:
		return fmt.Sprintf("%.2fMB", float64(bytes)/float64(MB))
	case bytes >= KB:
		return fmt.Sprintf("%.2fKB", float64(bytes)/float64(KB))
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}

// formatDuration 格式化耗时为易读格式
func formatDuration(seconds float64) string {
	switch {
	case seconds >= 1.0:
		return fmt.Sprintf("%.2fs", seconds)
	case seconds >= 0.001:
		ms := seconds * 1000
		if ms >= 10 {
			return fmt.Sprintf("%.0fms", ms)
		}
		return fmt.Sprintf("%.1fms", ms)
	case seconds > 0:
		us := seconds * 1000000
		if us >= 10 {
			return fmt.Sprintf("%.0fμs", us)
		}
		return fmt.Sprintf("%.1fμs", us)
	default:
		// 如果耗时为0或负数,显示为 < 1μs
		return "<1μs"
	}
}

// getStatusText 获取HTTP状态码描述
func getStatusText(statusCode int) string {
	switch statusCode {
	// 2xx Success
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 202:
		return "Accepted"
	case 204:
		return "No Content"
	// 3xx Redirection
	case 301:
		return "Moved Permanently"
	case 302:
		return "Found"
	case 304:
		return "Not Modified"
	// 4xx Client Error
	case 400:
		return "Bad Request"
	case 401:
		return "Unauthorized"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 405:
		return "Method Not Allowed"
	// 5xx Server Error
	case 500:
		return "Internal Server Error"
	case 502:
		return "Bad Gateway"
	case 503:
		return "Service Unavailable"
	case 504:
		return "Gateway Timeout"
	default:
		// 对于其他状态码,返回通用描述
		switch {
		case statusCode >= 200 && statusCode < 300:
			return "Success"
		case statusCode >= 300 && statusCode < 400:
			return "Redirect"
		case statusCode >= 400 && statusCode < 500:
			return "Client Error"
		case statusCode >= 500:
			return "Server Error"
		default:
			return "Unknown"
		}
	}
}

// formatComponent 格式化单个组件信息
func formatComponent(component map[string]interface{}) string {
	name, hasName := component["name"]
	if !hasName {
		return ""
	}

	nameStr := fmt.Sprintf("%v", name)

	// 特殊处理版本信息
	if version, hasVersion := component["version"]; hasVersion {
		versionStr := fmt.Sprintf("%v", version)
		// 组件名用亮青色,分隔符用灰色,版本号用亮黄色并加粗
		return fmt.Sprintf("%s%s%s",
			aurora.BrightCyan(nameStr).String(),
			aurora.Gray(12, "/").String(),
			aurora.Bold(aurora.BrightYellow(versionStr)).String())
	}

	// 收集其他属性
	var attrs []string
	for k, v := range component {
		if k != "name" && k != "version" {
			// 属性名用灰色,值用白色
			attrs = append(attrs, fmt.Sprintf("%s=%s",
				aurora.Gray(12, k).String(),
				aurora.White(fmt.Sprintf("%v", v)).String()))
		}
	}

	// 组合结果
	result := aurora.BrightCyan(nameStr).String()
	if len(attrs) > 0 {
		result += " " + strings.Join(attrs, " ")
	}

	return result
}

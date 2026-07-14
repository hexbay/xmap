package probe

import (
	"bufio"
	"fmt"
	"github.com/dlclark/regexp2"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/projectdiscovery/gologger"
)

// isHexDigit 检查字符是否为十六进制数字 (0-9, a-f, A-F)
func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// hexToInt 将十六进制字符转换为整数值
func hexToInt(c byte) int {
	if c >= '0' && c <= '9' {
		return int(c - '0')
	}
	if c >= 'a' && c <= 'f' {
		return int(c - 'a' + 10)
	}
	if c >= 'A' && c <= 'F' {
		return int(c - 'A' + 10)
	}
	return 0
}

// getPatternRegexp 编译正则表达式模式，并添加超时保护
func getPatternRegexp(pattern string, opt string) (*regexp2.Regexp, error) {
	o := regexp2.None
	if strings.Contains(opt, "i") {
		o |= regexp2.IgnoreCase
	}
	if strings.Contains(opt, "s") {
		o |= regexp2.Singleline
	}
	// 编译正则表达式
	re, err := regexp2.Compile(pattern, o)
	if err != nil {
		return nil, err
	}
	return re, nil
}

// ParseProbes 解析探针文件内容并添加到指定的探针存储中
func ParseProbes(content string) ([]*Probe, error) {
	var currentProbe *Probe
	probes := make([]*Probe, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		// 跳过注释和空行
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// 解析探针定义行
		if strings.HasPrefix(line, "Probe ") {
			currentProbe = parseProbeDefinition(line)
			if currentProbe != nil {
				probes = append(probes, currentProbe)
			}
			continue
		}

		// 如果没有当前探针，跳过
		if currentProbe == nil {
			continue
		}

		// 解析端口定义
		if strings.HasPrefix(line, "ports ") {
			parsePortsDefinition(currentProbe, line, false)
			continue
		}

		// 解析SSL端口定义
		if strings.HasPrefix(line, "sslports ") {
			parsePortsDefinition(currentProbe, line, true)
			continue
		}

		// 解析总等待时间
		if strings.HasPrefix(line, "totalwaitms ") {
			parseTotalWaitMS(currentProbe, line)
			continue
		}

		// 解析TCP包装等待时间
		if strings.HasPrefix(line, "tcpwrappedms ") {
			parseTCPWrappedMS(currentProbe, line)
			continue
		}

		// 解析稀有度
		if strings.HasPrefix(line, "rarity ") {
			parseRarityValue(currentProbe, line)
			continue
		}

		// 解析回退探针
		if strings.HasPrefix(line, "fallback ") {
			parseFallbackProbe(currentProbe, line)
			continue
		}

		// 解析匹配规则
		if strings.HasPrefix(line, "match ") || strings.HasPrefix(line, "softmatch ") {
			parseMatchRule(currentProbe, line, lineNum)
			continue
		}
	}

	// add last probe
	if currentProbe != nil {
		probes = append(probes, currentProbe)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("解析探针文件错误: %v", err)
	}

	return probes, nil
}

// parseProbeDefinition 解析探针定义行
func parseProbeDefinition(line string) *Probe {
	// 示例: Probe TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
	parts := strings.SplitN(line, " ", 4)
	if len(parts) < 4 {
		gologger.Warning().Msgf("无效的探针定义: %s", line)
		return nil
	}

	protocol := strings.ToLower(parts[1])
	name := parts[2]

	probe := &Probe{
		Name:       name,
		Protocol:   protocol,
		MatchGroup: make([]*Match, 0),
	}

	// 解析探针数据
	probeData := parts[3]
	if len(probeData) > 0 && probeData[0] == 'q' && probeData[1] == '|' {
		end := strings.LastIndex(probeData[2:], "|")
		if end == -1 {
			gologger.Warning().Msgf("无效的探针数据格式: %s", line)
			return nil
		}
		probe.SendData = []byte(parseEscapedString(probeData[2 : end+2]))
	}

	return probe
}

// parsePortsDefinition 解析端口定义
func parsePortsDefinition(probe *Probe, line string, isSSL bool) {
	if probe == nil {
		return
	}

	// 示例: ports 80,443,8080-8090 或 sslports 443,8443
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	ports := parsePortsList(parts[1])
	if isSSL {
		probe.SSLPorts = ports
	} else {
		probe.Ports = ports
	}
}

// parseTotalWaitMS 解析总等待时间
func parseTotalWaitMS(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: totalwaitms 6000
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	ms, err := strconv.Atoi(parts[1])
	if err != nil {
		gologger.Warning().Msgf("无效的等待时间值: %s", parts[1])
		return
	}

	probe.TotalWaitMS = time.Duration(ms) * time.Millisecond
}

// parseTCPWrappedMS 解析TCP包装等待时间
func parseTCPWrappedMS(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: tcpwrappedms 3000
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	ms, err := strconv.Atoi(parts[1])
	if err != nil {
		gologger.Warning().Msgf("无效的TCP包装等待时间值: %s", parts[1])
		return
	}

	probe.TCPWrappedMS = time.Duration(ms) * time.Millisecond
}

// parseRarityValue 解析稀有度
func parseRarityValue(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: rarity 5
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	rarity, err := strconv.Atoi(parts[1])
	if err != nil {
		gologger.Warning().Msgf("无效的稀有度值: %s", parts[1])
		return
	}

	probe.Rarity = rarity
}

// parseFallbackProbe 解析回退探针
func parseFallbackProbe(probe *Probe, line string) {
	if probe == nil {
		return
	}

	// 示例: fallback GetRequest2
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		return
	}

	// 设置回退探针名称
	probe.Fallback = append(probe.Fallback, strings.Split(parts[1], ",")...)
}

// parseMatchRule 解析匹配规则
func parseMatchRule(probe *Probe, line string, lineIndex int) {
	if probe == nil {
		return
	}

	// 判断是否为软匹配
	soft := strings.HasPrefix(line, "softmatch")

	// 示例: match http m|^HTTP/1\.[01] \d\d\d|
	// 或: softmatch http m|^HTTP/1\.[01] \d\d\d|
	// 或带自定义分隔符: match http m#^HTTP/1\.[01] \d\d\d#
	parts := strings.SplitN(line, " ", 3)

	if len(parts) < 3 {
		gologger.Warning().Msgf("无效的匹配规则格式: %s", line)
		return
	}

	// 获取服务名称
	serviceName := parts[1]

	// 解析匹配模式
	patternPart := parts[2]
	patternType := ""
	var pattern string

	// 检查模式前缀：m、i、s等
	if len(patternPart) >= 2 && (patternPart[0] == 'm') {
		// 分隔符
		if len(patternPart) < 3 {
			gologger.Warning().Msgf("无效的模式格式，缺少内容: %s", patternPart)
			return
		}
		delimiter := patternPart[1:2]
		patternType = patternPart[0:1]
		// 提取模式内容
		patternContent := patternPart[2:]
		// 查找结束分隔符，注意这里需要处理转义情况
		end := -1
		escaped := false
		for i := 0; i < len(patternContent); i++ {
			if escaped {
				escaped = false
				continue
			}
			if patternContent[i] == '\\' {
				escaped = true
				continue
			}
			if string(patternContent[i]) == delimiter {
				end = i
				break
			}
		}
		if end == -1 {
			gologger.Warning().Msgf("无效的模式格式，缺少结束分隔符 %s: %s", delimiter, patternPart)
			return
		}
		pattern = patternContent[:end]
		// 检查是否有额外的标志
		flags := ""
		if end+1 < len(patternContent) {
			flags = patternContent[end+1:]
			if spaceIndex := strings.IndexByte(flags, ' '); spaceIndex >= 0 {
				flags = flags[:spaceIndex]
			}
			// 处理标志，如 i（不区分大小写）、s（单行模式）等
			patternType = flags
		}
	} else {
		gologger.Warning().Msgf("不支持的模式类型: %s", patternPart)
		return
	}

	// 解析正则表达式模式
	decodePattern := ParseRegexPattern(pattern)
	match := &Match{
		Line:    lineIndex,
		Soft:    soft,
		Service: FixProtocol(serviceName),
		Pattern: decodePattern,
	}
	var err error
	match.regex, err = getPatternRegexp(decodePattern, patternType)
	if err != nil {
		gologger.Warning().Msgf("编译正则表达式失败: line: %d > %s - %v", lineIndex, pattern, err)
		return
	}
	// 解析版本信息
	match.VersionInfo = parseVersionInfo(line)

	// 添加到当前探针的匹配组
	probe.MatchGroup = append(probe.MatchGroup, match)
}

// parseVersionInfo 解析版本信息
func parseVersionInfo(line string) *VersionInfo {
	info := &VersionInfo{}

	// 提取版本信息字段
	// 示例: p/Apache httpd/ v/$1/ i/Debian/ o/Linux/ cpe:/a:apache:http_server:$1/
	versionPart := line
	vIndex := strings.Index(line, " p/")
	if vIndex != -1 {
		versionPart = line[vIndex+1:]
	} else {
		return info
	}

	// 解析产品名称
	pMatch := regexp.MustCompile(`p/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(pMatch) > 1 {
		info.ProductName = pMatch[1]
	}

	// 解析版本
	vMatch := regexp.MustCompile(`v/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(vMatch) > 1 {
		info.Version = vMatch[1]
	}

	// 解析信息
	iMatch := regexp.MustCompile(`i/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(iMatch) > 1 {
		info.Info = iMatch[1]
	}

	// 解析操作系统
	oMatch := regexp.MustCompile(`o/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(oMatch) > 1 {
		info.OS = oMatch[1]
	}

	// 解析主机名
	hMatch := regexp.MustCompile(`h/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(hMatch) > 1 {
		info.Hostname = hMatch[1]
	}

	// 解析设备类型
	dMatch := regexp.MustCompile(`d/([^/]*)/`).FindStringSubmatch(versionPart)
	if len(dMatch) > 1 {
		info.DeviceType = dMatch[1]
	}

	// 解析CPE标识符
	cpeMatches := regexp.MustCompile(`cpe:/[^/]+/([^/]+/[^/]+(?:/[^/]+)*)/`).FindAllStringSubmatch(versionPart, -1)
	if len(cpeMatches) > 0 {
		info.CPE = make([]string, 0, len(cpeMatches))
		for _, cpeMatch := range cpeMatches {
			if len(cpeMatch) > 1 {
				// 完整的CPE字符串
				fullCPE := "cpe:/" + cpeMatch[0]
				// 去掉末尾的斜杠
				if strings.HasSuffix(fullCPE, "/") {
					fullCPE = fullCPE[:len(fullCPE)-1]
				}
				info.CPE = append(info.CPE, fullCPE)
			}
		}
	}

	return info
}

// parsePortsList 解析端口列表
func parsePortsList(portsStr string) []int {
	var ports []int

	// 分割端口列表
	portParts := strings.Split(portsStr, ",")
	for _, part := range portParts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// 检查是否为端口范围
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, err1 := strconv.Atoi(rangeParts[0])
				end, err2 := strconv.Atoi(rangeParts[1])
				if err1 == nil && err2 == nil && start <= end {
					for port := start; port <= end; port++ {
						ports = append(ports, port)
					}
				}
			}
		} else {
			// 单个端口
			port, err := strconv.Atoi(part)
			if err == nil {
				ports = append(ports, port)
			}
		}
	}

	return ports
}

// parseEscapedString 解析转义字符串
func parseEscapedString(s string) string {
	var result strings.Builder
	i := 0

	for i < len(s) {
		if s[i] == '\\' && i+1 < len(s) {
			// 处理转义序列
			i++
			switch s[i] {
			case 'r':
				result.WriteByte('\r')
			case 'n':
				result.WriteByte('\n')
			case 't':
				result.WriteByte('\t')
			case '\\':
				result.WriteByte('\\')
			case '0':
				// 处理 \0 转义序列 (空字节)
				result.WriteByte(0)
			case 'a':
				result.WriteByte('\a') // 警报 (BEL)
			case 'b':
				result.WriteByte('\b') // 退格
			case 'f':
				result.WriteByte('\f') // 换页
			case 'v':
				result.WriteByte('\v') // 垂直制表符
			case 'x':
				// 十六进制转义序列 \xHH
				if i+2 < len(s) {
					hexStr := s[i+1 : i+3]
					val, err := strconv.ParseUint(hexStr, 16, 8)
					if err == nil {
						result.WriteByte(byte(val))
						i += 2 // 跳过已处理的两位十六进制数字
					} else {
						// 如果解析失败，保留原字符
						result.WriteByte('\\')
						result.WriteByte('x')
					}
				} else {
					// 不完整的十六进制序列，保留原始转义
					result.WriteByte('\\')
					result.WriteByte('x')
				}
			case 'u':
				// Unicode转义序列 \uHHHH
				if i+4 < len(s) {
					hexStr := s[i+1 : i+5]
					val, err := strconv.ParseUint(hexStr, 16, 16)
					if err == nil {
						// 写入UTF-8编码的Unicode字符
						result.WriteRune(rune(val))
						i += 4 // 跳过已处理的四位十六进制数字
					} else {
						// 如果解析失败，保留原始转义
						result.WriteByte('\\')
						result.WriteByte('u')
					}
				} else {
					// 不完整的Unicode序列，保留原始转义
					result.WriteByte('\\')
					result.WriteByte('u')
				}
			default:
				// 对于其他转义序列，保留原始的反斜杠和字符
				// 这样可以保留 \d, \w 等正则表达式特殊序列
				result.WriteByte('\\')
				result.WriteByte(s[i])
			}
		} else {
			// 普通字符
			result.WriteByte(s[i])
		}
		i++
	}

	return result.String()
}

// FixProtocol 标准化协议名称
func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}

// TemplateProcessor 处理版本信息模板替换
type TemplateProcessor struct {
	// 正则表达式匹配结果中的组
	groups map[string]string
}

// NewTemplateProcessor 创建一个新的模板处理器
func NewTemplateProcessor(groups map[string]string) *TemplateProcessor {
	return &TemplateProcessor{
		groups: groups,
	}
}

// ProcessTemplate 处理模板字符串，替换其中的变量
func (p *TemplateProcessor) ProcessTemplate(template string) string {
	// 如果模板为空，返回空字符串
	if template == "" {
		return ""
	}

	// 处理模板中的变量替换
	return p.processTemplate(template)
}

// processTemplate 处理模板字符串中的变量替换
func (p *TemplateProcessor) processTemplate(template string) string {
	result := template

	// 替换 $1, $2 等数字变量
	for i := 1; i <= 9; i++ {
		key := fmt.Sprintf("%d", i)
		if value, ok := p.groups[key]; ok {
			placeholder := fmt.Sprintf("$%s", key)
			result = strings.ReplaceAll(result, placeholder, value)
		}
	}

	// 替换 ${name} 形式的命名变量
	for key, value := range p.groups {
		placeholder := fmt.Sprintf("${%s}", key)
		result = strings.ReplaceAll(result, placeholder, value)
	}

	// 处理特殊命令，如 $P(), $I() 等
	result = p.processCommands(result)

	return result
}

// processCommands 处理模板中的特殊命令
func (p *TemplateProcessor) processCommands(template string) string {
	result := template

	// 处理 $P(n) 命令 - 提取端口号
	result = p.processPortCommand(result)

	// 处理 $I(n) 命令 - 提取IP地址
	result = p.processIPCommand(result)

	// 处理其他可能的命令
	// ...

	return result
}

// processPortCommand 处理 $P(n) 命令，提取端口号
func (p *TemplateProcessor) processPortCommand(template string) string {
	// 简单实现，实际应根据需求扩展
	for i := 1; i <= 9; i++ {
		cmd := fmt.Sprintf("$P(%d)", i)
		if strings.Contains(template, cmd) {
			if value, ok := p.groups[fmt.Sprintf("%d", i)]; ok {
				// 尝试从值中提取端口号
				// 这里是简化实现，实际可能需要更复杂的逻辑
				template = strings.ReplaceAll(template, cmd, value)
			}
		}
	}
	return template
}

// processIPCommand 处理 $I(n) 命令，提取IP地址
func (p *TemplateProcessor) processIPCommand(template string) string {
	// 简单实现，实际应根据需求扩展
	for i := 1; i <= 9; i++ {
		cmd := fmt.Sprintf("$I(%d)", i)
		if strings.Contains(template, cmd) {
			if value, ok := p.groups[fmt.Sprintf("%d", i)]; ok {
				// 尝试从值中提取IP地址
				// 这里是简化实现，实际可能需要更复杂的逻辑
				template = strings.ReplaceAll(template, cmd, value)
			}
		}
	}
	return template
}

// isRegexKey 判断是否是正则表达式关键字、根据结果判断是否需要转义
func isRegexKey(key string) bool {
	chars := []string{".", "*", "+", "?", "[", "]", "(", ")", "{", "\\", "|"}
	for _, char := range chars {
		if strings.Contains(key, char) {
			return true
		}
	}
	return false
}

func RegexStringUnescape(s string) string {
	if s == "" {
		return ""
	}
	var result strings.Builder
	result.Grow(len(s)) // 预分配空间
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++ // 跳过反斜杠
			switch s[i] {
			case '0': // \0 - 空字符
				result.WriteByte(0)
			case 'a': // \a - 响铃 (BEL)
				result.WriteByte('\a')
			case 'b': // \b - 退格 (BS)
				result.WriteByte('\b')
			case 'f': // \f - 换页 (FF)
				result.WriteByte('\f')
			case 'n': // \n - 换行 (LF)
				result.WriteByte('\n')
			case 'r': // \r - 回车 (CR)
				result.WriteByte('\r')
			case 't': // \t - 水平制表符 (TAB)
				result.WriteByte('\t')
			case 'v': // \v - 垂直制表符 (VT)
				result.WriteByte('\v')
			case 'x': // \xHH - 十六进制转义序列
				if i+2 < len(s) {
					ch1 := s[i+1]
					ch2 := s[i+2]
					if isHexDigit(ch1) && isHexDigit(ch2) {
						// 将两个十六进制字符转换为一个字节
						val := hexToInt(ch1)*16 + hexToInt(ch2)
						// 检查解析出的字符是否是正则表达式中的特殊字符
						ch := byte(val)
						if isRegexKey(string(ch)) {
							// 如果是特殊字符，添加转义
							result.WriteByte('\\')
						}
						result.WriteByte(ch)
						i += 2 // 跳过这两个十六进制字符
					} else {
						// 如果不是有效的十六进制序列，保留原始的 \x
						result.WriteByte('\\')
						result.WriteByte('x')
					}
				} else {
					// 如果 \x 后面没有足够的字符，保留原始的 \x
					result.WriteByte('\\')
					result.WriteByte('x')
				}
			case 'd', 'w', 's', 'D', 'W', 'S':
				result.WriteByte('\\')
				result.WriteByte(s[i])

			case '\\':
				result.WriteByte('\\')
				result.WriteByte('\\')
			default:
				// 检查是否是正则表达式中的特殊字符
				if isRegexKey(string(s[i])) {
					// 保留转义，因为这些在正则表达式中是特殊字符
					result.WriteByte('\\')
					result.WriteByte(s[i])
				} else if unicode.IsLetter(rune(s[i])) || unicode.IsDigit(rune(s[i])) {
					// 与 Nmap 保持一致，不支持八进制转义序列和其他字母数字转义
					// 返回原始字符
					result.WriteByte(s[i])
				} else {
					// 对于其他字符，只保留字符本身
					result.WriteByte(s[i])
				}
			}
		} else {
			result.WriteByte(s[i])
		}
	}
	return result.String()
}

// ParseRegexPattern 转换正则表达式
func ParseRegexPattern(pattern string) string {
	s := RegexStringUnescape(pattern)
	return s
}

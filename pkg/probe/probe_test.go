package probe

import (
	"encoding/hex"
	"testing"

	"github.com/dlclark/regexp2"
	"github.com/stretchr/testify/assert"
)

func HexToBytes(h string) []byte {
	data, _ := hex.DecodeString(h)
	return data
}

func TestRegex(t *testing.T) {
	data := []byte("\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\nFGT101E - FortiOS v6.4.8 FN1EDGE003\r\nUser Access Verification\r\n\r\nUsername: ")
	pat := []byte("^\xff\xfb\x01\xff\xfb\x03\xff\xfb\x00\xff\xfd\x00\xff\xfd\x1f\r\n.*User Access Verification\r\n\r\nUsername: ")
	com, err := regexp2.Compile(string(pat), regexp2.Singleline)
	assert.Nil(t, err)
	ok, s := com.MatchString(string(data))
	assert.True(t, ok)
	assert.Nil(t, s)
}

// 测试正则匹配
func TestMultiMatch(t *testing.T) {
	testCases := []struct {
		name string
		pat  []byte
		data []byte
	}{
		{
			name: "test1",
			pat:  []byte("^\x15\x03\x01\\0\x02\x02\x0a$"),
			data: HexToBytes("1503010002020a"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			com, err := regexp2.Compile(string(tc.pat), regexp2.Singleline)
			assert.Nil(t, err)
			ok, s := com.MatchString(string(tc.data))
			assert.Nil(t, s)
			assert.True(t, ok)
		})
	}
}

// 测试sendData 解析是否正确
func TestParseSendData(t *testing.T) {
	store, err := GetStoreWithOptions("", 9, false)
	assert.Nil(t, err)
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "tcp/GenericLines",
			data: []byte("\r\n\r\n"),
		},
		{
			name: "udp/Sqlping",
			data: []byte{2},
		},
		{
			// \0\0\0\0\0\x01\0\0\0\0\0\0\x09_services\x07_dns-sd\x04_udp\x05local\0\0\x0c\0\x01
			name: "udp/DNS-SD",
			// 正确的二进制表示，不包含反斜杠字符
			data: []byte{0, 0, 0, 0, 0, 0x1, 0, 0, 0, 0, 0, 0, 0x9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's', 0x7, '_', 'd', 'n', 's', '-', 's', 'd', 0x4, '_', 'u', 'd', 'p', 0x5, 'l', 'o', 'c', 'a', 'l', 0x0, 0x0, 0x0c, 0x0, 0x01},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			probe := store.GetProbesByName(tc.name)
			assert.NotNil(t, probe)
			assert.Equal(t, tc.data, probe.SendData)
		})
	}
}

func TestParseRegexPattern(t *testing.T) {
	// 测试regex 解析是否正确
	testCases := []struct {
		raw    string
		except string
	}{
		{
			raw:    `^\x04\x01\0\x28\0\0\0\0\xaa\x14\0\xa2\x0f\0\0\x01\x0eLogin failed\.\n\xfd\x02\0\x02\0\0\0\0\0$`,
			except: "^\x04\x01\x00\\(\x00\x00\x00\x00\xaa\x14\x00\xa2\x0f\x00\x00\x01\x0eLogin failed\\.\n\xfd\x02\x00\x02\x00\x00\x00\x00\x00$",
		},
		{
			raw:    `^\0\x5c`,
			except: "^\x00\\\\",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.raw, func(t *testing.T) {
			except := ParseRegexPattern(tc.raw)
			assert.Equal(t, tc.except, except)
			// 编译
			_, err := regexp2.Compile(except, regexp2.Singleline)
			if err != nil {
				t.Fatal(err)
			}
			assert.Nil(t, err)
		})
	}

}

func TestParseMatchRuleStopsFlagsAtVersionInfo(t *testing.T) {
	p := &Probe{Name: "TestProbe"}
	line := `match test m|^hello.*world$|s p/ISC BIND/`

	parseMatchRule(p, line, 1)

	assert.Len(t, p.MatchGroup, 1)
	match, err := p.Match([]byte("hello\nworld"))
	assert.NoError(t, err)
	assert.NotNil(t, match)
	assert.Equal(t, "test", match.Match.Service)
}

// 创建测试用的正则表达式
func createTestRegex(pattern string) *regexp2.Regexp {
	r, _ := regexp2.Compile(pattern, regexp2.None)
	return r
}

func TestMatch(t *testing.T) {
	// 创建测试用的探针和匹配规则
	mainProbe := &Probe{
		Name:     "MainProbe",
		SendData: []byte("MAIN"),
		MatchGroup: []*Match{
			{
				Service: "main-service",
				Pattern: "MAIN-PATTERN ([\\d\\.]+)",
				Soft:    false,
				VersionInfo: &VersionInfo{
					Version: "$1",
				},
				regex: createTestRegex("MAIN-PATTERN ([\\d\\.]+)"),
			},
		},
	}

	// 创建回退探针
	fallbackProbe := &Probe{
		Name:     "FallbackProbe",
		SendData: []byte("FALLBACK"),
		MatchGroup: []*Match{
			{
				Service: "fallback-service",
				Pattern: "FALLBACK-PATTERN ([\\d\\.]+)",
				Soft:    false,
				VersionInfo: &VersionInfo{
					Version: "$1",
				},
				regex: createTestRegex("FALLBACK-PATTERN ([\\d\\.]+)"),
			},
		},
	}
	mainProbe.Fallback = []string{"FallbackProbe"}
	mainProbe.FallbackProbes = []*Probe{fallbackProbe}
	t.Run("DirectMatch", func(t *testing.T) {
		response := []byte("MAIN-PATTERN 1.0")
		result, _ := mainProbe.Match(response)

		assert.NotNil(t, result)
		assert.Equal(t, "main-service", result.Match.Service)
		assert.Equal(t, "1.0", result.VersionInfo["version"])
		assert.False(t, result.IsFallback)
		assert.Empty(t, result.FallbackPath)
	})

	// 测试场景2: 直接匹配失败，回退匹配成功
	t.Run("FallbackMatch", func(t *testing.T) {
		response := []byte("FALLBACK-PATTERN 2.0")
		result, err := mainProbe.Match(response)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "fallback-service", result.Match.Service)
		assert.Equal(t, "2.0", result.VersionInfo["version"])
	})

	// 测试场景3: 所有匹配都失败
	t.Run("NoMatch", func(t *testing.T) {
		response := []byte("NO-MATCH")
		result, err := mainProbe.Match(response)
		assert.NoError(t, err)
		assert.Nil(t, result)
	})

}

// 测试常见协议匹配是否正确
func TestCommonProtocolMatch(t *testing.T) {
	store := GetDefaultStore()
	// 测试HTTP
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "tcp/GetRequest",
			data: []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n<html><body><h1>Test HTTP Server</h1></body></html>"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			probe := store.GetProbesByName(tc.name)
			assert.NotNil(t, probe)
			result, err := probe.Match(tc.data)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}

}

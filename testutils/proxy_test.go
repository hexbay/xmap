package testutils

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hexbay/xmap/pkg/api"
	"github.com/hexbay/xmap/pkg/types"
	"github.com/stretchr/testify/assert"
)

// TestProxyConnection 测试通过代理连接到目标服务器
func TestProxyConnection(t *testing.T) {
	// 创建一个测试HTTP服务器，用于验证代理是否正常工作
	targetServer := NewTestServer("tcp")
	httpResponse := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>")
	targetServer.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(httpResponse), 5)
	err := targetServer.Start()
	assert.NoError(t, err, "启动目标测试服务器失败")
	defer targetServer.Stop()

	fmt.Printf("目标服务器已启动，地址: %s\n", targetServer.GetAddress())

	// 创建一个简单的HTTP代理服务器
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			// 处理HTTPS代理请求
			destConn, err := net.Dial("tcp", r.Host)
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer destConn.Close()

			// 响应客户端连接已建立
			w.WriteHeader(http.StatusOK)

			// 获取底层连接
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "不支持Hijacking", http.StatusInternalServerError)
				return
			}

			clientConn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
			defer clientConn.Close()

			// 在客户端和目标服务器之间转发数据
			go func() {
				defer destConn.Close()
				defer clientConn.Close()
				_, _ = io.Copy(destConn, clientConn)
			}()
			_, _ = io.Copy(clientConn, destConn)
		} else {
			// 处理HTTP代理请求
			targetURL, err := url.Parse(r.URL.String())
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			// 创建到目标服务器的请求
			req, err := http.NewRequest(r.Method, targetURL.String(), r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// 复制原始请求的头信息
			for key, values := range r.Header {
				for _, value := range values {
					req.Header.Add(key, value)
				}
			}

			// 发送请求到目标服务器
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			// 复制目标服务器的响应头
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}

			// 设置响应状态码
			w.WriteHeader(resp.StatusCode)

			// 复制响应体
			_, _ = io.Copy(w, resp.Body)
		}
	}))
	defer proxyServer.Close()

	fmt.Printf("代理服务器已启动，地址: %s\n", proxyServer.URL)

	// 测试用例
	testCases := []struct {
		name           string
		useProxy       bool
		expectedResult bool
	}{
		{
			name:           "使用代理扫描",
			useProxy:       true,
			expectedResult: true,
		},
		{
			name:           "不使用代理扫描",
			useProxy:       false,
			expectedResult: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 创建XMap实例，根据测试用例配置是否使用代理
			options := types.DefaultOptions()
			options.Timeout = 5
			options.Retries = 1
			options.VersionIntensity = 7

			// 如果需要使用代理，添加代理选项
			if tc.useProxy {
				options.Proxy = proxyServer.URL
			}

			xmapInstance, err := api.NewEngine(api.EngineConfig{Options: options})
			assert.NoError(t, err, "初始化XMap实例失败")
			assert.NotNil(t, xmapInstance, "初始化XMap实例失败")

			// 创建扫描目标
			target := &types.ScanTarget{
				IP:       targetServer.GetIP(),
				Port:     targetServer.GetPort(),
				Protocol: "tcp",
			}

			// 执行扫描
			ctx := context.Background()
			result, err := xmapInstance.Scan(ctx, target)

			// 打印扫描结果和错误信息
			if err != nil {
				fmt.Printf("扫描错误: %v\n", err)
			}
			fmt.Printf("扫描结果: %+v\n", result)

			// 验证扫描结果
			assert.NotNil(t, result, "扫描结果不应为空")
			if tc.expectedResult {
				assert.Equal(t, "http", result.Service, "服务识别错误")
				assert.Contains(t, string(result.RawResponse), "nginx", "Banner识别错误")
			}
		})
	}
}

// TestProxyTimeout 测试代理超时情况
func TestProxyTimeout(t *testing.T) {
	// 创建一个延迟响应的测试服务器
	targetServer := NewTestServer("tcp")
	httpResponse := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>")
	targetServer.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(httpResponse), 5)
	targetServer.SetResponseDelay(3 * time.Second) // 设置3秒响应延迟
	err := targetServer.Start()
	assert.NoError(t, err, "启动目标测试服务器失败")
	defer targetServer.Stop()

	fmt.Printf("延迟响应服务器已启动，地址: %s\n", targetServer.GetAddress())

	// 创建一个简单的HTTP代理服务器
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 简单转发请求
		http.Error(w, "代理超时测试", http.StatusGatewayTimeout)
	}))
	defer proxyServer.Close()

	fmt.Printf("超时代理服务器已启动，地址: %s\n", proxyServer.URL)

	// 创建XMap实例，使用短超时时间
	options := types.DefaultOptions()
	options.Timeout = 1 // 设置1秒超时，小于服务器响应延迟
	options.MaxTimeout = 2
	options.Retries = 0 // 不重试
	options.Proxy = proxyServer.URL
	xmapInstance, err := api.NewEngine(api.EngineConfig{Options: options})
	assert.NoError(t, err, "初始化XMap实例失败")
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")

	// 创建扫描目标
	target := &types.ScanTarget{
		IP:       targetServer.GetIP(),
		Port:     targetServer.GetPort(),
		Protocol: "tcp",
	}

	// 执行扫描
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, target)

	// 打印扫描结果和错误信息
	fmt.Printf("超时测试扫描结果: %+v, 错误: %v\n", result, err)

	// 验证是否发生了超时或代理错误
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.True(t, err != nil || result.Error != nil || result.Status == types.StatusError, "应该有超时或代理错误")
}

// TestInvalidProxy 测试无效代理情况
func TestInvalidProxy(t *testing.T) {
	// 创建一个测试HTTP服务器
	targetServer := NewTestServer("tcp")
	httpResponse := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>")
	targetServer.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(httpResponse), 5)
	err := targetServer.Start()
	assert.NoError(t, err, "启动目标测试服务器失败")
	defer targetServer.Stop()

	fmt.Printf("目标服务器已启动，地址: %s\n", targetServer.GetAddress())

	// 使用一个不存在的代理地址
	invalidProxyURL := "http://127.0.0.1:65535" // 使用一个几乎肯定不可用的端口

	// 创建XMap实例，使用无效代理
	options := types.DefaultOptions()
	options.Timeout = 2
	options.Retries = 0
	options.Proxy = invalidProxyURL
	xmapInstance, err := api.NewEngine(api.EngineConfig{Options: options})
	assert.NoError(t, err, "初始化XMap实例失败")
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")

	// 创建扫描目标
	target := &types.ScanTarget{
		IP:       targetServer.GetIP(),
		Port:     targetServer.GetPort(),
		Protocol: "tcp",
	}

	// 执行扫描
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, target)

	// 打印扫描结果和错误信息
	fmt.Printf("无效代理测试扫描结果: %+v, 错误: %v\n", result, err)

	// 代理仅用于Web指纹阶段，基础TCP服务识别不依赖代理。
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.NoError(t, err, "基础服务扫描不应受无效代理影响")
	assert.Equal(t, "http", result.Service, "服务识别错误")
}

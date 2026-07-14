package api

import (
	"bytes"
	"context"
	"fmt"
	"github.com/hexbay/xmap/testutils"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hexbay/xmap/pkg/types"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
)

func createXmap() *XMap {
	opts := types.DefaultOptions()
	xmap, err := New(opts)
	if err != nil {
		panic(err)
	}
	return xmap
}

// TestProtocolDetection 测试协议检测功能
func TestProtocolDetection(t *testing.T) {
	// 创建测试用例
	testCases := []struct {
		name            string
		serverSetup     func() (*testutils.TestServer, error)
		expectedService string
	}{
		{
			name: "SSH服务识别",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建SSH测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置SSH响应
				sshResponse := []byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(sshResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动SSH测试服务器失败: %v", err)
				}

				fmt.Printf("SSH服务识别测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			expectedService: "ssh",
		},
		{
			name: "HTTP服务识别",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建HTTP测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置HTTP响应
				httpResponse := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Test</body></html>")

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(httpResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动HTTP测试服务器失败: %v", err)
				}

				fmt.Printf("HTTP服务识别测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			expectedService: "http",
		},
		{
			name: "Nginx服务识别",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建Nginx测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置Nginx响应
				nginxResponse := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n\r\n<html><body>Nginx Test</body></html>")

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(nginxResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动Nginx测试服务器失败: %v", err)
				}

				fmt.Printf("Nginx服务识别测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			expectedService: "http",
		},
		{
			name: "Redis服务识别",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建Redis测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置Redis响应
				redisResponse := []byte("-ERR unknown command\r\n")

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(redisResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动Redis测试服务器失败: %v", err)
				}

				fmt.Printf("Redis服务识别测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			expectedService: "redis",
		},
		{
			name: "MySQL服务识别",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建MySQL测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置MySQL响应
				mysqlResponse := []byte{74, 0, 0, 0, 10, 53, 46, 55, 46, 51, 57, 0, 43, 0, 0, 0, 78, 14, 68, 26, 67, 17, 35, 97, 0, 127, 167, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 65, 76, 73, 89, 85, 78, 95, 77, 89, 83, 81, 76, 95, 80, 65, 83, 83, 87, 79, 82, 68, 0}

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(mysqlResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动MySQL测试服务器失败: %v", err)
				}

				fmt.Printf("MySQL服务识别测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			expectedService: "mysql",
		},
		{
			name: "HTTPS服务识别",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建HTTPS测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置TLS握手响应（模拟）
				tlsResponse := []byte{0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(tlsResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动HTTPS测试服务器失败: %v", err)
				}

				fmt.Printf("HTTPS服务识别测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			expectedService: "https",
		},
	}

	// 初始化XMap扫描器
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	// 运行测试用例
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 设置测试服务器
			server, err := tc.serverSetup()
			assert.NoError(t, err, "设置测试服务器失败")
			defer server.Stop()
			// 创建扫描目标
			// 注意：不预先设置UseSSL，让XMap自动检测是否需要SSL
			// 执行扫描
			ctx := context.Background()
			result, err := xmapInstance.Scan(ctx, types.NewTarget(server.GetAddress()))
			// 打印扫描结果和错误信息
			if err != nil {
				fmt.Printf("%s扫描错误: %v\n", tc.name, err)
			}
			fmt.Printf("%s扫描结果: %+v\n", tc.name, result)
			// 验证测试服务器是否正常工作
			assert.NotNil(t, result, "扫描结果不应为空")
		})
	}
}

// TestDirectTCPConnection 测试直接TCP连接到测试服务器
func TestDirectTCPConnection(t *testing.T) {
	// 创建测试用例
	testCases := []struct {
		name           string
		serverSetup    func() (*testutils.TestServer, error)
		requestData    []byte
		expectedPrefix []byte
	}{
		{
			name: "SSH服务测试",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建SSH测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置SSH响应
				sshResponse := []byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")

				// 添加请求-响应规则
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(sshResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动SSH测试服务器失败: %v", err)
				}

				fmt.Printf("SSH服务测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			requestData:    []byte("SSH-2.0-Client\r\n"),
			expectedPrefix: []byte("SSH-2.0-"),
		},
		{
			name: "HTTP服务测试",
			serverSetup: func() (*testutils.TestServer, error) {
				// 创建HTTP测试服务器
				server := testutils.NewTestServer("tcp")

				// 设置HTTP响应
				httpResponse := []byte("HTTP/1.1 200 OK\r\n" +
					"Server: Apache/2.4.41 (Ubuntu)\r\n" +
					"Content-Type: text/html\r\n" +
					"Content-Length: 123\r\n" +
					"Connection: keep-alive\r\n" +
					"\r\n" +
					"<html><body><h1>Test Server</h1><p>This is a test HTTP server response.</p></body></html>")

				// 添加请求-响应规则
				server.AddRule(testutils.NewPrefixRequestMatcher([]byte("GET")), testutils.NewStaticResponseHandler(httpResponse), 10)
				server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler(httpResponse), 5)

				// 启动服务器
				err := server.Start()
				if err != nil {
					return nil, fmt.Errorf("启动HTTP测试服务器失败: %v", err)
				}

				fmt.Printf("HTTP服务测试服务器已启动，地址: %s\n", server.GetAddress())
				return server, nil
			},
			requestData:    []byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
			expectedPrefix: []byte("HTTP/1.1 200"),
		},
	}

	// 运行测试用例
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// 设置测试服务器
			server, err := tc.serverSetup()
			assert.NoError(t, err, "设置测试服务器失败")
			defer server.Stop()

			// 创建TCP连接
			conn, err := net.Dial("tcp", server.GetAddress())
			assert.NoError(t, err, "连接测试服务器失败")
			defer conn.Close()

			// 发送请求数据
			_, err = conn.Write(tc.requestData)
			assert.NoError(t, err, "发送请求数据失败")

			// 读取响应
			buffer := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := conn.Read(buffer)
			assert.NoError(t, err, "读取响应失败")

			// 验证响应
			response := buffer[:n]
			fmt.Printf("收到响应: %s\n", testutils.FormatBytes(response))
			assert.True(t, bytes.HasPrefix(response, tc.expectedPrefix), "响应前缀不匹配")

			// 验证服务器是否收到了请求
			requestCount := server.GetRequestCount()
			fmt.Printf("服务器收到请求数: %d\n", requestCount)
			assert.Greater(t, requestCount, 0, "服务器应该至少收到一个请求")
		})
	}
}

func TestSSHScan(t *testing.T) {
	// 创建测试用例
	gologger.DefaultLogger.SetMaxLevel(levels.LevelInfo)
	server := testutils.NewTestServer("tcp")
	server.AddRule(testutils.NewEmptyRequestMatcher(), testutils.NewStaticResponseHandler([]byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")), 5)
	err := server.Start()
	assert.NoError(t, err, "启动测试服务器失败")
	defer server.Stop()
	// 创建XMap实例
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, types.NewTarget(server.GetAddress()))
	assert.NoError(t, err, "扫描失败")

	// 打印扫描结果
	fmt.Printf("扫描结果:\n%s\n", result.JSON())
}

func TestHTTPScan(t *testing.T) {
	// 创建测试用例
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41 (Ubuntu)")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Hello, World!"))
	}))
	defer server.Close()
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建XMap实例
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, types.NewTarget(server.URL))
	assert.NoError(t, err, "扫描失败")
	// 打印扫描结果
	fmt.Printf("扫描结果:\n%s\n", result.JSON())
}

func TestTimeoutScan(t *testing.T) {
	// 创建测试用例
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	server := testutils.NewTestServer("tcp")
	server.AddRule(testutils.NewPrefixRequestMatcher([]byte("GET")), testutils.NewStaticResponseHandler([]byte("HTTP/1.1 200 OK\nServer: nginx/1.18.0\nContent-Type: text/html\n\n<html><body>Test</body></html>")), 5)
	server.SetResponseDelay(10 * time.Second)
	err := server.Start()
	assert.NoError(t, err, "启动测试服务器失败")
	defer server.Stop()

	// 创建XMap实例
	// 创建XMap实例
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, types.NewTarget(server.GetAddress()))
	assert.Error(t, err)
	assert.NotNil(t, result)
	assert.True(t, result.Duration > 10)
	assert.Equal(t, result.Service, "")
}

func TestRemoteWaf(t *testing.T) {
	// 创建XMap实例
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建XMap实例
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, &types.ScanTarget{
		IP:       "frp.lostpeach.cn",
		Port:     443,
		Protocol: "tcp",
	})
	println(result, err)
}

func TestScanWithWaf(t *testing.T) {
	// 创建XMap实例
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建XMap实例
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	ctx := context.Background()
	result, err := xmapInstance.Scan(ctx, &types.ScanTarget{
		IP:       "frp.lostpeach.cn",
		Port:     3001,
		Protocol: "tc",
	})
	if err != nil {
		println(err.Error())
	}
	assert.NotNil(t, result)
}

func TestScanHttps(t *testing.T) {
	// 创建XMap实例
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建XMap实例
	xmapInstance, err := New(types.DefaultOptions())
	assert.NoError(t, err)
	assert.NotNil(t, xmapInstance, "初始化XMap实例失败")
	ctx := context.Background()
	target := types.NewTarget("https://www.hackerone.com/")
	result, err := xmapInstance.Scan(ctx, target)
	assert.Nil(t, err)
	assert.NotNil(t, result)
	assert.True(t, len(result.Components) > 0)
}

func BenchmarkNewXmap(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = New(types.DefaultOptions())
	}
}

func TestParseCertificateMessage(t *testing.T) {
	// 测试证书解析
	xmap := createXmap()
	result, err := xmap.Scan(context.Background(), types.NewTarget("pc.test.pinbayun.com:443"))
	assert.Nil(t, err)
	println(result.Certificate)
}

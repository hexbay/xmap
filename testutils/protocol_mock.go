package testutils

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RequestMatcher 定义了请求匹配器接口
type RequestMatcher interface {
	// Match 检查请求数据是否匹配
	Match(data []byte) bool
}

// StringMatcher 实现了基于字符串的请求匹配
type StringMatcher struct {
	Pattern string
}

// Match 检查请求数据是否包含指定字符串
func (m *StringMatcher) Match(data []byte) bool {
	return strings.Contains(string(data), m.Pattern)
}

// RegexMatcher 实现了基于正则表达式的请求匹配
type RegexMatcher struct {
	Pattern *regexp.Regexp
}

// Match 检查请求数据是否匹配正则表达式
func (m *RegexMatcher) Match(data []byte) bool {
	return m.Pattern.MatchString(string(data))
}

// PrefixMatcher 实现了基于前缀的请求匹配
type PrefixMatcher struct {
	Prefix []byte
}

// Match 检查请求数据是否以指定前缀开始
func (m *PrefixMatcher) Match(data []byte) bool {
	println("PrefixMatcher Match", hex.EncodeToString(data), hex.EncodeToString(m.Prefix))
	if len(data) < len(m.Prefix) {
		return false
	}
	for i := 0; i < len(m.Prefix); i++ {
		if data[i] != m.Prefix[i] {
			return false
		}
	}
	return true
}

// ResponseHandler 定义了响应处理器接口
type ResponseHandler interface {
	// Handle 处理请求并返回响应
	Handle(request []byte) []byte
}

// StaticResponseHandler 实现了静态响应处理器
type StaticResponseHandler struct {
	Response []byte
}

// Handle 返回预定义的静态响应
func (h *StaticResponseHandler) Handle(request []byte) []byte {
	return h.Response
}

// RequestResponseRule 定义了请求-响应规则
type RequestResponseRule struct {
	Matcher  RequestMatcher
	Handler  ResponseHandler
	Priority int // 优先级，数字越大优先级越高
}

// TestServer 测试服务器
type TestServer struct {
	protocol         string         // 协议类型
	tcpListener      net.Listener   // TCP网络监听器
	udpListener      net.PacketConn // UDP网络监听器
	httpServer       *http.Server   // HTTP服务器
	address          string         // 服务器地址
	port             int            // 服务器端口
	started          bool           // 服务器是否已启动
	stopped          bool           // 服务器是否已停止
	startOnce        sync.Once
	stopOnce         sync.Once
	wg               sync.WaitGroup
	stopChan         chan struct{}
	rules            []RequestResponseRule // 请求-响应规则列表
	defaultResponses map[string][]byte     // 默认响应映射
	keepAlive        bool                  // 是否保持连接
	responseDelay    time.Duration         // 响应延迟
	requestCount     int
	requestMutex     sync.Mutex
	probeData        []byte
	probeMutex       sync.Mutex
}

// NewTestServer 创建一个新的测试服务器
func NewTestServer(protocol string) *TestServer {
	server := &TestServer{
		protocol:         protocol,
		stopChan:         make(chan struct{}),
		rules:            make([]RequestResponseRule, 0),
		defaultResponses: make(map[string][]byte),
		keepAlive:        true,                 // 默认保持连接
		responseDelay:    0 * time.Millisecond, // 默认无延迟
	}
	return server
}

// SetKeepAlive 设置是否保持连接
func (s *TestServer) SetKeepAlive(keepAlive bool) {
	s.keepAlive = keepAlive
}

// SetResponseDelay 设置响应延迟
func (s *TestServer) SetResponseDelay(delay time.Duration) {
	s.responseDelay = delay
}

// AddRule 添加请求-响应规则
func (s *TestServer) AddRule(matcher RequestMatcher, handler ResponseHandler, priority int) {
	rule := RequestResponseRule{
		Matcher:  matcher,
		Handler:  handler,
		Priority: priority,
	}
	s.rules = append(s.rules, rule)

	// 按优先级排序规则
	s.sortRules()
}

// AddStringRule 添加基于字符串匹配的规则
func (s *TestServer) AddStringRule(pattern string, response []byte, priority int) {
	matcher := &StringMatcher{Pattern: pattern}
	handler := &StaticResponseHandler{Response: response}
	s.AddRule(matcher, handler, priority)
}

// AddRegexRule 添加基于正则表达式匹配的规则
func (s *TestServer) AddRegexRule(pattern string, response []byte, priority int) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}

	matcher := &RegexMatcher{Pattern: regex}
	handler := &StaticResponseHandler{Response: response}
	s.AddRule(matcher, handler, priority)
	return nil
}

// NewEmptyRequestMatcher 创建一个匹配空请求的匹配器
func NewEmptyRequestMatcher() RequestMatcher {
	return &StringMatcher{Pattern: ""}
}

// NewPrefixRequestMatcher 创建一个匹配前缀的匹配器
func NewPrefixRequestMatcher(prefix []byte) RequestMatcher {
	return &PrefixMatcher{Prefix: prefix}
}

// NewStaticResponseHandler 创建一个静态响应处理器
func NewStaticResponseHandler(response []byte) ResponseHandler {
	return &StaticResponseHandler{Response: response}
}

// sortRules 按优先级排序规则
func (s *TestServer) sortRules() {
	// 简单的冒泡排序，实际可以使用更高效的排序算法
	for i := 0; i < len(s.rules); i++ {
		for j := i + 1; j < len(s.rules); j++ {
			if s.rules[i].Priority < s.rules[j].Priority {
				s.rules[i], s.rules[j] = s.rules[j], s.rules[i]
			}
		}
	}
}

func (s *TestServer) StartWithListener(listener net.Listener) {
	s.tcpListener = listener
	s.address = listener.Addr().String()
	s.started = true
	s.wg.Add(1)
	go s.serveTCP()
}

// Start 启动测试服务器
func (s *TestServer) Start() error {
	var err error
	s.startOnce.Do(func() {
		// 根据协议类型创建不同的监听器
		if s.protocol == "tcp" {
			// 创建TCP监听器
			s.tcpListener, err = net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				err = fmt.Errorf("failed to create TCP listener: %v", err)
				return
			}
			// 获取分配的端口和地址
			s.port = s.tcpListener.Addr().(*net.TCPAddr).Port
			s.address = fmt.Sprintf("127.0.0.1:%d", s.port)
			s.started = true
			s.wg.Add(1)
			go s.serveTCP()
		} else {
			// 创建UDP监听器
			s.udpListener, err = net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				err = fmt.Errorf("failed to create UDP listener: %v", err)
				return
			}
			// 获取分配的端口和地址
			s.port = s.udpListener.LocalAddr().(*net.UDPAddr).Port
			s.address = fmt.Sprintf("127.0.0.1:%d", s.port)
			s.started = true
			s.wg.Add(1)
			go s.serveUDP()
		}

	})

	return err
}

// serveTCP 处理TCP连接
func (s *TestServer) serveTCP() {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		default:
			conn, err := s.tcpListener.Accept()
			if err != nil {
				select {
				case <-s.stopChan:
					return
				default:
					fmt.Printf("Error accepting connection: %v\n", err)
					continue
				}
			}
			// fmt.Printf("Accepted connection from %s\n", conn.RemoteAddr().String())
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				// 确保连接最终会关闭
				defer c.Close()

				// 设置读取超时
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				// 遍历规则列表，按优先级匹配
				for _, rule := range s.rules {
					if rule.Matcher.Match([]byte{}) {
						s.requestMutex.Lock()
						s.requestCount++
						s.requestMutex.Unlock()

						time.Sleep(s.responseDelay)
						response := rule.Handler.Handle([]byte{})
						_, _ = c.Write(response)
						return
					}
				}

				buffer := make([]byte, 4096) // 增大缓冲区
				n, err := c.Read(buffer)
				// 如果是超时错误，使用空请求
				if err != nil {
					var netErr net.Error
					if errors.As(err, &netErr) && netErr.Timeout() {
						// 超时，使用空请求继续处理
						buffer = []byte{}
						n = 0
					}
				}

				// 增加请求计数
				s.requestMutex.Lock()
				s.requestCount++
				s.requestMutex.Unlock()

				// 存储探针数据
				s.probeMutex.Lock()
				s.probeData = make([]byte, n)
				copy(s.probeData, buffer[:n])
				s.probeMutex.Unlock()

				// 处理请求数据
				request := buffer[:n]
				// 准备响应
				var response []byte
				matched := false

				// 遍历规则列表，按优先级匹配
				for _, rule := range s.rules {
					if rule.Matcher.Match(request) {
						response = rule.Handler.Handle(request)
						matched = true
						break
					}
				}
				// 如果仍然没有匹配的规则，关闭连接
				if !matched {
					return
				}
				// 发送响应
				if len(response) > 0 {
					// 设置写入超时
					c.SetWriteDeadline(time.Now().Add(5 * time.Second))
					time.Sleep(s.responseDelay)
					_, err = c.Write(response)
					if err != nil {
						fmt.Printf("Error writing to connection: %v\n", err)
						return
					}

					// 如果保持连接，等待更多请求
					if s.keepAlive {
						// 设置一个较长的读取超时，等待可能的后续请求
						_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))

						// 循环处理后续请求
						for {
							n, err := c.Read(buffer)
							if err != nil {
								if err == io.EOF {
									// 连接关闭，正常退出
									break
								}
								var netErr net.Error
								if errors.As(err, &netErr) && netErr.Timeout() {
									// 超时，正常退出
									break
								}
								// 其他错误
								fmt.Printf("Error reading subsequent request: %v\n", err)
								break
							}

							// 处理后续请求
							if n > 0 {
								request = buffer[:n]
								fmt.Printf("收到后续请求 (%d 字节): %s\n", len(request), FormatBytes(request))

								// 匹配规则
								matched = false
								for _, rule := range s.rules {
									if rule.Matcher.Match(request) {
										response = rule.Handler.Handle(request)
										matched = true
										fmt.Printf("匹配后续规则，将发送响应 (%d 字节): %s\n", len(response), FormatBytes(response))
										break
									}
								}

								// 发送响应
								if matched && len(response) > 0 {
									c.SetWriteDeadline(time.Now().Add(5 * time.Second))
									_, err = c.Write(response)
									if err != nil {
										fmt.Printf("Error writing subsequent response: %v\n", err)
										break
									}
								} else {
									// 没有匹配的规则，退出循环
									break
								}
							}
						}
					}
				}
			}(conn)
		}
	}
}

// ServeUDP 处理UDP连接
func (s *TestServer) serveUDP() {
	fmt.Println("Starting UDP server on", s.address)
	defer s.wg.Done()

	// 直接使用udpListener，它已经是PacketConn类型
	buffer := make([]byte, 4096) // UDP数据包缓冲区

	for {
		select {
		case <-s.stopChan:
			return
		default:
			// 设置读取超时
			s.udpListener.SetReadDeadline(time.Now().Add(5 * time.Second))

			// 从UDP连接读取数据
			n, addr, err := s.udpListener.ReadFrom(buffer)

			// 处理可能的错误
			if err != nil {
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					// 读取超时，继续循环
					continue
				}

				select {
				case <-s.stopChan:
					return
				default:
					fmt.Printf("Error reading from UDP: %v\n", err)
					continue
				}
			}

			fmt.Printf("Received UDP packet from %s\n", addr.String())

			// 增加请求计数
			s.requestMutex.Lock()
			s.requestCount++
			s.requestMutex.Unlock()

			// 存储探针数据
			s.probeMutex.Lock()
			s.probeData = make([]byte, n)
			copy(s.probeData, buffer[:n])
			s.probeMutex.Unlock()

			// 处理请求数据
			request := buffer[:n]
			// 准备响应
			var response []byte
			matched := false
			println("Received UDP packet data from", FormatBytes(request))
			// 遍历规则列表，按优先级匹配
			for _, rule := range s.rules {
				if rule.Matcher.Match(request) {
					// 添加延迟（如果配置了）
					time.Sleep(s.responseDelay)

					// 只处理一次请求
					response = rule.Handler.Handle(request)
					matched = true
					break
				}
			}

			// 如果没有匹配的规则，使用默认响应或继续
			if !matched {
				println("No matching rule found for UDP packet data", FormatBytes(request))
				if defaultResp, ok := s.defaultResponses["udp"]; ok {
					response = defaultResp
				} else {
					continue
				}
			}

			// 发送UDP响应
			if len(response) > 0 {
				s.udpListener.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_, err = s.udpListener.WriteTo(response, addr)
				if err != nil {
					fmt.Printf("Error writing UDP response: %v\n", err)
				}
			}
		}
	}
}

// Stop 停止测试服务器
func (s *TestServer) Stop() error {
	var err error
	s.stopOnce.Do(func() {
		if !s.started {
			return
		}
		// 发送停止信号
		close(s.stopChan)
		// 如果是HTTP服务器，关闭HTTP服务器
		if s.httpServer != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			shutdownErr := s.httpServer.Shutdown(ctx)
			if shutdownErr != nil && !strings.Contains(shutdownErr.Error(), "use of closed network connection") {
				fmt.Printf("Failed to shutdown HTTP server: %v\n", shutdownErr)
				err = shutdownErr
			}
		}
		// 关闭TCP监听器
		if s.tcpListener != nil {
			listenerErr := s.tcpListener.Close()
			if listenerErr != nil {
				fmt.Printf("Failed to close TCP listener: %v\n", listenerErr)
				if err == nil {
					err = listenerErr
				}
			}
		}

		// 关闭UDP监听器
		if s.udpListener != nil {
			listenerErr := s.udpListener.Close()
			if listenerErr != nil {
				fmt.Printf("Failed to close UDP listener: %v\n", listenerErr)
				if err == nil {
					err = listenerErr
				}
			}
		}
		// 等待所有goroutine结束，但设置超时避免无限阻塞
		waitCh := make(chan struct{})
		go func() {
			s.wg.Wait()
			close(waitCh)
		}()

		// 最多等待3秒
		select {
		case <-waitCh:
			// 正常结束
		case <-time.After(3 * time.Second):
			return
		}

		s.stopped = true
	})

	return err
}

// GetAddress 获取测试服务器的地址
func (s *TestServer) GetAddress() string {
	return s.address
}

// GetPort 获取测试服务器的端口
func (s *TestServer) GetPort() int {
	return s.port
}

// GetIP 获取测试服务器的IP
func (s *TestServer) GetIP() string {
	return "127.0.0.1"
}

// GetRequestCount 获取测试服务器的请求计数
func (s *TestServer) GetRequestCount() int {
	s.requestMutex.Lock()
	defer s.requestMutex.Unlock()
	return s.requestCount
}

// GetProbeData 获取最近接收到的探针数据
func (s *TestServer) GetProbeData() []byte {
	s.probeMutex.Lock()
	defer s.probeMutex.Unlock()
	return s.probeData
}

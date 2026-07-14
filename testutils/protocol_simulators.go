package testutils

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPServer 创建一个模拟HTTP服务器
func HTTPServer() *TestServer {
	server := NewTestServer("tcp")
	httpResponse := []byte("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\nConnection: keep-alive\r\n\r\n<html><body><h1>Test HTTP Server</h1></body></html>")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(httpResponse), 10)
	return server
}

// SSHServer 创建一个模拟SSH服务器
func SSHServer() *TestServer {
	server := NewTestServer("tcp")
	sshBanner := []byte("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(sshBanner), 10)

	// 添加对SSH协议握手的响应
	sshClientVersionMatcher := &StringMatcher{Pattern: "SSH-2.0-"}
	sshKeyExchangeResponse := []byte{
		0x00, 0x00, 0x01, 0x0c, // 包长度
		0x05, // 包类型 (SSH_MSG_SERVICE_ACCEPT)
		// 随机数据模拟SSH密钥交换响应
		0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
		0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
	}
	server.AddRule(sshClientVersionMatcher, NewStaticResponseHandler(sshKeyExchangeResponse), 5)

	return server
}

// FTPServer 创建一个模拟FTP服务器
func FTPServer() *TestServer {
	server := NewTestServer("tcp")
	ftpBanner := []byte("220 FTP Server - FileZilla\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(ftpBanner), 10)
	return server
}

// SMTPServer 创建一个模拟SMTP服务器
func SMTPServer() *TestServer {
	server := NewTestServer("tcp")
	smtpBanner := []byte("220 smtp.example.com ESMTP Postfix\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(smtpBanner), 10)

	// 添加对常见SMTP命令的响应
	heloMatcher := &StringMatcher{Pattern: "HELO "}
	heloResponse := []byte("250 Hello\r\n")
	server.AddRule(heloMatcher, NewStaticResponseHandler(heloResponse), 5)

	ehloMatcher := &StringMatcher{Pattern: "EHLO "}
	ehloResponse := []byte("250-smtp.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-STARTTLS\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250 DSN\r\n")
	server.AddRule(ehloMatcher, NewStaticResponseHandler(ehloResponse), 5)

	return server
}

// POP3Server 创建一个模拟POP3服务器
func POP3Server() *TestServer {
	server := NewTestServer("tcp")
	pop3Banner := []byte("+OK POP3 server ready\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(pop3Banner), 10)

	// 添加对常见POP3命令的响应
	userMatcher := &StringMatcher{Pattern: "USER "}
	userResponse := []byte("+OK\r\n")
	server.AddRule(userMatcher, NewStaticResponseHandler(userResponse), 5)

	passMatcher := &StringMatcher{Pattern: "PASS "}
	passResponse := []byte("+OK Logged in.\r\n")
	server.AddRule(passMatcher, NewStaticResponseHandler(passResponse), 5)

	statMatcher := &StringMatcher{Pattern: "STAT"}
	statResponse := []byte("+OK 2 320\r\n")
	server.AddRule(statMatcher, NewStaticResponseHandler(statResponse), 5)

	return server
}

// IMAPServer 创建一个模拟IMAP服务器
func IMAPServer() *TestServer {
	server := NewTestServer("tcp")
	imapBanner := []byte("* OK Welcome to Binc IMAP v1\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(imapBanner), 10)
	return server
}

// DNSServer 创建一个模拟DNS服务器
func DNSServer() *TestServer {
	server := NewTestServer("udp")
	//b'\x00\x06\x81\x82\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
	// 标准DNS响应包
	dnsResponse := []byte{
		0x00, 0x06, // Transaction ID
		0x81, 0x82, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00,       // Root domain
		0x00, 0x10, // Type A
		0x00, 0x03, // Class CH
		// Answer
		0xc0, 0x0c, // Pointer to domain name
		0x00, 0x10, // Type A
		0x00, 0x03, // Class CH
		0x00, 0x00, 0x00, 0x3c, // TTL (60 seconds)
		0x00, 0x04, // Data length
		0x7f, 0x00, 0x00, 0x01, // IP (127.0.0.1)
	}

	// DNS版本查询响应（用于服务识别）
	dnsVersionResponse := []byte{
		0x00, 0x06, // Transaction ID (与请求匹配)
		0x81, 0x80, // Flags (标准响应)
		0x00, 0x01, // Questions
		0x00, 0x01, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query section (复制请求中的查询)
		0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
		0x04, 'b', 'i', 'n', 'd',
		0x00,       // Root domain
		0x00, 0x10, // Type TXT
		0x00, 0x03, // Class CH
		// Answer section
		0xc0, 0x0c, // Pointer to domain name
		0x00, 0x10, // Type TXT
		0x00, 0x03, // Class CH
		0x00, 0x00, 0x00, 0x3c, // TTL (60 seconds)
		0x00, 0x0b, // Data length (11 bytes)
		0x0a,                                             // Text length (10 bytes)
		'9', '.', '1', '1', '.', '3', '-', 'P', '1', '2', // BIND版本
	}

	// 匹配标准DNS查询
	dnsMatcher := &PrefixMatcher{Prefix: []byte{0x00}}
	server.AddRule(dnsMatcher, NewStaticResponseHandler(dnsResponse), 20)

	// 匹配DNS版本查询（用于服务识别）
	dnsVersionMatcher := &PrefixMatcher{Prefix: []byte{0x00, 0x06, 0x01}}
	server.AddRule(dnsVersionMatcher, NewStaticResponseHandler(dnsVersionResponse), 30)

	return server
}

// MySQLServer 创建一个模拟MySQL服务器
func MySQLServer() *TestServer {
	server := NewTestServer("tcp")

	// MySQL初始握手包
	mysqlGreeting := []byte{
		0x4a, 0x00, 0x00, 0x00, // 包长度
		0x0a,                                     // 协议版本
		0x35, 0x2e, 0x37, 0x2e, 0x33, 0x38, 0x00, // 服务器版本 (5.7.38)
		0x01, 0x00, 0x00, 0x00, // 线程ID
		0x4e, 0x52, 0x73, 0x67, 0x00, // 盐值前8字节
		0x00,       // 填充
		0xff, 0xf7, // 服务器能力标志低16位
		0x21,       // 字符集
		0x02, 0x00, // 服务器状态
		0xff, 0x81, // 服务器能力标志高16位
		0x15,                                                       // 盐值长度
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 填充
		0x64, 0x76, 0x48, 0x53, 0x52, 0x43, 0x55, 0x64, 0x53, 0x38, 0x65, 0x6b, 0x00, // 盐值后13字节
		0x6d, 0x79, 0x73, 0x71, 0x6c, 0x5f, 0x6e, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, // 认证插件名
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(mysqlGreeting), 10)

	return server
}

// PostgreSQLServer 创建一个模拟PostgreSQL服务器
func PostgreSQLServer() *TestServer {
	server := NewTestServer("tcp")

	// PostgreSQL错误响应 - 使用更可读的格式
	// 创建字节数组并连接多个部分
	//E\x00\x00\x00\xceSFATAL\x00VFATAL\x00C0A000\x00Munsupported frontend protocol 65363.19778: server supports 2.0 to 3.0\x00Fd:\\pginstaller_12.auto\\postgres.windows-x64\\src\\backend\\postmaster\\postmaster.c\x00L2093\x00RProcessStartupPacket\x00\x00
	pgAuthRequest, _ := hex.DecodeString("45000000ce53464154414c0056464154414c00433041303030004d756e737570706f727465642066726f6e74656e642070726f746f636f6c2036353336332e31393737383a2073657276657220737570706f72747320322e3020746f20332e300046643a5c7067696e7374616c6c65725f31322e6175746f5c706f7374677265732e77696e646f77732d7836345c7372635c6261636b656e645c706f73746d61737465725c706f73746d61737465722e63004c32303933005250726f63657373537461727475705061636b65740000")

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(pgAuthRequest), 10)

	return server
}

// RedisServer 创建一个模拟Redis服务器
func RedisServer() *TestServer {
	server := NewTestServer("tcp")
	// Redis服务器响应
	redisResponse := []byte("-NOAUTH Authentication required.\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(redisResponse), 10)
	return server
}

// MongoDBServer 创建一个模拟MongoDB服务器
func MongoDBServer() *TestServer {
	server := NewTestServer("tcp")

	// MongoDB服务器响应
	mongoResponse := []byte{
		0x3c, 0x00, 0x00, 0x00, // 消息长度
		0x00, 0x00, 0x00, 0x00, // 请求ID
		0x00, 0x00, 0x00, 0x00, // 响应ID
		0x01, 0x00, 0x00, 0x00, // opCode (OP_REPLY)
		0x00, 0x00, 0x00, 0x00, // 响应标志
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // cursorID
		0x00, 0x00, 0x00, 0x00, // 起始位置
		0x01, 0x00, 0x00, 0x00, // 返回文档数量
		// BSON文档开始
		0x1c, 0x00, 0x00, 0x00, // 文档大小
		0x02,                                    // 字符串类型
		'v', 'e', 'r', 's', 'i', 'o', 'n', 0x00, // 字段名
		0x0c, 0x00, 0x00, 0x00, // 字符串长度
		'4', '.', '4', '.', '6', 0x00, // 字符串值
		0x00, // 文档结束
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(mongoResponse), 10)

	return server
}

// LDAPServer 创建一个模拟LDAP服务器
func LDAPServer() *TestServer {
	server := NewTestServer("tcp")

	// LDAP绑定响应
	ldapBindResponse := []byte{
		0x30, 0x0c, // LDAP消息序列
		0x02, 0x01, 0x01, // 消息ID
		0x61, 0x07, // 绑定响应
		0x0a, 0x01, 0x00, // 结果代码 (成功)
		0x04, 0x00, // 匹配的DN
		0x04, 0x00, // 错误消息
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(ldapBindResponse), 10)

	return server
}

// SMBServer 创建一个模拟SMB服务器
func SMBServer() *TestServer {
	server := NewTestServer("tcp")

	// SMB协议协商响应
	smbResponse := []byte{
		0x00, 0x00, 0x00, 0x55, // NetBIOS会话服务头
		0xff, 0x53, 0x4d, 0x42, // SMB协议标识
		0x72,                   // SMB命令 (协商协议)
		0x00, 0x00, 0x00, 0x00, // 状态
		0x98,       // 标志
		0x53, 0xc8, // 标志2
		0x00, 0x00, // 进程ID高位
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 签名
		0x00, 0x00, // 保留
		0x00, 0x00, // 树ID
		0x00, 0x00, // 进程ID
		0x00, 0x00, // 用户ID
		0x00, 0x00, // 多路复用ID
		// 以下是协商响应特定数据
		0x11, 0x00, // 字节计数
		0x00,       // 字数
		0x02, 0x00, // 方言计数
		0x01, 0x00, // 安全模式
		0x00, 0x00, // 最大缓冲区大小
		0x01, 0x00, // 最大挂起请求
		0x00, 0x00, 0x00, 0x00, // 会话密钥
		0x00, 0x00, 0x00, 0x00, // 能力
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 服务器时间
		0x00, 0x00, // 服务器时区
		0x00, // 密钥长度
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(smbResponse), 10)

	return server
}

// RDPServer 创建一个模拟RDP服务器
func RDPServer() *TestServer {
	server := NewTestServer("tcp")

	// RDP连接确认响应
	rdpResponse := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT头
		0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(rdpResponse), 10)

	return server
}

// TelnetServer 创建一个模拟Telnet服务器
func TelnetServer() *TestServer {
	server := NewTestServer("tcp")

	// Telnet欢迎消息
	telnetBanner := []byte("\xff\xfb\x01\xff\xfb\x03\xff\xfd\x03\xff\xfe\x01Welcome to Telnet Server\r\nlogin: ")

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(telnetBanner), 10)

	return server
}

// VNCServer 创建一个模拟VNC服务器
func VNCServer() *TestServer {
	server := NewTestServer("tcp")

	// VNC协议版本响应
	vncResponse := []byte("RFB 003.008\n")

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(vncResponse), 10)

	return server
}

// SNMPServer 创建一个模拟SNMP服务器
func SNMPServer() *TestServer {
	server := NewTestServer("udp")

	// SNMP响应包（简化版本）
	snmpResponse := []byte{
		0x30, 0x29, // SEQUENCE
		0x02, 0x01, 0x00, // Version: v1
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', // Community: public
		0xa2, 0x1c, // GetResponse
		0x02, 0x04, 0x4c, 0xd8, 0xc4, 0x43, // RequestID
		0x02, 0x01, 0x00, // ErrorStatus: no error
		0x02, 0x01, 0x00, // ErrorIndex: 0
		0x30, 0x0e, // VarBindList
		0x30, 0x0c, // VarBind
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
		0x04, 0x00, // Value: empty string
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(snmpResponse), 10)

	return server
}

// TLSServer
func TLSServer() (*TestServer, error) {
	server := NewTestServer("tcp")
	// 生成自签名证书
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		return nil, err
	}
	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	// 创建TLS监听器
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}
	// 添加TLS握手响应
	tlsResponse := []byte{0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x00}
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(tlsResponse), 10)
	server.StartWithListener(listener)

	return server, nil
}

// SimpleTLSServer 类型定义，用于管理简单的TLS服务器
type SimpleTLSServer struct {
	Listener net.Listener
	Address  string
	Stopped  bool
	mutex    sync.Mutex
}

// NewSimpleTLSServer 创建一个简单的TLS服务器，保持连接活跃
func NewSimpleTLSServer() (*SimpleTLSServer, error) {
	// 生成自签名证书
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		return nil, err
	}
	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS10,
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}
	// 创建TLS监听器
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}
	server := &SimpleTLSServer{
		Listener: listener,
		Address:  listener.Addr().String(),
		Stopped:  false,
	}

	return server, nil
}

// Start 启动TLS服务器
func (s *SimpleTLSServer) Start() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.Stopped {
		return fmt.Errorf("服务器已经停止")
	}

	// 在后台处理连接
	go func() {
		for {
			s.mutex.Lock()
			if s.Stopped {
				s.mutex.Unlock()
				break
			}
			s.mutex.Unlock()

			conn, err := s.Listener.Accept()
			if err != nil {
				// 如果服务器已停止，则退出
				s.mutex.Lock()
				stopped := s.Stopped
				s.mutex.Unlock()
				if stopped {
					break
				}
				// 否则打印错误并继续
				fmt.Printf("接受连接错误: %v\n", err)
				continue
			}

			// 启动一个goroutine处理每个连接
			go func(c net.Conn) {
				// TLS握手已经在Accept时自动完成
				// 保持连接活跃，但不发送数据
				buf := make([]byte, 1024)
				for {
					// 检查服务器是否已停止
					s.mutex.Lock()
					if s.Stopped {
						s.mutex.Unlock()
						c.Close()
						break
					}
					s.mutex.Unlock()

					// 设置读取超时，防止阻塞
					c.SetReadDeadline(time.Now().Add(10 * time.Second))
					_, err := c.Read(buf)
					if err != nil {
						// 超时错误可以忽略，继续保持连接
						if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
							continue
						}
						// 其他错误则关闭连接
						c.Close()
						break
					}
					// 收到数据也不需要处理，保持连接即可
				}
			}(conn)
		}
	}()

	return nil
}

// Stop 停止TLS服务器
func (s *SimpleTLSServer) Stop() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.Stopped {
		return nil
	}

	s.Stopped = true
	return s.Listener.Close()
}

// GetAddress 返回TLS服务器的地址
func (s *SimpleTLSServer) GetAddress() string {
	return s.Address
}

// RealHTTPSServer 创建一个真实的HTTPS服务器
type RealHTTPSServer struct {
	Server   *http.Server
	Listener net.Listener
	Address  string
}

// GetAddress 返回HTTPS服务器的地址
func (s *RealHTTPSServer) GetAddress() string {
	return s.Address
}

// Stop 停止HTTPS服务器
func (s *RealHTTPSServer) Stop() error {
	if s.Server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.Server.Shutdown(ctx)
	}
	return nil
}

// RealTLSServer 创建一个真实的TLS服务器，使用标准库的HTTPS实现
func RealTLSServer() (*RealHTTPSServer, error) {
	// 生成自签名证书
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		return nil, err
	}

	// 创建TLS配置 - 使用更完整的TLS配置
	tlsConfig := &tls.Config{
		Certificates:             []tls.Certificate{cert},
		MinVersion:               tls.VersionTLS10, // 支持较旧版本以增加兼容性
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
	}

	// 创建TLS监听器
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}

	// 创建一个简单的HTTP服务器，添加明显的SSL相关响应头
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 添加更多的SSL相关响应头
			w.Header().Set("Server", "TestTLSServer/1.0")
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Write([]byte("TLS Test Server - Secure Connection Established"))
		}),
		TLSConfig: tlsConfig, // 确保服务器使用同样的TLS配置
	}

	// 在后台启动HTTP服务器
	go func() {
		// 使用TLS监听器直接提供TLS服务
		err := httpServer.Serve(listener)
		if err != nil {
			fmt.Printf("HTTPS服务器错误: %v\n", err)
		}
	}()

	// 创建RealHTTPSServer实例
	server := &RealHTTPSServer{
		Server:   httpServer,
		Listener: listener,
		Address:  listener.Addr().String(),
	}

	return server, nil
}

// SMTPSServer 创建一个模拟SMTP over TLS服务器
func SMTPSServer() (*TestServer, error) {
	server := NewTestServer("tcp")

	// 添加SMTP响应
	smtpBanner := []byte("220 smtp.example.com ESMTP Service ready\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(smtpBanner), 10)

	// 生成自签名证书
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		return nil, err
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// 创建TLS监听器
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}

	// 启动服务器
	server.StartWithListener(listener)

	return server, nil
}

// IMAPSServer 创建一个模拟IMAP over TLS服务器
func IMAPSServer() (*TestServer, error) {
	server := NewTestServer("tcp")

	// 添加IMAP响应
	imapBanner := []byte("* OK IMAP4rev1 Service Ready\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(imapBanner), 10)

	// 生成自签名证书
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		return nil, err
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// 创建TLS监听器
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}

	// 启动服务器
	server.StartWithListener(listener)

	return server, nil
}

// POP3SServer 创建一个模拟POP3 over TLS服务器
func POP3SServer() (*TestServer, error) {
	server := NewTestServer("tcp")

	// 添加POP3响应
	pop3Banner := []byte("+OK POP3 server ready\r\n")
	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(pop3Banner), 10)

	// 生成自签名证书
	cert, err := generateSelfSignedCert("localhost")
	if err != nil {
		return nil, err
	}

	// 创建TLS配置
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// 创建TLS监听器
	listener, err := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	if err != nil {
		return nil, err
	}

	// 启动服务器
	server.StartWithListener(listener)

	return server, nil
}

// generateSelfSignedCert 生成自签名证书
func generateSelfSignedCert(host string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   host,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = append(template.IPAddresses, ip)
	} else {
		template.DNSNames = append(template.DNSNames, host)
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

// ElasticsearchServer 创建一个模拟Elasticsearch服务器
func ElasticsearchServer() *TestServer {
	server := NewTestServer("tcp")

	// Elasticsearch响应
	esResponse := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"name\":\"test_node\",\"cluster_name\":\"elasticsearch\",\"version\":{\"number\":\"7.10.0\"}}")

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(esResponse), 10)

	return server
}

// WebSocketServer 创建一个模拟WebSocket服务器
func WebSocketServer() *TestServer {
	server := NewTestServer("tcp")

	// WebSocket握手响应
	wsResponse := []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n")

	// 匹配WebSocket握手请求
	wsMatcher := &StringMatcher{Pattern: "Sec-WebSocket-Key:"}
	server.AddRule(wsMatcher, NewStaticResponseHandler(wsResponse), 10)

	return server
}

// RTSPServer 创建一个模拟RTSP服务器
func RTSPServer() *TestServer {
	server := NewTestServer("tcp")

	// RTSP响应
	rtspResponse := []byte("RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: TestRTSP/1.0\r\n\r\n")

	// 匹配RTSP请求
	rtspMatcher := &StringMatcher{Pattern: "RTSP/1.0"}
	server.AddRule(rtspMatcher, NewStaticResponseHandler(rtspResponse), 10)

	return server
}

// SIPServer 创建一个模拟SIP服务器
func SIPServer() *TestServer {
	server := NewTestServer("udp") // SIP通常使用UDP

	// SIP响应
	sipResponse := []byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1-0\r\nFrom: <sip:test@127.0.0.1>;tag=tag-1\r\nTo: <sip:test@127.0.0.1>;tag=tag-2\r\nCall-ID: call-id-1\r\nCSeq: 1 REGISTER\r\nContact: <sip:test@127.0.0.1:5060>\r\nContent-Length: 0\r\n\r\n")

	// 匹配SIP请求
	sipMatcher := &StringMatcher{Pattern: "SIP/2.0"}
	server.AddRule(sipMatcher, NewStaticResponseHandler(sipResponse), 10)

	return server
}

// ModbusServer 创建一个模拟Modbus服务器
func ModbusServer() *TestServer {
	server := NewTestServer("tcp")

	// Modbus响应
	modbusResponse := []byte{
		0x00, 0x01, // 事务标识符
		0x00, 0x00, // 协议标识符
		0x00, 0x05, // 长度
		0x01,       // 单元标识符
		0x03,       // 功能码 (读保持寄存器)
		0x02,       // 字节计数
		0x12, 0x34, // 寄存器值
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(modbusResponse), 10)

	return server
}

// BACnetServer 创建一个模拟BACnet服务器
func BACnetServer() *TestServer {
	server := NewTestServer("udp")

	// BACnet响应
	bacnetResponse := []byte{
		0x81, 0x0a, 0x00, 0x14, // BVLC头
		0x01, 0x00, 0x00, 0x00, // NPDU
		0x10, 0x08, // APDU类型
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 对象标识符
	}

	server.AddRule(NewEmptyRequestMatcher(), NewStaticResponseHandler(bacnetResponse), 10)

	return server
}

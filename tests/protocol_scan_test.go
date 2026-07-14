package tests

import (
	"context"
	"fmt"
	"testing"

	"github.com/hexbay/xmap/pkg/api"
	"github.com/hexbay/xmap/pkg/types"
	"github.com/hexbay/xmap/testutils"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/assert"
)

func CreateXmapInstance() *api.XMap {
	opt := types.DefaultOptions()
	opt.VersionIntensity = 9
	//opt.DebugRequest = true
	//opt.DebugResponse = true
	xmap, err := api.New(opt)
	if err != nil {
		panic(err)
	}
	return xmap
}

// TestHTTPScan 测试HTTP服务识别
func TestHTTPScan(t *testing.T) {
	//gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建HTTP服务模拟器
	server := testutils.HTTPServer()
	err := server.Start()
	assert.NoError(t, err, "启动HTTP测试服务器失败")
	defer server.Stop()
	fmt.Printf("HTTP服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	// 验证扫描结果
	assert.NoError(t, err, "扫描HTTP服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "http", result.Service, "服务识别错误")
}

// TestSSHScan 测试SSH服务识别
func TestSSHScan(t *testing.T) {
	// 创建SSH服务模拟器
	server := testutils.SSHServer()
	err := server.Start()
	assert.NoError(t, err, "启动SSH测试服务器失败")
	defer server.Stop()
	fmt.Printf("SSH服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap, err := api.New(types.DefaultOptions())
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描SSH服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "ssh", result.Service, "服务识别错误")
	assert.Contains(t, string(result.RawResponse), "SSH-2.0-OpenSSH", "Banner识别错误")
}

// TestFTPScan 测试FTP服务识别
func TestFTPScan(t *testing.T) {
	// 创建FTP服务模拟器
	server := testutils.FTPServer()
	err := server.Start()
	assert.NoError(t, err, "启动FTP测试服务器失败")
	defer server.Stop()

	fmt.Printf("FTP服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描FTP服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "ftp", result.Service, "服务识别错误")
	assert.Contains(t, string(result.RawResponse), "220 FTP Server - FileZilla", "Banner识别错误")
}

// TestSMTPScan 测试SMTP服务识别
func TestSMTPScan(t *testing.T) {
	// 创建SMTP服务模拟器
	server := testutils.SMTPServer()
	err := server.Start()
	assert.NoError(t, err, "启动SMTP测试服务器失败")
	defer server.Stop()

	fmt.Printf("SMTP服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap, err := api.New(types.DefaultOptions())
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描SMTP服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "smtp", result.Service, "服务识别错误")
	assert.Contains(t, string(result.RawResponse), "smtp.example.com", "Banner识别错误")
}

// TestPOP3Scan 测试POP3服务识别
func TestPOP3Scan(t *testing.T) {
	// 创建POP3服务模拟器
	server := testutils.POP3Server()
	err := server.Start()
	assert.NoError(t, err, "启动POP3测试服务器失败")
	defer server.Stop()
	fmt.Printf("POP3服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap, err := api.New(types.DefaultOptions())
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描POP3服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "pop3", result.Service, "服务识别错误")
	assert.Contains(t, string(result.RawResponse), "+OK", "Banner识别错误")
}

// TestIMAPScan 测试IMAP服务识别
func TestIMAPScan(t *testing.T) {
	// 创建IMAP服务模拟器
	server := testutils.IMAPServer()
	err := server.Start()
	assert.NoError(t, err, "启动IMAP测试服务器失败")
	defer server.Stop()
	fmt.Printf("IMAP服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描IMAP服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "imap", result.Service, "服务识别错误")
	assert.Contains(t, string(result.RawResponse), "IMAP", "Banner识别错误")
}

// TestMySQLScan 测试MySQL服务识别
func TestMySQLScan(t *testing.T) {
	server := testutils.MySQLServer()
	err := server.Start()
	assert.NoError(t, err, "启动MySQL测试服务器失败")
	defer server.Stop()
	fmt.Printf("MySQL服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描MySQL服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "mysql", result.Service, "服务识别错误")
}

// TestPostgreSQLScan 测试PostgreSQL服务识别
func TestPostgreSQLScan(t *testing.T) {
	// 创建PostgreSQL服务模拟器
	server := testutils.PostgreSQLServer()
	err := server.Start()
	assert.NoError(t, err, "启动PostgreSQL测试服务器失败")
	defer server.Stop()
	fmt.Printf("PostgreSQL服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描PostgreSQL服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	println(result.Service)
	assert.Equal(t, "postgresql", result.Service, "服务识别错误")
}

// TestRedisScan 测试Redis服务识别
func TestRedisScan(t *testing.T) {
	// 创建Redis服务模拟器
	server := testutils.RedisServer()
	err := server.Start()
	assert.NoError(t, err, "启动Redis测试服务器失败")
	defer server.Stop()
	fmt.Printf("Redis服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描Redis服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "redis", result.Service, "服务识别错误")
}

// TestDNSScan 测试DNS服务识别 (UDP)
func TestDNSScan(t *testing.T) {
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	// 创建DNS服务模拟器
	server := testutils.DNSServer()
	err := server.Start()
	assert.NoError(t, err, "启动DNS测试服务器失败")
	defer server.Stop()
	fmt.Printf("DNS服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	target.Protocol = "udp"
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描DNS服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "dns", result.Service, "服务识别错误")
}

// TestSNMPScan 测试SNMP服务识别 (UDP)
func TestSNMPScan(t *testing.T) {
	server := testutils.SNMPServer()
	err := server.Start()
	assert.NoError(t, err, "启动SNMP测试服务器失败")
	defer server.Stop()
	fmt.Printf("SNMP服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	target.Protocol = "udp"
	ctx := context.Background()
	xmap := CreateXmapInstance()
	assert.NoError(t, err, "创建XMap实例失败")
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描SNMP服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	assert.Equal(t, "snmp", result.Service, "服务识别错误")
}

// TestSimpleTLSScan 测试TLS服务识别（真实TLS握手并保持连接活跃）
func TestTLSScan(t *testing.T) {
	// 创建TLS服务器
	//gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	server, err := testutils.TLSServer()
	assert.NoError(t, err, "创建TLS测试服务器失败")
	// 启动服务器
	err = server.Start()
	assert.NoError(t, err, "启动TLS测试服务器失败")
	defer server.Stop()
	fmt.Printf("TLS服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描简单TLS服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	// 验证服务识别结果
	assert.Equal(t, "ssl", result.Service, "服务识别错误")
	assert.Equal(t, "tcp", result.Protocol, "协议识别错误")
	assert.Equal(t, true, result.SSL, "SSL识别错误")
}

func TestRealTLSScan(t *testing.T) {
	// 创建TLS服务器
	//gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	server, err := testutils.RealTLSServer()
	assert.NoError(t, err, "创建真实TLS测试服务器失败")
	defer server.Stop()

	target := types.NewTarget("https://" + server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描简单TLS服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	// 验证服务识别结果
	assert.Equal(t, "https", result.Service, "服务识别错误")
	assert.Equal(t, "tcp", result.Protocol, "协议识别错误")
	assert.Equal(t, true, result.SSL, "SSL识别错误")
	assert.NotNil(t, result.Certificate)
	assert.True(t, len(result.Certificate.CertInfo) > 0)
}

// TestSMTPSScan 测试SMTP over TLS服务识别
func TestSMTPSScan(t *testing.T) {
	// 创建SMTPS服务模拟器
	server, err := testutils.SMTPSServer()
	assert.NoError(t, err, "创建SMTPS测试服务器失败")
	defer server.Stop()
	fmt.Printf("SMTPS服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描SMTPS服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	// 注意：可能会识别为smtp或ssl/tls
	assert.NotEqual(t, "", result.Service, "服务识别失败")
}

// TestIMAPSScan 测试IMAP over TLS服务识别
func TestIMAPSScan(t *testing.T) {
	// 创建IMAPS服务模拟器
	server, err := testutils.IMAPSServer()
	assert.NoError(t, err, "创建IMAPS测试服务器失败")
	defer server.Stop()
	fmt.Printf("IMAPS服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描IMAPS服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	// 注意：可能会识别为imap或ssl/tls
	assert.NotEqual(t, "", result.Service, "服务识别失败")
}

// TestPOP3SScan 测试POP3 over TLS服务识别
func TestPOP3SScan(t *testing.T) {
	// 创建POP3S服务模拟器
	server, err := testutils.POP3SServer()
	assert.NoError(t, err, "创建POP3S测试服务器失败")
	defer server.Stop()
	fmt.Printf("POP3S服务器已启动，地址: %s\n", server.GetAddress())
	target := types.NewTarget(server.GetAddress())
	ctx := context.Background()
	xmap := CreateXmapInstance()
	result, err := xmap.Scan(ctx, target)
	assert.NoError(t, err, "扫描POP3S服务失败")
	assert.NotNil(t, result, "扫描结果不应为空")
	// 注意：可能会识别为pop3或ssl/tls
	assert.NotEqual(t, "", result.Service, "服务识别失败")
}

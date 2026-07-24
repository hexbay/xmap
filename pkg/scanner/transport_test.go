package scanner

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/hexbay/xmap/pkg/types"
	"github.com/stretchr/testify/require"
)

type stubSession struct{ ip string }

func (s stubSession) Write([]byte, WritePolicy) (int, error) { return 0, nil }
func (s stubSession) Read(ReadPolicy) ([]byte, error)        { return nil, nil }
func (s stubSession) RemoteIP() string                       { return s.ip }
func (s stubSession) Close() error                           { return nil }

func TestConnSessionReadsResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = server.Write([]byte("hello world"))
	}()

	response, err := (connSession{Conn: client}).Read(ReadPolicy{OverallTimeout: time.Second, MaxBytes: 4096})
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), response)
}

func TestConnSessionCollectsFragmentsWithinIdleWindow(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = server.Write([]byte("hello "))
		time.Sleep(10 * time.Millisecond)
		_, _ = server.Write([]byte("world"))
		_ = server.Close()
	}()

	response, err := (connSession{Conn: client}).Read(ReadPolicy{
		OverallTimeout: time.Second,
		IdleTimeout:    100 * time.Millisecond,
		MaxBytes:       4096,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("hello world"), response)
}

func TestConnSessionReturnsPartialResponseAfterIdleTimeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = server.Write([]byte("partial")) }()

	response, err := (connSession{Conn: client}).Read(ReadPolicy{
		OverallTimeout: time.Second,
		IdleTimeout:    10 * time.Millisecond,
		MaxBytes:       4096,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("partial"), response)
}

func TestConnSessionHonorsMaxBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = server.Write([]byte("more than four bytes")) }()

	response, err := (connSession{Conn: client}).Read(ReadPolicy{
		OverallTimeout: time.Second,
		MaxBytes:       4,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("more"), response)
}

func TestConnSessionSingleReadReturnsWithoutIdleWait(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() { _, _ = server.Write([]byte("datagram")) }()

	started := time.Now()
	response, err := (connSession{Conn: client}).Read(ReadPolicy{
		OverallTimeout: time.Second,
		IdleTimeout:    200 * time.Millisecond,
		MaxBytes:       4096,
		SingleRead:     true,
	})
	require.NoError(t, err)
	require.Equal(t, []byte("datagram"), response)
	require.Less(t, time.Since(started), 100*time.Millisecond)
}

func TestConnSessionWriteHonorsDeadline(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	_, err := (connSession{Conn: client}).Write([]byte("blocked"), WritePolicy{Timeout: 10 * time.Millisecond})
	require.Error(t, err)
}

func TestDialerTransportHonorsCanceledContext(t *testing.T) {
	transport, err := newDialerTransport()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = transport.Open(ctx, types.NewTarget("127.0.0.1:1"), false, time.Second)
	require.Error(t, err)
}

func TestDialerTransportDoesNotMutateTarget(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = conn.Close()
		}
	}()

	transport, err := newDialerTransport()
	require.NoError(t, err)
	target := types.NewTarget(fmt.Sprintf("localhost:%d", listener.Addr().(*net.TCPAddr).Port))
	require.Empty(t, target.IP)
	session, err := transport.Open(context.Background(), target, false, time.Second)
	require.NoError(t, err)
	require.NoError(t, session.Close())
	require.Empty(t, target.IP)
}

func TestResolvedIPIsStoredOnResultNotInputTarget(t *testing.T) {
	target := types.NewTarget("example.test:443")
	result := types.NewScanResult(target)
	(&ServiceScanner{}).setResolvedIP(result, stubSession{ip: "192.0.2.10"})

	require.Equal(t, "192.0.2.10", result.IP)
	require.Empty(t, target.IP)
}

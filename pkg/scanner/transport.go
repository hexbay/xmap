package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/hexbay/xmap/pkg/types"
	"github.com/projectdiscovery/fastdialer/fastdialer"
)

// Transport owns connection creation. It is deliberately independent from
// probe selection and matching, making network behavior injectable in tests.
type Transport interface {
	Open(context.Context, *types.ScanTarget, bool, time.Duration) (Session, error)
}

// ClosableTransport is implemented by transports that retain resources such
// as DNS caches or connection pools.
type ClosableTransport interface {
	Transport
	Close() error
}

// RateLimitedTransport applies a shared global rate limiter before every
// connection attempt. A single limiter may be passed to many engines.
type RateLimitedTransport struct {
	base    Transport
	limiter types.RateLimiter
}

func NewRateLimitedTransport(base Transport, limiter types.RateLimiter) Transport {
	if limiter == nil {
		return base
	}
	return &RateLimitedTransport{base: base, limiter: limiter}
}

func (t *RateLimitedTransport) Open(ctx context.Context, target *types.ScanTarget, tls bool, timeout time.Duration) (Session, error) {
	if err := t.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return t.base.Open(ctx, target, tls, timeout)
}

func (t *RateLimitedTransport) Close() error {
	if base, ok := t.base.(ClosableTransport); ok {
		return base.Close()
	}
	return nil
}

// Session represents exactly one protocol conversation.
type Session interface {
	Write([]byte, WritePolicy) (int, error)
	Read(ReadPolicy) ([]byte, error)
	RemoteIP() string
	Close() error
}

type WritePolicy struct {
	Timeout time.Duration
}

type ReadPolicy struct {
	OverallTimeout time.Duration
	IdleTimeout    time.Duration
	MaxBytes       int
	SingleRead     bool
}

type dialerTransport struct{ dialer *fastdialer.Dialer }

func (t *dialerTransport) Close() error {
	t.dialer.Close()
	return nil
}

func newDialerTransport() (*dialerTransport, error) {
	dialer, err := fastdialer.NewDialer(fastdialer.DefaultOptions)
	if err != nil {
		return nil, err
	}
	return &dialerTransport{dialer: dialer}, nil
}

func (t *dialerTransport) Open(ctx context.Context, target *types.ScanTarget, tls bool, timeout time.Duration) (Session, error) {
	host := target.Host
	if host == "" {
		host = target.IP
	}
	network := target.Protocol
	if network != "udp" {
		network = "tcp"
	}
	address := fmt.Sprintf("%s:%d", host, target.Port)
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var conn net.Conn
	var err error
	if tls {
		conn, err = t.dialer.DialTLS(dialCtx, network, address)
	} else {
		conn, err = t.dialer.Dial(dialCtx, network, address)
	}
	if err != nil {
		return nil, err
	}
	return connSession{Conn: conn}, nil
}

type connSession struct{ net.Conn }

func (s connSession) RemoteIP() string {
	switch addr := s.Conn.RemoteAddr().(type) {
	case *net.TCPAddr:
		return addr.IP.String()
	case *net.UDPAddr:
		return addr.IP.String()
	default:
		return ""
	}
}

func (s connSession) Write(data []byte, policy WritePolicy) (int, error) {
	if policy.Timeout <= 0 {
		policy.Timeout = time.Second
	}
	if err := s.SetWriteDeadline(time.Now().Add(policy.Timeout)); err != nil {
		return 0, err
	}
	return s.Conn.Write(data)
}

func (s connSession) Read(policy ReadPolicy) ([]byte, error) {
	if policy.OverallTimeout <= 0 {
		policy.OverallTimeout = time.Second
	}
	if policy.IdleTimeout <= 0 {
		policy.IdleTimeout = 50 * time.Millisecond
	}
	if policy.MaxBytes <= 0 {
		policy.MaxBytes = 4096
	}
	deadline := time.Now().Add(policy.OverallTimeout)
	buf := make([]byte, 1024)
	var response []byte
	for len(response) < policy.MaxBytes {
		readDeadline := deadline
		if len(response) > 0 && time.Until(deadline) > policy.IdleTimeout {
			readDeadline = time.Now().Add(policy.IdleTimeout)
		}
		if err := s.SetReadDeadline(readDeadline); err != nil {
			return response, err
		}
		n, err := s.Conn.Read(buf)
		if n > 0 {
			remaining := policy.MaxBytes - len(response)
			if n > remaining {
				n = remaining
			}
			response = append(response, buf[:n]...)
			if policy.SingleRead {
				return response, nil
			}
		}
		if err != nil {
			if err == io.EOF && len(response) > 0 {
				return response, nil
			}
			if len(response) > 0 {
				return response, nil
			}
			return response, err
		}
	}
	return response, nil
}

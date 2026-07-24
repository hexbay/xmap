package scanner

import (
	"errors"
	"io"
	"net"
)

var (
	ConnectionError  = errors.New("connection error")
	ReadTimeoutError = errors.New("read timeout")
	PeerClosedError  = errors.New("peer closed connection")
	ReadDataError    = errors.New("read data error")
	WriteDataError   = errors.New("write data error")
	ErrNotMatched    = errors.New("not matched")
)

func classifyReadError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return PeerClosedError
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return ReadTimeoutError
	}
	return ReadDataError
}

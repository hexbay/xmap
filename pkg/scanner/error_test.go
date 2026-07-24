package scanner

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestClassifyReadError(t *testing.T) {
	require.ErrorIs(t, classifyReadError(io.EOF), PeerClosedError)
	require.ErrorIs(t, classifyReadError(&net.DNSError{IsTimeout: true}), ReadTimeoutError)
	require.ErrorIs(t, classifyReadError(errors.New("connection reset")), ReadDataError)
}

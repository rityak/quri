package route

import (
	"errors"
	"go.uber.org/goleak"
	"io"
	"net"
	"testing"
	"time"
)

type failedHalfClose struct {
	net.Conn
	err error
}

func (c failedHalfClose) CloseWrite() error { return c.err }

func TestRelayAbortsOnHalfCloseError(t *testing.T) {
	left, leftPeer := net.Pipe()
	right, rightPeer := net.Pipe()
	defer closeTest(t, left)
	defer closeTest(t, right)
	defer closeTest(t, rightPeer)
	closeTest(t, leftPeer)
	want := errors.New("half-close failed")
	done := make(chan error, 1)
	go func() { done <- Relay(left, failedHalfClose{Conn: right, err: want}) }()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		closeTest(t, right)
		<-done //nolint:errcheck // Join the aborted worker before reporting its failure.
		t.Fatal("relay did not abort the blocked reverse copy")
	}
}

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }
func closeTest(t testing.TB, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Error(err)
	}
}

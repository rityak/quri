package quri

import (
	"errors"
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
	defer left.Close()
	defer right.Close()
	defer rightPeer.Close()
	leftPeer.Close()
	want := errors.New("half-close failed")
	done := make(chan error, 1)
	go func() { done <- Relay(left, failedHalfClose{Conn: right, err: want}) }()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want %v", err, want)
		}
	case <-time.After(time.Second):
		right.Close()
		<-done
		t.Fatal("relay did not abort the blocked reverse copy")
	}
}

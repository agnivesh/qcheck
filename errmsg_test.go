package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestFriendlyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"dns not found", &net.DNSError{Err: "no such host", IsNotFound: true}, "DNS lookup failed: no such host"},
		{"deadline exceeded", context.DeadlineExceeded, "timed out after 10s"},
		{
			"connection refused, wrapped",
			fmt.Errorf("dial tcp 127.0.0.1:1: connect: %w", syscall.ECONNREFUSED),
			"connection refused",
		},
		{"handshake failure alert", errors.New("remote error: tls: handshake failure"), "TLS handshake rejected by server"},
		{
			"unknown error falls back to last segment",
			errors.New("dial tcp 10.0.0.1:443: connect: no route to host"),
			"no route to host",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := friendlyError(tt.err, 10*time.Second); got != tt.want {
				t.Fatalf("friendlyError() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPQRejected(t *testing.T) {
	if !pqRejected(errors.New("remote error: tls: handshake failure")) {
		t.Error("a handshake_failure alert should count as an ordinary PQ rejection")
	}
	if pqRejected(context.DeadlineExceeded) {
		t.Error("a timeout is a transport failure, not a PQ rejection")
	}
}

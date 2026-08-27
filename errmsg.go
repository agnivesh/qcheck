package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// friendlyError turns a dial or TLS-handshake error into a short line fit for a
// report, dropping Go's transport internals ("dial tcp 1.2.3.4:443: connect: ").
func friendlyError(err error, timeout time.Duration) string {
	if err == nil {
		return ""
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return fmt.Sprintf("timed out after %s", timeout)
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		switch {
		case dnsErr.IsNotFound:
			return "DNS lookup failed: no such host"
		case dnsErr.IsTimeout:
			return "DNS lookup timed out"
		default:
			return "DNS lookup failed: " + dnsErr.Err
		}
	}

	if msg, ok := certErrorMessage(err); ok {
		return msg
	}

	var rhe tls.RecordHeaderError
	if errors.As(err, &rhe) {
		return "no TLS server on this port (it answered with non-TLS bytes)"
	}

	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection reset by peer"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "no route to host"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network unreachable"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Sprintf("timed out after %s", timeout)
	}

	if strings.Contains(err.Error(), "handshake failure") {
		return "TLS handshake rejected by server"
	}

	return lastSegment(err.Error())
}

// certErrorMessage recognizes the common certificate-verification failures and
// returns a plain-language description. The bool is false when err is unrelated
// to certificates.
func certErrorMessage(err error) (string, bool) {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		return "certificate has expired or is not yet valid", true
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "certificate is not valid for this hostname", true
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return "certificate is not trusted (unknown issuer); pass --insecure to probe anyway", true
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "certificate verification failed; pass --insecure to probe anyway", true
	}
	return "", false
}

// lastSegment returns the text after the final ": " in a wrapped error string,
// which is normally the part written for humans.
func lastSegment(s string) string {
	if i := strings.LastIndex(s, ": "); i != -1 && i+2 < len(s) {
		return s[i+2:]
	}
	return s
}

// pqRejected reports whether err is the ordinary "server offers no hybrid PQ
// group" handshake rejection, rather than a transport failure that left the
// forced probe with no answer.
func pqRejected(err error) bool {
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "handshake failure") ||
		strings.Contains(s, "no supported versions") ||
		strings.Contains(s, "protocol version not supported") ||
		strings.Contains(s, "no cipher suite supported")
}

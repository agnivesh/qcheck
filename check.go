package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"
)

// Options controls how a single site is probed.
type Options struct {
	// Timeout bounds each of the two handshakes. Defaults to 10s.
	Timeout time.Duration
	// InsecureSkipVerify disables certificate verification (--insecure). When
	// false, a bad certificate makes the probe an error.
	InsecureSkipVerify bool
	// ALPN is the protocol list offered via ALPN. Defaults to h2, http/1.1.
	ALPN []string
}

func (o Options) withDefaults() Options {
	o.Timeout = cmp.Or(o.Timeout, 10*time.Second)
	if len(o.ALPN) == 0 {
		o.ALPN = []string{"h2", "http/1.1"}
	}
	return o
}

// Probe runs two TLS handshakes against target: one with Go's default
// key-exchange preferences (what a current browser negotiates) and one that
// offers only hybrid post-quantum groups (latent capability). target may be a
// bare host, host:port, or a URL.
func Probe(ctx context.Context, target string, opts Options) Result {
	opts = opts.withDefaults()
	start := time.Now()
	r := Result{Target: target}

	host, port, err := parseTarget(target)
	if err != nil {
		r.Err = err.Error()
		return finish(r, start)
	}
	r.Host, r.Port = host, port
	r.ResolvedIP = resolveIP(ctx, host)

	state, err := handshake(ctx, host, port, opts, nil)
	if err != nil {
		r.Err = fmt.Sprintf("default handshake: %v", err)
		return finish(r, start)
	}
	r.TLSVersion = state.Version
	r.CipherSuite = state.CipherSuite
	r.NegotiatedGroup = state.CurveID
	r.DefaultIsPQ = isPQ(state.CurveID)
	r.ALPN = state.NegotiatedProtocol
	recordCert(&r, state.PeerCertificates)

	forced, err := handshake(ctx, host, port, opts, pqGroups)
	switch {
	case err != nil:
		r.ForcedPQError = err.Error()
	case isPQ(forced.CurveID):
		r.ForcedPQSupported = true
		r.ForcedPQGroup = forced.CurveID
	}

	return finish(r, start)
}

func finish(r Result, start time.Time) Result {
	r.ElapsedMS = time.Since(start).Milliseconds()
	r.Verdict = decideVerdict(r)
	r.Explanation = explanationFor(r)
	return r
}

// handshake dials host:port, completes the TLS handshake, and returns its state.
// When groups is non-nil it is offered as the exclusive key-exchange preference
// and TLS 1.3 is required.
func handshake(ctx context.Context, host, port string, opts Options, groups []tls.CurveID) (tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	cfg := &tls.Config{
		ServerName:         host,
		NextProtos:         opts.ALPN,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // opt-in via --insecure; verification is on by default
	}
	if groups != nil {
		cfg.CurvePreferences = groups
		cfg.MinVersion = tls.VersionTLS13
	}

	dialer := tls.Dialer{
		NetDialer: &net.Dialer{Timeout: opts.Timeout},
		Config:    cfg,
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return tls.ConnectionState{}, errors.New("connection is not TLS")
	}
	return tlsConn.ConnectionState(), nil
}

func recordCert(r *Result, chain []*x509.Certificate) {
	if len(chain) == 0 {
		return
	}
	leaf := chain[0]
	r.LeafSigAlg = leaf.SignatureAlgorithm.String()
	r.CertNotAfter = leaf.NotAfter
	for _, c := range chain[1:] {
		r.ChainSigAlgs = append(r.ChainSigAlgs, c.SignatureAlgorithm.String())
	}
}

func resolveIP(ctx context.Context, host string) string {
	if net.ParseIP(host) != nil {
		return host
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0].IP.String()
}

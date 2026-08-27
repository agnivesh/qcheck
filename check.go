package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	// EnumerateGroups probes every group in allGroups individually (--groups) and
	// records which the server accepts.
	EnumerateGroups bool
	// Follow resolves HTTP redirects and probes the final host (--follow).
	Follow bool
	// DialOverride maps "host:port" to a dial address, so a probe connects to a
	// chosen IP while keeping the real hostname for SNI (--resolve).
	DialOverride map[string]string
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

	if opts.Follow {
		host, port = applyFollow(ctx, host, port, opts, &r)
	}

	r.Host, r.Port = host, port
	r.ResolvedIP = resolveIP(ctx, host, port, opts.DialOverride)

	state, err := handshake(ctx, host, port, opts, nil)
	if err != nil {
		r.Err = friendlyError(err, opts.Timeout)
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
	case err == nil:
		r.ForcedPQSupported = isPQ(forced.CurveID)
		if r.ForcedPQSupported {
			r.ForcedPQGroup = forced.CurveID
		}
	case !pqRejected(err):
		// A real transport failure on the second handshake, not the ordinary
		// "no common PQ group" rejection.
		r.ForcedPQError = friendlyError(err, opts.Timeout)
	}

	if opts.EnumerateGroups {
		r.SupportedGroups = enumerateGroups(ctx, host, port, opts)
	}

	return finish(r, start)
}

// applyFollow resolves HTTP redirects for host:port and returns the endpoint to
// probe. It is best-effort: on any failure it returns the original host:port and
// records a note on r, so the caller always gets a TLS verdict.
func applyFollow(ctx context.Context, host, port string, opts Options, r *Result) (string, string) {
	finalHost, finalPort, chain, err := resolveFinalTarget(ctx, host, port, opts)
	if err != nil {
		r.FollowNote = "redirect-following failed: " + friendlyError(err, opts.Timeout)
		return host, port
	}
	if finalHost != host || finalPort != port {
		r.FinalTarget = net.JoinHostPort(finalHost, finalPort)
		r.Redirects = chain
	}
	return finalHost, finalPort
}

// enumerateGroups probes each group in allGroups with its own single-group TLS
// 1.3 handshake and returns those the server accepted, in allGroups order. A
// handshake that fails to negotiate means the group is unsupported; probes force
// TLS 1.3, so a group offered only under TLS 1.2 reads as unsupported, which is
// acceptable because post-quantum key exchange requires TLS 1.3.
func enumerateGroups(ctx context.Context, host, port string, opts Options) []tls.CurveID {
	var supported []tls.CurveID
	for _, g := range allGroups {
		state, err := handshake(ctx, host, port, opts, []tls.CurveID{g})
		if err == nil && state.CurveID == g {
			supported = append(supported, g)
		}
	}
	return supported
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
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr(host, port, opts.DialOverride))
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

// dialAddr returns the socket address to connect to for host:port. A --resolve
// override for that exact host:port redirects the connection to a chosen address
// while the caller keeps host as the TLS ServerName. Without an override it is
// just net.JoinHostPort(host, port).
func dialAddr(host, port string, override map[string]string) string {
	if addr, ok := override[net.JoinHostPort(host, port)]; ok {
		return addr
	}
	return net.JoinHostPort(host, port)
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

// resolveIP reports the address the probe connects to, for display. A --resolve
// override wins; then a host that is already a literal IP; otherwise it does a
// short DNS lookup. It returns "" when the name cannot be resolved.
func resolveIP(ctx context.Context, host, port string, override map[string]string) string {
	if addr, ok := override[net.JoinHostPort(host, port)]; ok {
		if h, _, err := net.SplitHostPort(addr); err == nil {
			return h
		}
		return addr
	}
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

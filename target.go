package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// parseTarget normalizes a user-supplied site into a host and port. It accepts a
// bare host ("example.com"), host:port ("example.com:8443"), a URL
// ("https://example.com/path"), and bracketed IPv6 ("[2606:4700::1111]:443").
// The port defaults to "443"; a scheme other than the port is ignored, since
// qcheck always speaks TLS.
func parseTarget(raw string) (host, port string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("empty target")
	}

	if strings.Contains(s, "://") {
		u, perr := url.Parse(s)
		if perr != nil {
			return "", "", fmt.Errorf("parsing URL %q: %w", raw, perr)
		}
		if u.Hostname() == "" {
			return "", "", fmt.Errorf("URL %q has no host", raw)
		}
		return u.Hostname(), portOrDefault(u.Port()), nil
	}

	if h, p, serr := net.SplitHostPort(s); serr == nil {
		if h == "" {
			return "", "", fmt.Errorf("target %q has no host", raw)
		}
		if _, cerr := strconv.Atoi(p); cerr != nil {
			return "", "", fmt.Errorf("target %q has non-numeric port %q", raw, p)
		}
		return h, p, nil
	}

	// Bare host: a hostname, an unbracketed IPv6 literal, or "[::1]" with no port.
	h := strings.Trim(s, "[]")
	if strings.ContainsAny(h, " \t") {
		return "", "", fmt.Errorf("invalid target %q", raw)
	}
	return h, "443", nil
}

func portOrDefault(p string) string {
	if p == "" {
		return "443"
	}
	return p
}

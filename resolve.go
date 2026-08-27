package main

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// resolveFlag collects curl-style --resolve entries. Each entry maps a
// "host:port" to a dial address, letting a probe connect to a chosen IP while
// keeping the original hostname for SNI and certificate checks. The flag is
// repeatable.
type resolveFlag struct {
	overrides map[string]string
}

func (f *resolveFlag) String() string {
	if len(f.overrides) == 0 {
		return ""
	}
	pairs := make([]string, 0, len(f.overrides))
	for k, v := range f.overrides {
		pairs = append(pairs, k+"->"+v)
	}
	return strings.Join(pairs, ",")
}

// Set parses one "host:port:addr" entry. addr may be an IPv4 or IPv6 literal,
// bracketed or not. The resulting override dials addr on the same port while the
// probe still presents host as the server name.
func (f *resolveFlag) Set(value string) error {
	host, port, addr, err := parseResolve(value)
	if err != nil {
		return err
	}
	if f.overrides == nil {
		f.overrides = make(map[string]string)
	}
	f.overrides[net.JoinHostPort(host, port)] = net.JoinHostPort(addr, port)
	return nil
}

// parseResolve splits a "host:port:addr" entry. Host is the text before the
// first colon, port the numeric field before the second, and addr everything
// after (an IP literal, optionally bracketed for IPv6).
func parseResolve(value string) (host, port, addr string, err error) {
	first := strings.IndexByte(value, ':')
	if first <= 0 {
		return "", "", "", fmt.Errorf("--resolve %q: expected host:port:addr", value)
	}
	rest := value[first+1:]
	second := strings.IndexByte(rest, ':')
	if second <= 0 {
		return "", "", "", fmt.Errorf("--resolve %q: expected host:port:addr", value)
	}

	host = value[:first]
	port = rest[:second]
	addr = strings.Trim(rest[second+1:], "[]")

	if _, cerr := strconv.Atoi(port); cerr != nil {
		return "", "", "", fmt.Errorf("--resolve %q: port %q is not numeric", value, port)
	}
	if net.ParseIP(addr) == nil {
		return "", "", "", fmt.Errorf("--resolve %q: %q is not an IP address", value, addr)
	}
	return host, port, addr, nil
}

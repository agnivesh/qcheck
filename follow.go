package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
)

// maxRedirects caps how many hops --follow will chase before giving up.
const maxRedirects = 10

// resolveFinalTarget follows HTTP redirects starting at https://host:port/ and
// returns the host and port of the endpoint the chain lands on, along with the
// URL of every hop. It honors --insecure and --resolve through the same dial
// override the TLS probes use. Any transport error is returned so the caller can
// fall back to the original target.
func resolveFinalTarget(ctx context.Context, host, port string, opts Options) (string, string, []string, error) {
	var chain []string

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			h, p, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			d := &net.Dialer{Timeout: opts.Timeout}
			return d.DialContext(ctx, network, dialAddr(h, p, opts.DialOverride))
		},
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: opts.InsecureSkipVerify, //nolint:gosec // opt-in via --insecure
		},
	}
	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return errors.New("stopped after too many redirects")
			}
			chain = append(chain, req.URL.String())
			return nil
		},
	}

	start := "https://" + net.JoinHostPort(host, port) + "/"
	resp, err := requestFollowing(ctx, client, start)
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()

	finalHost, finalPort := hostPortFromURL(resp.Request.URL)
	return finalHost, finalPort, chain, nil
}

// requestFollowing issues a HEAD request and retries with GET when the server
// rejects HEAD, since some hosts only redirect on GET.
func requestFollowing(ctx context.Context, client *http.Client, rawURL string) (*http.Response, error) {
	for _, method := range []string{http.MethodHead, http.MethodGet} {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		if method == http.MethodHead && resp.StatusCode == http.StatusMethodNotAllowed {
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, errors.New("no response")
}

// hostPortFromURL extracts the host and port from a URL, defaulting the port to
// the scheme's standard when absent.
func hostPortFromURL(u *url.URL) (string, string) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" {
			port = "80"
		} else {
			port = "443"
		}
	}
	return host, port
}

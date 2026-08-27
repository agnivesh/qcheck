package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

func TestProbeReady(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	r := Probe(t.Context(), srv.URL, Options{InsecureSkipVerify: true})
	if r.Err != "" {
		t.Fatalf("probe error: %s", r.Err)
	}
	if r.Verdict != VerdictReady {
		t.Fatalf("verdict = %v (%s), want ready", r.Verdict, r.Explanation)
	}
	if !r.DefaultIsPQ || !isPQ(r.NegotiatedGroup) {
		t.Fatalf("expected a hybrid PQ group by default, got %v", r.NegotiatedGroup)
	}
	if r.TLSVersion != tls.VersionTLS13 {
		t.Fatalf("tls version = %#x, want 1.3", r.TLSVersion)
	}
}

func TestProbeClassicalOnly(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}
	srv.StartTLS()
	defer srv.Close()

	r := Probe(t.Context(), srv.URL, Options{InsecureSkipVerify: true})
	if r.Err != "" {
		t.Fatalf("probe error: %s", r.Err)
	}
	if r.DefaultIsPQ {
		t.Fatal("did not expect a PQ group by default")
	}
	if r.ForcedPQSupported {
		t.Fatal("did not expect the forced-PQ handshake to succeed")
	}
	if r.ForcedPQError != "" {
		t.Fatalf("an ordinary PQ rejection should not set an error, got %q", r.ForcedPQError)
	}
	if r.Verdict != VerdictNotReady {
		t.Fatalf("verdict = %v (%s), want not-ready", r.Verdict, r.Explanation)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	r := Probe(t.Context(), "127.0.0.1:1", Options{Timeout: 2 * time.Second})
	if r.Verdict != VerdictError {
		t.Fatalf("verdict = %v, want error", r.Verdict)
	}
	if r.Err != "connection refused" {
		t.Fatalf("Err = %q, want %q", r.Err, "connection refused")
	}
}

func TestProbeBadTarget(t *testing.T) {
	r := Probe(t.Context(), "", Options{})
	if r.Verdict != VerdictError || r.Err == "" {
		t.Fatalf("expected an error verdict for an empty target, got %v / %q", r.Verdict, r.Err)
	}
}

func TestProbeEnumerateGroups(t *testing.T) {
	srv := httptest.NewUnstartedServer(nil)
	srv.TLS = &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.X25519MLKEM768},
	}
	srv.StartTLS()
	defer srv.Close()

	r := Probe(t.Context(), srv.URL, Options{InsecureSkipVerify: true, EnumerateGroups: true})
	if r.Err != "" {
		t.Fatalf("probe error: %s", r.Err)
	}
	if !slices.Contains(r.SupportedGroups, tls.X25519) {
		t.Errorf("expected X25519 in supported groups, got %v", r.SupportedGroups)
	}
	if !slices.Contains(r.SupportedGroups, tls.X25519MLKEM768) {
		t.Errorf("expected X25519MLKEM768 in supported groups, got %v", r.SupportedGroups)
	}
	if slices.Contains(r.SupportedGroups, tls.CurveP256) {
		t.Errorf("did not offer P-256; it should not be listed, got %v", r.SupportedGroups)
	}
}

func TestProbeResolveOverride(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()

	// Probe a name that would never resolve to the test server, forcing the
	// override to be what makes the connection succeed.
	opts := Options{
		InsecureSkipVerify: true,
		DialOverride:       map[string]string{"example.com:443": srv.Listener.Addr().String()},
	}
	r := Probe(t.Context(), "example.com:443", opts)
	if r.Err != "" {
		t.Fatalf("probe error: %s", r.Err)
	}
	if r.Host != "example.com" {
		t.Errorf("Host = %q, want example.com (SNI must keep the real name)", r.Host)
	}
	if r.ResolvedIP != "127.0.0.1" {
		t.Errorf("ResolvedIP = %q, want 127.0.0.1 (the override address)", r.ResolvedIP)
	}
	if r.Verdict != VerdictReady {
		t.Errorf("verdict = %v, want ready", r.Verdict)
	}
}

func TestProbeFollowRedirect(t *testing.T) {
	dest := httptest.NewTLSServer(nil)
	defer dest.Close()

	redirector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, dest.URL, http.StatusFound)
	}))
	defer redirector.Close()

	_, destPort, _ := parseTarget(dest.URL)
	r := Probe(t.Context(), redirector.URL, Options{InsecureSkipVerify: true, Follow: true})
	if r.Err != "" {
		t.Fatalf("probe error: %s", r.Err)
	}
	if r.FinalTarget != "127.0.0.1:"+destPort {
		t.Errorf("FinalTarget = %q, want 127.0.0.1:%s", r.FinalTarget, destPort)
	}
	if len(r.Redirects) == 0 {
		t.Error("expected a non-empty redirect chain")
	}
	if r.FollowNote != "" {
		t.Errorf("did not expect a follow note on success, got %q", r.FollowNote)
	}
}

func TestProbeFollowFailureFallsBack(t *testing.T) {
	r := Probe(t.Context(), "127.0.0.1:1", Options{Timeout: 2 * time.Second, Follow: true})
	if r.FollowNote == "" {
		t.Error("expected a follow note when redirect-following fails")
	}
	if r.Verdict != VerdictError {
		t.Errorf("verdict = %v, want error (the original host is still probed)", r.Verdict)
	}
}

// TestProbeIntegrationReady hits a real host and needs network access.
func TestProbeIntegrationReady(t *testing.T) {
	if testing.Short() {
		t.Skip("network integration test; skipped with -short")
	}
	r := Probe(t.Context(), "cloudflare.com", Options{})
	if r.Err != "" {
		t.Fatalf("probe error: %s", r.Err)
	}
	if r.Verdict != VerdictReady {
		t.Fatalf("cloudflare.com verdict = %v (%s), want ready", r.Verdict, r.Explanation)
	}
}

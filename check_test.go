package main

import (
	"crypto/tls"
	"net/http/httptest"
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
	if r.ForcedPQError == "" {
		t.Fatal("expected a forced-PQ rejection message")
	}
	if r.Verdict != VerdictNotReady {
		t.Fatalf("verdict = %v (%s), want not-ready", r.Verdict, r.Explanation)
	}
}

func TestProbeConnectionRefused(t *testing.T) {
	r := Probe(t.Context(), "127.0.0.1:1", Options{Timeout: 2 * time.Second})
	if r.Verdict != VerdictError || r.Err == "" {
		t.Fatalf("expected an error verdict, got %v / %q", r.Verdict, r.Err)
	}
}

func TestProbeBadTarget(t *testing.T) {
	r := Probe(t.Context(), "", Options{})
	if r.Verdict != VerdictError || r.Err == "" {
		t.Fatalf("expected an error verdict for an empty target, got %v / %q", r.Verdict, r.Err)
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

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleReady() Result {
	r := Result{
		Target:            "example.com",
		Host:              "example.com",
		Port:              "443",
		ResolvedIP:        "203.0.113.10",
		TLSVersion:        tls.VersionTLS13,
		CipherSuite:       tls.TLS_AES_128_GCM_SHA256,
		NegotiatedGroup:   tls.X25519MLKEM768,
		DefaultIsPQ:       true,
		ForcedPQGroup:     tls.X25519MLKEM768,
		ForcedPQSupported: true,
		ALPN:              "h2",
		LeafSigAlg:        "ECDSA-SHA256",
		ChainSigAlgs:      []string{"SHA384-RSA"},
		CertNotAfter:      time.Now().Add(720 * time.Hour),
		ElapsedMS:         42,
	}
	return finish(r, time.Now())
}

func TestRenderTextReady(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, []Result{sampleReady()}, false)
	got := buf.String()
	for _, want := range []string{"READY", "X25519MLKEM768", "post-quantum hybrid", "TLS 1.3", "harvest now"} {
		if !strings.Contains(got, want) {
			t.Fatalf("text output missing %q:\n%s", want, got)
		}
	}
}

func TestRenderTextNoColorHasNoEscapes(t *testing.T) {
	var buf bytes.Buffer
	RenderText(&buf, []Result{sampleReady()}, false)
	if strings.Contains(buf.String(), "\x1b[") {
		t.Fatal("expected no ANSI escapes when color is disabled")
	}
}

func TestRenderJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderJSON(&buf, []Result{sampleReady()}); err != nil {
		t.Fatal(err)
	}
	var rep jsonReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if rep.Tool != "qcheck" || len(rep.Results) != 1 {
		t.Fatalf("unexpected report envelope: %+v", rep)
	}
	got := rep.Results[0]
	if got.Verdict != "ready" || got.KeyExchange != "X25519MLKEM768" || !got.KeyExchangePostQuantum {
		t.Fatalf("unexpected result: %+v", got)
	}
	if got.TLSVersion != "TLS 1.3" || got.CipherSuite != "TLS_AES_128_GCM_SHA256" {
		t.Fatalf("unexpected tls fields: %+v", got)
	}
}

func TestRenderTextError(t *testing.T) {
	r := finish(Result{Target: "nope.invalid", Err: "DNS lookup failed: no such host"}, time.Now())
	var buf bytes.Buffer
	RenderText(&buf, []Result{r}, false)
	got := buf.String()
	if !strings.Contains(got, "ERROR") || !strings.Contains(got, "DNS lookup failed: no such host") {
		t.Fatalf("error report missing expected content:\n%s", got)
	}
	if strings.Contains(got, "handshake") || strings.Contains(got, "  error ") {
		t.Fatalf("error report leaks internal wording:\n%s", got)
	}
}

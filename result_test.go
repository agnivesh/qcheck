package main

import (
	"crypto/tls"
	"strings"
	"testing"
)

func TestDecideVerdict(t *testing.T) {
	tests := []struct {
		name string
		r    Result
		want Verdict
	}{
		{"connection error", Result{Err: "dial tcp: connection refused"}, VerdictError},
		{"error outranks a good handshake", Result{Err: "x", TLSVersion: tls.VersionTLS13, DefaultIsPQ: true}, VerdictError},
		{"no tls 1.3", Result{TLSVersion: tls.VersionTLS12}, VerdictNotReady},
		{"pq by default", Result{TLSVersion: tls.VersionTLS13, DefaultIsPQ: true}, VerdictReady},
		{"capable but not default", Result{TLSVersion: tls.VersionTLS13, ForcedPQSupported: true}, VerdictCapable},
		{"classical only", Result{TLSVersion: tls.VersionTLS13}, VerdictNotReady},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := decideVerdict(tt.r); got != tt.want {
				t.Fatalf("decideVerdict() = %v, want %v", got, tt.want)
			}
			if got := explanationFor(tt.r); strings.TrimSpace(got) == "" {
				t.Fatalf("explanationFor() returned empty string for %v", tt.want)
			}
		})
	}
}

func TestVerdictStrings(t *testing.T) {
	for _, v := range []Verdict{VerdictError, VerdictNotReady, VerdictCapable, VerdictReady} {
		if v.String() == "unknown" || v.label() == "UNKNOWN" {
			t.Fatalf("verdict %d has no string form", v)
		}
	}
}

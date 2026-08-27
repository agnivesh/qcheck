package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

const confidentialityNote = "Note: a READY verdict means connection confidentiality resists a future quantum\n" +
	"adversary (\"harvest now, decrypt later\"). Certificate authentication is still\n" +
	"classical (RSA/ECDSA) across the public web; PQ signature certificates are not\n" +
	"in the Web PKI yet."

// RenderText writes a human-readable report for results to w. color enables ANSI
// coloring of the verdict headline.
func RenderText(w io.Writer, results []Result, color bool) {
	for i, r := range results {
		if i > 0 {
			fmt.Fprintln(w)
		}
		writeResultText(w, r, color)
	}
	if len(results) > 1 {
		fmt.Fprintln(w)
		writeSummary(w, results)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, confidentialityNote)
}

func writeResultText(w io.Writer, r Result, color bool) {
	fmt.Fprintf(w, "%s  →  %s\n", r.Target, colorize(r.Verdict.label(), r.Verdict, color))
	if r.Err != "" {
		fmt.Fprintf(w, "  %s\n", r.Err)
		return
	}
	fmt.Fprintf(w, "  %s\n", r.Explanation)

	fmt.Fprintf(w, "  TLS           %s  /  %s\n", tlsVersionName(r.TLSVersion), tls.CipherSuiteName(r.CipherSuite))

	def := "classical, negotiated by default"
	if r.DefaultIsPQ {
		def = "negotiated by default"
	}
	kx := groupName(r.NegotiatedGroup)
	if kx == "" {
		kx = "unknown"
	}
	fmt.Fprintf(w, "  Key exchange  %s  (%s)\n", kx, def)

	switch {
	case r.ForcedPQSupported:
		fmt.Fprintf(w, "  Forced PQ     %s accepted\n", r.ForcedPQGroup.String())
	case r.ForcedPQError != "":
		fmt.Fprintf(w, "  Forced PQ     rejected (%s)\n", r.ForcedPQError)
	default:
		fmt.Fprintln(w, "  Forced PQ     rejected")
	}

	if r.LeafSigAlg != "" {
		fmt.Fprintf(w, "  Certificate   %s leaf  (classical)\n", r.LeafSigAlg)
		if len(r.ChainSigAlgs) > 0 {
			fmt.Fprintf(w, "                chain: %s\n", strings.Join(r.ChainSigAlgs, ", "))
		}
	}
	if !r.CertNotAfter.IsZero() {
		days := int(time.Until(r.CertNotAfter).Hours() / 24)
		fmt.Fprintf(w, "  Expires       %s  (%dd)\n", r.CertNotAfter.Format("2006-01-02"), days)
	}
	if r.ALPN != "" {
		fmt.Fprintf(w, "  ALPN          %s\n", r.ALPN)
	}
	if r.ResolvedIP != "" {
		fmt.Fprintf(w, "  Resolved      %s\n", r.ResolvedIP)
	}
	fmt.Fprintf(w, "  Took          %dms\n", r.ElapsedMS)
}

func writeSummary(w io.Writer, results []Result) {
	var ready, capable, notReady, errs int
	for _, r := range results {
		switch r.Verdict {
		case VerdictReady:
			ready++
		case VerdictCapable:
			capable++
		case VerdictNotReady:
			notReady++
		case VerdictError:
			errs++
		}
	}
	fmt.Fprintf(w, "Summary: %d ready, %d capable, %d not ready, %d error  (of %d)\n",
		ready, capable, notReady, errs, len(results))
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case 0:
		return "unknown"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func colorize(s string, v Verdict, enabled bool) string {
	if !enabled {
		return s
	}
	code := "0"
	switch v {
	case VerdictReady:
		code = "32" // green
	case VerdictCapable:
		code = "33" // yellow
	case VerdictNotReady:
		code = "31" // red
	case VerdictError:
		code = "35" // magenta
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

type jsonReport struct {
	Tool      string       `json:"tool"`
	CheckedAt string       `json:"checked_at"`
	Results   []jsonResult `json:"results"`
}

type jsonResult struct {
	Target                   string   `json:"target"`
	Host                     string   `json:"host,omitempty"`
	Port                     string   `json:"port,omitempty"`
	ResolvedIP               string   `json:"resolved_ip,omitempty"`
	Verdict                  string   `json:"verdict"`
	Explanation              string   `json:"explanation"`
	TLSVersion               string   `json:"tls_version,omitempty"`
	CipherSuite              string   `json:"cipher_suite,omitempty"`
	KeyExchange              string   `json:"key_exchange,omitempty"`
	KeyExchangePostQuantum   bool     `json:"key_exchange_post_quantum"`
	ForcedPQGroup            string   `json:"forced_pq_group,omitempty"`
	ForcedPQSupported        bool     `json:"forced_pq_supported"`
	ForcedPQError            string   `json:"forced_pq_error,omitempty"`
	ALPN                     string   `json:"alpn,omitempty"`
	LeafSignatureAlgorithm   string   `json:"leaf_signature_algorithm,omitempty"`
	ChainSignatureAlgorithms []string `json:"chain_signature_algorithms,omitempty"`
	CertNotAfter             string   `json:"cert_not_after,omitempty"`
	Error                    string   `json:"error,omitempty"`
	ElapsedMS                int64    `json:"elapsed_ms"`
}

// RenderJSON writes an indented JSON report for results to w.
func RenderJSON(w io.Writer, results []Result) error {
	rep := jsonReport{
		Tool:      "qcheck",
		CheckedAt: time.Now().UTC().Format(time.RFC3339),
		Results:   make([]jsonResult, len(results)),
	}
	for i, r := range results {
		rep.Results[i] = r.toJSON()
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func (r Result) toJSON() jsonResult {
	jr := jsonResult{
		Target:                   r.Target,
		Host:                     r.Host,
		Port:                     r.Port,
		ResolvedIP:               r.ResolvedIP,
		Verdict:                  r.Verdict.String(),
		Explanation:              r.Explanation,
		KeyExchangePostQuantum:   r.DefaultIsPQ,
		ForcedPQSupported:        r.ForcedPQSupported,
		ForcedPQError:            r.ForcedPQError,
		ALPN:                     r.ALPN,
		LeafSignatureAlgorithm:   r.LeafSigAlg,
		ChainSignatureAlgorithms: r.ChainSigAlgs,
		Error:                    r.Err,
		ElapsedMS:                r.ElapsedMS,
	}
	if r.TLSVersion != 0 {
		jr.TLSVersion = tlsVersionName(r.TLSVersion)
	}
	if r.CipherSuite != 0 {
		jr.CipherSuite = tls.CipherSuiteName(r.CipherSuite)
	}
	if r.NegotiatedGroup != 0 {
		jr.KeyExchange = r.NegotiatedGroup.String()
	}
	if r.ForcedPQGroup != 0 {
		jr.ForcedPQGroup = r.ForcedPQGroup.String()
	}
	if !r.CertNotAfter.IsZero() {
		jr.CertNotAfter = r.CertNotAfter.UTC().Format(time.RFC3339)
	}
	return jr
}

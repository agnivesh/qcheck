package main

import (
	"crypto/tls"
	"time"
)

// Result is the full outcome of probing one target. Every field is populated by
// Probe before the verdict is decided.
type Result struct {
	Target     string
	Host       string
	Port       string
	ResolvedIP string

	TLSVersion  uint16
	CipherSuite uint16

	// NegotiatedGroup is the key-exchange group chosen in the default handshake
	// (what a current browser would get). DefaultIsPQ caches isPQ of it.
	NegotiatedGroup tls.CurveID
	DefaultIsPQ     bool

	// ForcedPQGroup is the group chosen when only hybrid PQ groups were offered;
	// zero when the server rejected them. ForcedPQError holds the rejection.
	ForcedPQGroup     tls.CurveID
	ForcedPQSupported bool
	ForcedPQError     string

	// SupportedGroups lists the key-exchange groups the server accepted, one per
	// group, when --groups enumeration ran. Empty otherwise.
	SupportedGroups []tls.CurveID

	// FinalTarget and Redirects record where --follow landed. FinalTarget is the
	// "host:port" actually probed when it differs from the original; Redirects is
	// the URL chain. FollowNote explains a best-effort follow that failed.
	FinalTarget string
	Redirects   []string
	FollowNote  string

	ALPN         string
	LeafSigAlg   string
	ChainSigAlgs []string
	CertNotAfter time.Time

	Verdict     Verdict
	Explanation string
	Err         string
	ElapsedMS   int64
}

// Verdict is qcheck's assessment of a site's post-quantum readiness.
type Verdict int

const (
	// VerdictError means no TLS handshake could be completed.
	VerdictError Verdict = iota
	// VerdictNotReady means the site negotiates no post-quantum key exchange,
	// even when one is explicitly offered, or it lacks TLS 1.3.
	VerdictNotReady
	// VerdictCapable means the site supports a hybrid PQ group but does not
	// pick one by default.
	VerdictCapable
	// VerdictReady means the site negotiates a hybrid PQ key exchange out of the box.
	VerdictReady
)

func (v Verdict) String() string {
	switch v {
	case VerdictReady:
		return "ready"
	case VerdictCapable:
		return "capable"
	case VerdictNotReady:
		return "not-ready"
	case VerdictError:
		return "error"
	default:
		return "unknown"
	}
}

func (v Verdict) label() string {
	switch v {
	case VerdictReady:
		return "READY"
	case VerdictCapable:
		return "CAPABLE"
	case VerdictNotReady:
		return "NOT READY"
	case VerdictError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

// decideVerdict maps a completed probe to a verdict. It is pure: it reads only
// fields already set on r and has no side effects.
func decideVerdict(r Result) Verdict {
	switch {
	case r.Err != "":
		return VerdictError
	case r.TLSVersion != 0 && r.TLSVersion < tls.VersionTLS13:
		return VerdictNotReady
	case r.DefaultIsPQ:
		return VerdictReady
	case r.ForcedPQSupported:
		return VerdictCapable
	default:
		return VerdictNotReady
	}
}

// explanationFor returns a one-line rationale for r's verdict.
func explanationFor(r Result) string {
	switch decideVerdict(r) {
	case VerdictError:
		return "no TLS connection could be established"
	case VerdictReady:
		return "negotiates a hybrid post-quantum key exchange by default"
	case VerdictCapable:
		return "supports a hybrid post-quantum key exchange but prefers a classical group; " +
			"reorder the server's key-exchange preferences to put " + tls.X25519MLKEM768.String() + " first"
	case VerdictNotReady:
		if r.TLSVersion != 0 && r.TLSVersion < tls.VersionTLS13 {
			return "no TLS 1.3 support; post-quantum key exchange requires TLS 1.3"
		}
		return "no hybrid post-quantum key exchange, even when explicitly offered"
	default:
		return ""
	}
}

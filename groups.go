package main

import "crypto/tls"

// pqGroups are the hybrid post-quantum key-exchange groups qcheck offers when it
// probes a server for latent capability, most-preferred first. Each pairs a
// classical ECDHE exchange with ML-KEM (FIPS 203), so the derived secret stays
// safe as long as either half holds. X25519MLKEM768 is the group Chrome,
// Firefox, and Cloudflare deploy by default.
var pqGroups = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
}

// allGroups is every key-exchange group qcheck probes for one at a time when
// --groups is set, in the order they are reported. It covers the classical
// curves plus the three hybrid PQ groups, so the report shows both what a server
// accepts today and which PQ groups it is missing.
var allGroups = []tls.CurveID{
	tls.X25519,
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// isPQ reports whether id is a hybrid post-quantum key-exchange group.
func isPQ(id tls.CurveID) bool {
	switch id {
	case tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024:
		return true
	default:
		return false
	}
}

// groupName returns a human label for a negotiated key-exchange group, tagging
// the post-quantum ones. It returns "" for the zero value (no group / legacy RSA
// key exchange).
func groupName(id tls.CurveID) string {
	if id == 0 {
		return ""
	}
	if isPQ(id) {
		return id.String() + " (post-quantum hybrid)"
	}
	return id.String()
}

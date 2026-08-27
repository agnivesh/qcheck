# qcheck

Is a website ready for the quantum era? `qcheck` tells you.

When you load an `https://` site, your browser and the server agree on a shared
secret to encrypt the connection. Today's method for agreeing on that secret can
be broken by a future quantum computer. That matters now, not later: an attacker
can record your encrypted traffic today and decrypt it years from now once the
hardware exists. This is called "harvest now, decrypt later."

The fix is a newer key-agreement method that a quantum computer cannot break.
`qcheck` connects to a site and reports whether it uses that method yet.

```
$ qcheck cloudflare.com

cloudflare.com  →  READY
  negotiates a hybrid post-quantum key exchange by default
  TLS           TLS 1.3  /  TLS_AES_128_GCM_SHA256
  Key exchange  X25519MLKEM768 (post-quantum hybrid)  (negotiated by default)
  Forced PQ     X25519MLKEM768 accepted
  Certificate   ECDSA-SHA256 leaf  (classical)
                chain: SHA256-RSA
  Expires       2026-11-02  (67d)
  ALPN          h2
  Resolved      104.16.132.229
  Took          138ms
```

## Install

With Go 1.26 or newer:

```
go install github.com/agnivesh/qcheck@latest
```

Or download a prebuilt binary for your platform from the
[Releases](https://github.com/agnivesh/qcheck/releases) page (Linux, macOS,
Windows, FreeBSD). Or build from source:

```
git clone https://github.com/agnivesh/qcheck
cd qcheck
make build      # -> bin/qcheck
```

## Usage

Point it at one or more sites:

```
qcheck cloudflare.com github.com example.com
```

A site can be a bare host (`example.com`), a `host:port` (`example.com:8443`), or
a full URL (`https://example.com/path`). The port defaults to 443.

### Reading the output

| Line | What it tells you |
|------|-------------------|
| **Verdict** (`READY` / `CAPABLE` / `NOT READY` / `ERROR`) | The headline answer. See the table below. |
| **TLS** | The protocol version and cipher that were negotiated. TLS 1.3 is required for post-quantum key exchange. |
| **Key exchange** | The group used to agree on the shared secret, and whether it was post-quantum. This is the line that decides the verdict. |
| **Forced PQ** | Whether the server accepts a post-quantum group when asked directly, even if it doesn't prefer one. |
| **Certificate** | The signature algorithm on the site's certificate. These are still classical everywhere on the public web (see the note below). |
| **Expires** | Certificate expiry date and days remaining. |

### Verdicts

| Verdict | Meaning |
|---------|---------|
| `READY` | Uses a hybrid post-quantum key exchange by default. Nothing to do. |
| `CAPABLE` | Supports a post-quantum group but prefers a classical one. Reorder the server's key-exchange preferences to fix it. |
| `NOT READY` | No post-quantum key exchange, even when asked directly. Or the site has no TLS 1.3. |
| `ERROR` | No TLS connection could be made (bad DNS, timeout, refused, or a certificate problem). |

### A note on scope

A `READY` verdict means the *connection's confidentiality* resists a future
quantum computer. Certificate *authentication* is a separate question, and it is
still classical (RSA/ECDSA) across the whole public web, because post-quantum
certificates are not part of the Web PKI yet. `qcheck` reports the certificate's
algorithm for information but does not hold it against the verdict.

## Options

```
qcheck [flags] <site>...

  --json                emit a JSON report instead of text
  --timeout duration    per-handshake timeout (default 10s)
  --insecure            skip certificate verification
  --concurrency int     max concurrent probes (default: min(targets, 8))
  --input string        read targets from a file, one per line ("-" for stdin)
  --strict              exit non-zero unless every target is READY
  --groups              list every key-exchange group the server accepts
  --resolve value       dial host:port at a given IP, keeping SNI (repeatable)
  --follow              follow HTTP redirects and probe the final host
  --version             print version and exit
```

**`--groups`** turns a `NOT READY` into an actionable answer. Instead of just
"no post-quantum group," it lists every group the server accepts, so you can see
what to add:

```
$ qcheck --groups github.com
...
  Groups        X25519
                CurveP256
```

**`--resolve`** connects to a specific IP while still presenting the real
hostname (like `curl --resolve`). Useful for testing one server behind a load
balancer, or a new edge node before DNS points at it:

```
qcheck --resolve www.example.com:443:203.0.113.9 www.example.com
```

**`--follow`** follows HTTP redirects and probes wherever the site lands, so an
apex that redirects to `www` gets measured at the real endpoint:

```
$ qcheck --follow bbc.com
bbc.com  →  READY
  Followed      bbc.com → www.bbc.com:443
  ...
```

If following fails (the host stalls or refuses), `qcheck` probes the original
host anyway and adds a note, so you always get a TLS reading.

### Exit codes

`0` every target ready (`CAPABLE` too, unless `--strict`) · `1` a target is not
ready · `2` a target errored · `3` usage error.

This makes it usable as a CI gate:

```
qcheck --strict --input production-hosts.txt
```

The JSON output (`--json`) carries the same data as structured records, one per
target, for scripting.

## How it works

For each target, `qcheck` runs two TLS handshakes:

1. **Default handshake.** Go's normal key-exchange preferences, the same set a
   current Chrome or Firefox sends (`X25519MLKEM768` first). `qcheck` reads the
   group the server chose from `tls.ConnectionState.CurveID`.
2. **Forced PQ handshake.** Only the hybrid groups `X25519MLKEM768`,
   `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`, over TLS 1.3. If it succeeds,
   the server supports post-quantum key exchange even when it doesn't prefer it.

`--groups` adds one more handshake per candidate group, each offering a single
group, to map exactly what the server accepts. All of this happens at the TLS
layer; `qcheck` never sends an HTTP request unless you pass `--follow`.

The hybrid groups pair a classical exchange (like X25519) with ML-KEM (FIPS 203).
The shared secret stays safe as long as either half holds, which is why they are
called hybrid.

## Contributing

```
make test       # unit tests + httptest, no network needed
make test-short # skips the one live-network integration test
make lint       # go vet + gofmt + staticcheck if installed
```

Tests use in-memory `httptest` TLS servers, so the suite runs offline.

## Releases

Pushing a semver tag builds `qcheck` for Linux, macOS, Windows, and FreeBSD and
publishes a GitHub Release with archives and a `checksums.txt`. See
`.github/workflows/release.yml` and `.goreleaser.yaml`.

```
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

## License

[MIT](LICENSE)

# qcheck

Check whether a website's TLS is **post-quantum ready**: whether its TLS 1.3
handshake negotiates a *hybrid post-quantum key exchange*. That handshake is
what stops "harvest now, decrypt later" attacks, where someone records your
encrypted traffic today and decrypts it once a large enough quantum computer
exists.

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

Note: a READY verdict means connection confidentiality resists a future quantum
adversary ("harvest now, decrypt later"). Certificate authentication is still
classical (RSA/ECDSA) across the public web; PQ signature certificates are not
in the Web PKI yet.
```

## How it works

For each target, qcheck runs two TLS handshakes:

1. **Default handshake.** Go's normal key-exchange preferences, the same set a
   current Chrome or Firefox sends (`X25519MLKEM768` first). qcheck reads the
   negotiated group from `tls.ConnectionState.CurveID`.
2. **Forced PQ handshake.** Only the hybrid groups `X25519MLKEM768`,
   `SecP256r1MLKEM768`, and `SecP384r1MLKEM1024`, over TLS 1.3. If it succeeds,
   the server supports post-quantum key exchange even when it doesn't prefer it.

| Verdict     | Meaning |
|-------------|---------|
| `READY`     | Negotiates a hybrid PQ key exchange by default. |
| `CAPABLE`   | Supports a hybrid PQ group but prefers a classical one. Reorder the server's key-exchange preferences. |
| `NOT READY` | No PQ key exchange even when explicitly offered, or no TLS 1.3. |
| `ERROR`     | No TLS connection could be established (DNS, timeout, bad certificate). |

## Usage

```
qcheck [flags] <site>...

  --json                emit a JSON report instead of text
  --timeout duration    per-handshake timeout (default 10s)
  --insecure            skip certificate verification
  --concurrency int     max concurrent probes (default: min(targets, 8))
  --input string        read targets from a file, one per line ("-" for stdin)
  --strict              exit non-zero unless every target is READY
  --version             print version and exit
```

A target may be a bare host (`example.com`), `host:port`, or a URL
(`https://example.com/path`). The port defaults to 443.

### Exit codes

`0` every target ready (`CAPABLE` too, unless `--strict`) · `1` a target is not
ready · `2` a target errored · `3` usage error. Useful in CI:

```
qcheck --strict --input production-hosts.txt
```

## Build and test

```
make build      # -> bin/qcheck
make test       # unit + httptest, no network
make test-short # skips the network integration test
make lint       # go vet + gofmt + staticcheck if installed
```

Requires Go 1.26+ (`crypto/tls.ConnectionState.CurveID` and the ML-KEM group
constants).

## Releases

Pushing a semver tag builds `qcheck` for Linux, macOS, Windows, and FreeBSD on
amd64/arm64 (plus 386 and armv7 where they exist) and publishes a GitHub Release
with the archives and a `checksums.txt`. See `.github/workflows/release.yml` and
`.goreleaser.yaml`.

```
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

Every pull request that touches Go files or the release config runs the same
cross-compile as a snapshot (no publish), so a broken matrix fails before a tag
is cut. Dry run locally with [GoReleaser](https://goreleaser.com):

```
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```

## License

[MIT](LICENSE)

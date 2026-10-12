# Auditing Kilvater

This is the entry point for an independent security review of Kilvater, the private HTTPS transport in this
repository. It gathers the scope, the questions that matter, and how to build and reproduce everything in one
place. For how to report what you find, see [SECURITY.md](../SECURITY.md).

## What Kilvater is

An ordinary-looking HTTPS site that also tunnels traffic for a client holding a key. TLS 1.3 (valid
certificate, ALPN `h2`) carries HTTP/2; one POST stream carries one tunnelled connection as a short frame
protocol; a visitor without a key — including an active prober — gets a static website. The full protocol is
[docs/KILVATER.md](KILVATER.md). **Kilvater adds no cipher of its own**: TLS 1.3 provides confidentiality and
integrity. Its own security rests on a small amount of code (below).

## Scope

In priority order:

1. **The Kilvater protocol and server.** Packages [`kilvater`](../kilvater), [`cmd/kilvaterd`](../cmd/kilvaterd)
   and [`wire/kilvater.go`](../wire/kilvater.go). This is the highest-value target and is small (~800 lines
   excluding tests).
2. **Client transports** in [`wire`](../wire): clean-room VLESS/REALITY/Trojan/VMess/XHTTP/gRPC/WebSocket over
   uTLS. Focus on TLS/REALITY handling, parsing of peer data, and fingerprint fidelity.
3. **Local switchboard and mobile bindings** ([`switchboard`](../switchboard), [`mobile`](../mobile)): the
   SOCKS5 front-end, local authentication, and cross-app leaks on the device.

Out of scope: third-party code in [`third_party/`](../third_party) (report upstream), and the
traffic-analysis limits already documented in [KILVATER.md §8](KILVATER.md#8-limits).

## The security-critical code

Everything Kilvater defines itself, and where it lives:

| Concern | Where | Spec |
|---|---|---|
| Authentication tag (HMAC, ±120 s window, replay cache) | `kilvater/proto.go`, `kilvater/keys.go` | §3, §7 |
| v2 key derivation (key id + HKDF), pinpoint revocation | `kilvater/keys.go` | §7 |
| Frame / address parser | `kilvater/proto.go` | §4 |
| Decoy fallback (anything that fails auth → static site, unchanged) | `kilvater/server.go` | §3, §6 |
| Target filtering (refuse non-public addresses without `-allow-private`) | `kilvater/server.go` | §5 |
| TLS/handshake handling (silent close, no Go error strings) | `cmd/kilvaterd` | §5 |

## Questions we want answered

- Can a server be told apart from an ordinary website **without a key** — active probing, TLS/HTTP/2
  fingerprinting, timing, error behaviour?
- Can authentication be **bypassed**, or a tag **replayed**, across the window or a key reload?
- Is the **private-address filter** sound, including DNS-rebinding and cloud-metadata (169.254.169.254)?
- Are there **memory or CPU exhaustion** vectors from an unauthenticated peer (frame lengths, stream counts)?
- Does the v2 scheme leak anything about a subscriber, or let a leaked client key reach the master or another
  client's key?

## Build and reproduce

Go 1.26+, Python 3 (standard library only). No network needed.

```sh
go vet ./...
go test ./... -count=1          # unit tests, fuzz corpora, and the golden test vectors
go test -race ./... -count=1
./tools/licensegate.sh          # no GPL/AGPL modules

# the second, independent implementation of the wire format, cross-checked against
# the same golden vectors (kilvater/testdata/vectors.json):
python3 -m unittest discover -s reference/python -v
```

- **Test vectors.** [KILVATER.md §9](KILVATER.md#9-test-vectors) and
  [`kilvater/testdata/vectors.json`](../kilvater/testdata/vectors.json) fix the exact bytes of the tag, the v2
  derivation and every frame. Both the Go code and the [Python reference](../reference/python) are checked
  against them, so the format is pinned by two implementations.
- **Fuzzing.** `kilvater/fuzz_test.go` fuzzes the frame, address and tag parsers:
  `go test ./kilvater -run x -fuzz FuzzReadFrame` (and the other `Fuzz*`).
- **What CI already runs** on every push: the above, plus CodeQL, govulncheck, an OpenSSF Scorecard run, and
  build-provenance attestations on releases.

## Trust model, in one paragraph

The certificate is the server's identity; clients pin nothing beyond WebPKI. Each client key is independent;
a leaked client key lets its holder use the tunnel until the key (v1) or key id (v2) is revoked, and reveals
neither anyone's traffic (TLS keys are per connection) nor the master (HKDF is one-way). The **master** is the
only secret that mints keys; it lives on the server and the issuer, never in a link, a client, or this
repository. Full detail: [KILVATER.md §7](KILVATER.md#7-keys-and-trust).

## Known limits (not findings)

Already documented in [KILVATER.md §8](KILVATER.md#8-limits): traffic analysis beyond the padding (overall
volume and cross-direction timing are not hidden), the Go TLS/HTTP-2 server fingerprint when no proxy is in
front, and the decoy being only as convincing as the files behind it.

## Publication

We publish the audit report together with our fixes.

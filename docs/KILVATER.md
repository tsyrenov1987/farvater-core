# Kilvater — a private HTTPS transport

Status: **experimental.** Kilvater works and ships inside the Farvater apps. It has not had an independent
security review yet, and field data on how it does against censorship is still being collected. Read
[§8](#8-limits) before you rely on it.

Kilvater carries TCP connections inside an ordinary-looking HTTPS website. Its parts:

- The client wire is in `wire/kilvater.go`, on top of `wire/h2mux.go`.
- The shared wire format is the `kilvater` package.
- The server is `cmd/kilvaterd`. Setup guide: [KILVATERD.md](KILVATERD.md).

A visitor without a key, whether a browser or an active prober, gets a static website. A client with a key
gets a tunnel on the same port, under the same certificate, at the same URL.

## 1. Layers

```
TCP ─ TLS 1.3 (valid certificate, ALPN h2) ─ HTTP/2 ─ one POST stream per tunnelled connection ─ frames (§4)
```

TLS 1.3 provides all of the confidentiality and integrity. Kilvater adds no cipher of its own.

**Client side:**
- The client handshake uses uTLS with a browser fingerprint (`fp`, `chrome` by default).
- It refuses any certificate that does not verify. An `insecure=1` link is rejected at parse time.

**One connection, many streams:**
- One TLS connection carries many streams, up to the server's HTTP/2 stream limit, the way a browser reuses a
  connection.
- A new connection is dialed only when the current one is full or dead.
- Dead connections are found by HTTP/2 PING after an idle gap.

## 2. Share link

```
kilvater://<key>@<host>:<port>/<path>?sni=<server name>&fp=<fingerprint>&host=<Host header>#<name>
```

| Part | Meaning | Default |
|---|---|---|
| `key` | client key, 64 hex characters (32 bytes) | required |
| `path` | URL path of the tunnel endpoint | `/connect` |
| `sni` | TLS server name; must match the certificate | `host` |
| `fp` | uTLS fingerprint | `chrome` |
| `host` | HTTP `:authority`, if different from `sni` | `sni` |

## 3. Request and authentication

A tunnel stream is an HTTP/2 `POST` to `path`:

- It carries browser-like headers: User-Agent, Client Hints, `Sec-Fetch-*`.
- It carries one cookie: `_sid=<tag>`.

The tag is 32 bytes, encoded as base64url without padding:

```
ts    = unix seconds, 8 bytes big-endian
nonce = 8 random bytes
mac   = HMAC-SHA256(key, "kilvater/1\x00" || ts || nonce || path)[0:16]
tag   = ts || nonce || mac
```

The server accepts a tag only if all of these hold:

1. `|now − ts| ≤ 120 s`.
2. The MAC matches one of the configured keys. Comparison is constant time.
3. The pair `ts||nonce` has not been seen within the window (replay cache).
4. The MAC covers `path`, so a tag made for another URL path fails.

Any request that fails these checks is handed to the decoy file server **unchanged**: any method, any path,
no cookie, a bad cookie, an old cookie or a replayed cookie. The server never answers with an
authentication error.

## 4. Frames

After authentication the server answers `200`. Both directions of the stream then carry frames:

```
[type: 1 byte][length: 3 bytes, big-endian][body: length bytes]      length ≤ 16384
```

| Type | Name | Body |
|---|---|---|
| 1 | OPEN | network byte (`1` = TCP), then `[len:1]["host:port"]` |
| 2 | DATA | payload |
| 3 | PAD | ignored; its length varies the size of the first TLS records |
| 4 | — | reserved (datagrams); never sent |
| 5 | CLOSE | one code byte: `0` normal end, `1` error / refused |

A length above 16384 is a protocol error. It is never turned into an allocation.

**Order of frames on a stream:**

1. The server's first frame is a PAD of random length (16–271 bytes).
2. The client sends OPEN, then a PAD, then DATA in both directions, and finally CLOSE or end of stream.
3. If OPEN does not arrive within 15 s of authentication, the stream is dropped.

UDP is not carried. In Farvater, UDP flows take other paths.

## 5. Server behaviour

**Dialing the target:**
- The server dials the OPEN target with a 10 s timeout.
- It refuses non-public addresses unless the operator runs with `-allow-private`. Refused targets get
  `CLOSE(1)`. Non-public means loopback, RFC 1918, RFC 6598 shared space, link-local (including cloud
  metadata at 169.254.169.254), unique-local, multicast and unspecified.
- The check runs on the address actually dialed, after DNS resolution. A hostname that resolves to
  `127.0.0.1` is refused too.

**Handshakes:**
- TLS handshakes run per connection under a 10 s deadline.
- A failed handshake is closed silently. For example, plain HTTP sent to the TLS port gets no answer, not
  Go's "Client sent an HTTP request to an HTTPS server" text, which would identify the software.

**Keys:**
- Keys are read from a file, one per line. A key is revoked by removing its line and restarting the server.
- Key values never reach logs: `Key` redacts itself when printed.

## 6. What an observer sees

- **On the wire:** a TLS 1.3 connection to a host name with a valid certificate, ALPN `h2`, and long-lived
  HTTP/2 traffic.
- **To an active prober:** a static website at every URL. With a real certificate and real-looking pages, the
  answers are those of a small site served by Go's HTTP/2 server.

## 7. Keys and trust

- **Per-client keys.** Each key is independent. Give one key per client or per group, so one leak can be
  revoked without touching the others.
- **What a leaked key gives:** the holder can use the tunnel until the key is removed.
- **What a leaked key does not give:** it cannot decrypt anyone's traffic, because TLS keys are per
  connection. It also cannot reach the server's own private network unless `-allow-private` is on.
- **The certificate is the server's identity.** Clients pin nothing beyond normal WebPKI validation.

## 8. Limits

These are known limits, not plans:

- **No independent audit yet.**
- **Traffic analysis.** Padding only varies the first records. Packet timing and volume of a long tunnel
  differ from a browsing session, and nothing here hides that.
- **Server TLS fingerprint.** The server uses Go's `crypto/tls`. Its ServerHello and HTTP/2 SETTINGS are
  those of a Go server, not nginx or a CDN. That is common on the web, but it is a fingerprint.
- **Static decoy.** The decoy is only as convincing as the files you put in it. With an empty directory every
  URL returns 404, and the server warns about it at start.
- **Clock skew.** A client clock more than 2 minutes off cannot authenticate.
- **Hosting matters more than the protocol.** Some networks throttle or freeze traffic by destination network
  and port, regardless of what the bytes look like. In our measurements, port 443 and a few common web ports
  (80, 8080, 8443) passed in places where uncommon high ports were frozen.

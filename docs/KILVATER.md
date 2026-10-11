# Kilvater — a private HTTPS transport

Status: **experimental.** Kilvater works and ships inside the Farvater apps. It has not had an independent
security review yet, and field data on how it does against censorship is still being collected. Read
[§8](#8-limits) before you rely on it.

Kilvater carries TCP connections, and UDP associations, inside an ordinary-looking HTTPS website. Its parts:

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
- With `fp=chrome` (and the empty default) both layers are shaped to a current Chrome, so TLS and HTTP/2
  name the same browser. The ClientHello is the newest Chrome, including its `trust_anchors` extension and
  the ML-DSA entries in `signature_algorithms` that the profile uTLS ships (a year behind) still lacks. The
  HTTP/2 layer matches too: the SETTINGS (values and order), the connection window, the order of
  pseudo-headers and headers, and a priority on every request, recorded from a real Chrome into
  `wire/testdata/h2fp/`. A link that names an explicit older profile (such as `fp=hellochrome_131`) is left
  as uTLS ships it; other fingerprints keep Go's HTTP/2.

**Opening a connection:** a new connection starts the way a browser visit does.
1. `GET /` with the headers of a page load.
2. Up to two same-origin stylesheets, scripts or images the page links to. The client waits for them no
   longer than twice the time the page took.
3. `/favicon.ico`, while the tunnel streams begin.

The `Date` of the page answer gives the client the server's clock, and tags are made with that clock from
then on (§3).

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

- It carries the headers of a script's `fetch` on the site: User-Agent, Client Hints, `Sec-Fetch-*`,
  `Origin` and `Referer`.
- It carries one cookie: `_sid=<tag>`.

The tag is 32 bytes, encoded as base64url without padding:

```
ts    = unix seconds, 8 bytes big-endian (the server's clock, as the client last learned it; see §1)
nonce = 8 random bytes
mac   = HMAC-SHA256(key, "kilvater/1\x00" || ts || nonce || path)[0:16]
tag   = ts || nonce || mac
```

The server accepts a tag only if all of these hold:

1. `|now − ts| ≤ 120 s`.
2. The MAC matches one of the configured keys. Comparison is constant time.
3. The pair `ts||nonce` has not been seen within the window (replay cache).
4. The MAC covers `path`, so a tag made for another URL path fails.

**v2 tag (optional, §7).** A client issued a derived key also gets a short key id and sends a longer tag:

```
version = 1 byte, value 2
keyID   = 8 bytes, the client's key id
ts      = unix seconds, 8 bytes big-endian
nonce   = 8 random bytes
mac     = HMAC-SHA256(key, "kilvater/2\x00" || keyID || ts || nonce || path)[0:16]
tag     = version || keyID || ts || nonce || mac
```

The server reads the key id, derives that one key from the master (§7), and checks the single MAC — O(1),
no scan — after the same window and path checks, plus: the key id is not on the revocation list, and the MAC
(unique per client) has not been seen within the window. A server tells the two apart by length and the
leading version byte, and accepts both, so v1 clients keep working.

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
| 1 | OPEN | network byte (`1` = TCP, `2` = UDP), then `[len:1]["host:port"]` |
| 2 | DATA | payload (a TCP byte stream) |
| 3 | PAD | ignored; varies record sizes and fills pauses (see padding) |
| 4 | DGRAM | one UDP datagram; the frame length is the datagram boundary |
| 5 | CLOSE | one code byte: `0` normal end, `1` error / refused |

A length above 16384 is a protocol error. It is never turned into an allocation.

**Order of frames on a stream:**

1. The server's first frame is a PAD of random length (16–271 bytes).
2. The client sends OPEN, then a PAD, then DATA (a TCP target) or DGRAM frames (a
   UDP target) in both directions, and finally CLOSE or end of stream.
3. If OPEN does not arrive within 15 s of authentication, the stream is dropped.

**Padding.** DATA is split into frames whose sizes follow a web-like spread rather than a run of
maximum-size records, and PAD frames ride between them; a sender may also send a PAD during a pause. This
is one-sided and needs no agreement: a peer joins DATA frames back together and ignores PAD regardless, so
any padding mode interoperates with any other, in both directions. Both ends pad. The mode — `off`,
`moderate` (default), or `heavy` — is set per server (`kilvaterd -pad`) and per client (the link's optional
`pad` parameter); it only changes how many frames of what sizes are sent, never the bytes delivered.

**UDP.** An OPEN with network byte `2` starts a UDP association instead of a TCP
one: the stream then carries DGRAM frames, one frame per datagram in each
direction, so message boundaries are kept. One stream carries one target — the
one named in OPEN — which is how a per-socket, per-destination association maps
onto a stream; a different destination opens its own stream. DNS (a datagram to
`:53`) and other UDP, such as Nyutag's calls, ride kilvater this way. UDP/443
(QUIC) is not used.

## 5. Server behaviour

**Dialing the target:**
- The server dials the OPEN target with a 10 s timeout.
- It refuses non-public addresses unless the operator runs with `-allow-private`. Refused targets get
  `CLOSE(1)`. Non-public means loopback, RFC 1918, RFC 6598 shared space, link-local (including cloud
  metadata at 169.254.169.254), unique-local, multicast and unspecified.
- The check runs on the address actually dialed, after DNS resolution. A hostname that resolves to
  `127.0.0.1` is refused too.

**UDP associations:**
- A UDP OPEN dials a socket connected to the one target in OPEN. The same
  public-address check applies — a UDP target is refused exactly as a TCP one is,
  because the connected dial runs the very same check.
- Each datagram is relayed whole, one DGRAM frame per datagram, both ways; a
  datagram too large to fit one frame is dropped, as any UDP datagram may be.
- An association silent both ways for 2 minutes is closed, so a client that opens
  one and vanishes does not hold a socket. This gates only idle associations; it
  never cuts one still carrying datagrams.

**Handshakes:**
- TLS handshakes run per connection under a 10 s deadline.
- A failed handshake is closed silently. For example, plain HTTP sent to the TLS port gets no answer, not
  Go's "Client sent an HTTP request to an HTTPS server" text, which would identify the software.

**Keys:**
- Keys are read from a file, one per line. A key is revoked by removing its line and restarting the server.
- Key values never reach logs: `Key` redacts itself when printed.

## 6. What an observer sees

- **On the wire:** a TLS 1.3 connection to a host name with a valid certificate, ALPN `h2`. It opens with
  a page request and its assets, and then carries long-lived HTTP/2 traffic.
- **To an active prober:** a static website at every URL. With a real certificate and real-looking pages, the
  answers are those of a small static site — served by Go's HTTP/2, or, behind an nginx `stream` proxy with
  `-h2c`, by what reads as nginx at both the TLS and HTTP/2-SETTINGS layers (§8).

## 7. Keys and trust

- **Per-client keys.** Each key is independent. Give one key per client or per group, so one leak can be
  revoked without touching the others.
- **Two key schemes.** *v1:* a flat list of 32-byte keys the server holds in a file; a client's tag is matched
  against the whole list. *v2:* each client's key is **derived from one master**, so the server stores only the
  master and derives the client key on demand from the key id in the tag. Both are accepted at once; v2 is the
  one new links use.
- **How v2 derivation works** (so a key issuer in any language can match it):
  - `keyID = HMAC-SHA256(master, "kilvater/kid\0" || subscriber)[0:8]` — a short, opaque id. The server never
    sees the subscriber string; the issuer keeps the id-to-subscriber map.
  - `key = HKDF-SHA256(secret = master, salt = "", info = "kilvater/key\0" || keyID, length = 32)`.
  - The client is given `key` and `keyID`; the server, holding `master`, re-derives `key` from `keyID` alone.
- **Pinpoint revocation.** A v2 key id on the revocation list is refused even though it still derives; one
  client is cut without touching the master or anyone else. The server reloads its keys, master and revocation
  list on `SIGHUP`, so a revocation takes effect at once and never cuts an open tunnel (it only gates new ones).
- **What a leaked key gives:** the holder can use the tunnel until the key (v1) or its key id (v2) is removed.
  A leaked *client* key never reveals the master or any other client's key (HKDF is one-way).
- **What a leaked key does not give:** it cannot decrypt anyone's traffic, because TLS keys are per
  connection. It also cannot reach the server's own private network unless `-allow-private` is on.
- **The certificate is the server's identity.** Clients pin nothing beyond normal WebPKI validation.
- **The master is the server's crown jewel.** Whoever holds it can mint any client key. Keep it only on the
  server and the issuer; it is never in a link, a client, or this repository.

## 8. Limits

These are known limits, not plans:

- **No independent audit yet.**
- **Traffic analysis.** Padding (§4) now shapes record sizes across the whole stream, not just the first
  records: in `moderate` (default) and `heavy` a bulk transfer no longer shows as an unbroken run of
  maximum-size records but as a spread of sizes, measured at well under 1 % and about 1.4 % of extra bytes
  respectively, and `heavy` also puts a small frame on the wire during a pause. What this does *not* hide:
  the overall volume of a long transfer, and the fine timing correlation between the two directions. It
  raises the cost of size-and-shape classification; it is not an unobservable channel.
- **Server fingerprint.** On its own the server uses Go's `crypto/tls` and Go's HTTP/2: its ServerHello and
  its HTTP/2 SETTINGS are a Go server's, not nginx or a CDN. That is common on the web, but it is a
  fingerprint. An nginx `stream` proxy in front (see KILVATERD.md §9) turns the TLS layer into OpenSSL's, and
  in that mode (`-h2c`) kilvaterd shapes its own HTTP/2 SETTINGS and connection window to a stock nginx's, so
  both layers read as nginx. What is not shaped even then is the HTTP/2 behaviour below the SETTINGS (the
  order of a response's header fields, flow-control and timing).
- **Static decoy.** The decoy is only as convincing as the files you put in it. With an empty directory every
  URL returns 404, and the server warns about it at start.
- **Clock skew.** The client corrects its clock from the `Date` of the page it loads on each new
  connection (§1). Any answer that carries `Date` will do, a 404 included. A client whose clock is more
  than 2 minutes off still fails if that page load fails.
- **Hosting matters more than the protocol.** Some networks throttle or freeze traffic by destination network
  and port, regardless of what the bytes look like. In our measurements, port 443 and a few common web ports
  (80, 8080, 8443) passed in places where uncommon high ports were frozen.

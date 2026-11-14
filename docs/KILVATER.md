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
- A new connection is dialed only when the current one is full, dead, or past its rotation limit: about
  10 minutes or 256 MiB, each connection drawing its own limits within ±30 % of those. Once a connection is
  80 % into a limit the next one is dialed and warmed in the background, so the rotation holds no stream up;
  the old connection finishes the streams it carries.
- Dead connections are found by HTTP/2 PING after an idle gap of 15 to 25 s, drawn once per path.
- From the second connection on, the page and its assets are asked for with `If-None-Match` /
  `If-Modified-Since` from the answers the first one got, as a browser revalidates what it has cached.

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

Worked examples of both tags, with the key and frame bytes, are in [§9](#9-test-vectors).

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
| 5 | CLOSE | one code byte: `0` normal end, `1` the target could not be reached, `2` the target is not allowed, `3` no such session (resume) |
| 6 | ACK | 8 bytes, big-endian: how many DATA bytes of this flow the sender has taken (resume) |
| 7 | END | empty; client only: the flow is over, keep nothing for it (resume) |

A frame of a type this build does not know is skipped, body and all, so a newer peer can add frame types without breaking
an older one.

A length above 16384 is a protocol error. It is never turned into an allocation.

**Order of frames on a stream:**

1. The server's first frame is a PAD of random length (16–271 bytes).
2. The client sends OPEN, then a PAD, then DATA (a TCP target) or DGRAM frames (a
   UDP target) in both directions, and finally CLOSE or end of stream. OPEN, the first DATA
   (or DGRAM) and their PAD leave in one write, so they ride one TLS record.
3. If OPEN does not arrive within 15 s of authentication, the stream is dropped.

**Padding.** DATA is split into frames whose sizes follow a web-like spread rather than a run of
maximum-size records, and PAD frames ride between them; a sender may also send a PAD during a pause. This
is one-sided and needs no agreement: a peer joins DATA frames back together and ignores PAD regardless, so
any padding mode interoperates with any other, in both directions. Both ends pad. The mode — `off`,
`moderate` (default), `heavy`, or `site` — is set per server (`kilvaterd -pad`) and per client (the link's optional
`pad` parameter); it only changes how many frames of what sizes are sent, never the bytes delivered.

`site` does not draw sizes at all. It hands bulk down in pieces of 16375 bytes: with the 9 bytes of an
HTTP/2 frame header that is 16384, one full TLS record, which is what most of a file from the nginx in front
is made of (§8). On the client the request body also gathers writes made while the connection is the slower
side, so an upload leaves in full records as a browser's does. It is meant for the deployment behind an
nginx front (KILVATERD.md §9), and needs `grpc_buffer_size 16k` there: with the default buffer nginx cuts
the tunnel into records of about 4.1 KB whatever the mode. A build that does not know the name runs
`moderate`.

Unless the mode is `off`, the first eight writes of a stream are padded harder, each as one record: a write
shorter than 900 bytes is filled up to 900–1400, a longer one (up to 4096) gets 0–255 more. Those records are
where a TLS handshake carried inside the tunnel shows its sizes.

**UDP.** An OPEN with network byte `2` starts a UDP association instead of a TCP
one: the stream then carries DGRAM frames, one frame per datagram in each
direction, so message boundaries are kept. One stream carries one target — the
one named in OPEN — which is how a per-socket, per-destination association maps
onto a stream; a different destination opens its own stream. DNS (a datagram to
`:53`) and other UDP, such as Nyutag's calls, ride kilvater this way. UDP/443
(QUIC) is not used.

**Resuming a flow.** A TCP flow can outlive the stream that carries it, so a connection that is reset or
goes silent does not end the app's connection. It is optional on both sides and off for UDP.

- The client adds an option after the address in OPEN: `[1][16][session id: 16 random bytes]`. A server
  that predates it ignores everything after the address and serves the flow as before.
- A server that keeps sessions answers with ACK `0` before it dials, and with an ACK on every stream of
  the flow. No ACK before the first DATA or CLOSE means the server does not keep sessions; the client
  then treats the flow as an ordinary one.
- Each side counts the DATA bytes it has taken and sends an ACK every 256 KiB (builds before 14.11.2026:
  every 64 KiB; the step is the receiver's choice and either side accepts any). Each side keeps what it
  sent until it is confirmed, and stops reading its own source while 1 MiB is unconfirmed.
- When the stream is lost, the client opens a new one — on the same connection, a new connection, or
  another entry of the same server process — with OPEN `[3][session id][8 bytes: DATA bytes taken]`.
  The server answers ACK (how many of the client's bytes it has taken) and sends on from the client's
  count; the client sends on from the server's. If the server has no such session it answers CLOSE `3`.
- A session answers only the key that opened it. The last stream to attach owns the flow; an earlier
  one can no longer write to the target.
- The server cannot tell a stream the client dropped from one the network took, so a client that is
  done sends END. Without it the server holds the target for a grace period (30 s by default) and
  closes it if no stream comes back. Sessions live in the server process: a restart ends them.

## 5. Server behaviour

**Dialing the target:**
- The server dials the OPEN target with a 10 s timeout.
- It refuses non-public addresses unless the operator runs with `-allow-private`. Refused targets get
  `CLOSE(2)`; a target that did not answer gets `CLOSE(1)`. A client that sees either before any data knows
  the path itself is fine. Non-public means loopback, RFC 1918, RFC 6598 shared space, link-local (including cloud
  metadata at 169.254.169.254), unique-local, multicast and unspecified.
- The check runs on the address actually dialed, after DNS resolution. A hostname that resolves to
  `127.0.0.1` is refused too.
- The node's own addresses and those listed in `-deny-dst` (its sister nodes) are refused on every port but
  `-self-ports` (80 and 443 by default), so the tunnel cannot be turned on the nodes' own services, tunnel
  ports included. Ports in `-deny-ports` (25 by default) are refused everywhere.
  `-deny-dst-file` holds more such addresses, one per line; it is re-read on SIGHUP, so a fleet address
  change needs no restart.
- `-max-streams-per-key` counts streams per subscriber for per-subscriber (v2) keys only; a shared v1 key is
  one name for every client and is not limited by it.

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
- A server may also hold an allow list of key ids (`-allowed`): an id that is derivable but not listed is refused
  like an unknown one. The list is how account removal and expiry reach the tunnel; revocation alone cannot do it,
  because nobody can compute the id of a token that no longer exists.
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
  Measured on a stand (`tools/kv-wirelab.sh`: kilvaterd behind nginx on loopback, 8 MiB each way, a Go
  client), a spread of sizes is also not what the web server in front sends. A download of a static file
  from that nginx is 8–15 distinct record lengths, mostly 16401 and 8218 bytes; the same download through
  the tunnel is 470–660 distinct lengths in `moderate` and 35–48 in `site`. As a distance between the two
  length distributions (0 the same, 1 nothing in common; two static downloads are 0.00–0.57 apart, most
  often under 0.4): `off` 0.57, `moderate` 0.51–0.66, `heavy` 0.68, `site` 0.15–0.29. That is record
  lengths downstream on loopback only — not timing, not a real path, not the upstream direction, and not a
  classifier's verdict. A decoy that has no large files gives a long transfer nothing to resemble in any
  mode.
  The loopback figures did not hold on a live entry (14.11.2026: a copy of the production nginx front on a
  node, a client and headless Chrome 157 across the Atlantic, tcpdump on the node, `tools/kvshape`). There
  nginx sent a static file as 16401-byte records (79 % of them) and the tunnel, through `grpc_pass` with its
  default buffer, as records of 4122/4113 bytes in every mode: the distance to Chrome's download of the same
  8 MiB was 0.93–0.95 in `moderate` and 0.87–0.88 in the `site` of that day (8192-byte pieces). Three things
  moved it: `grpc_buffer_size 16k` in the front (`moderate` 0.52, and 0.32 on a 1.2 MB file), 16375-byte
  pieces in `site` (0.36 and 0.26), and on the way up the gathering request body (an 8 MiB upload against
  Chrome's POST of the same size: 0.98–0.99 before, 0.20–0.23 after). The client's HTTP/2 layer also used to
  refill its window every few kilobytes — about 850 small records against Chrome's 10 over an 8 MiB download;
  it now waits for half the window, as Chrome does. Upload speed: nginx gives an unbuffered request body a
  window of `http2_body_preread_size` (64 KiB by default), so a stream uploads at most that much per round
  trip: 8 MiB took 21–22 s at 130 ms where Chrome's POST took 1.9 s. `client_body_buffer_size` in the front
  raises that window without changing the SETTINGS nginx advertises (the buffer is per tunnel stream, its
  pages taken as they are written). Timed to the target's answer, 8 MiB up: 3.0 s at 512k, 2.0 s at 1m,
  1.6–2.0 s at 2m; the fronts run 1m. (Earlier figures of 4–9 s counted the 2 s the client waits on a
  silent stream after its source ends, not the upload.) What still differs, measured and not fixed: the
  resume ACK (about 135 small records upstream per 8 MiB downloaded at a 64 KiB step, 44 at 256 KiB; about
  115 against 28 while uploading), and nginx's own WINDOW_UPDATE for every chunk of an unbuffered request
  body (420–580 small records downstream per 8 MiB uploaded, Chrome's POST draws 12; no nginx setting
  removes it). One vantage point outside Russia, record lengths only, no classifier.
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

## 9. Test vectors

These fix the exact bytes of the tag, the v2 key derivation and every frame, so a second implementation can be
checked against them. The machine-readable copy is [`kilvater/testdata/vectors.json`](../kilvater/testdata/vectors.json);
the Go reference checks it in `go test ./...`, and an independent Python reference
([`reference/python`](../reference/python)) checks the same file in CI, so the two implementations are proven to
agree byte for byte.

> The keys below are **frozen test constants** (incrementing bytes), never real keys. A real key is random and
> never appears in this repository.

All values are hex unless noted. Bytes are big-endian.

**v1 tag** (§3):

| Input | Value |
|---|---|
| key (32 bytes) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| path | `/connect` |
| ts (unix seconds) | `1700000000` (= `000000006553f100`) |
| nonce (8 bytes) | `1122334455667788` |

```
mac = HMAC-SHA256(key, "kilvater/1\x00" || ts || nonce || path)[0:16]
    = f0ee9d48d90bf1c08b864d4df389d08c
raw = ts || nonce || mac
    = 000000006553f1001122334455667788f0ee9d48d90bf1c08b864d4df389d08c
tag = base64url(raw) without padding
    = AAAAAGVT8QARIjNEVWZ3iPDunUjZC_HAi4ZNTfOJ0Iw
```

**v2 key and tag** (§3, §7):

| Input | Value |
|---|---|
| master (32 bytes) | `404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f` |
| subscriber | `subscriber-1` |
| path | `/connect` |
| ts | `1700000000` |
| nonce (8 bytes) | `99aabbccddeeff00` |

```
keyID = HMAC-SHA256(master, "kilvater/kid\x00" || subscriber)[0:8]
      = 551ef5fe2f217702
key   = HKDF-SHA256(secret=master, salt="", info="kilvater/key\x00" || keyID, 32)
      = 06fb6a4bec386704fd41c55276f00c4281fdba159b4210a1ee874e1899a9624b
mac   = HMAC-SHA256(key, "kilvater/2\x00" || keyID || ts || nonce || path)[0:16]
      = c31a47118c1af1e436f49551257f01ed
raw   = 0x02 || keyID || ts || nonce || mac
      = 02551ef5fe2f217702000000006553f10099aabbccddeeff00c31a47118c1af1e436f49551257f01ed
tag   = base64url(raw) without padding
      = AlUe9f4vIXcCAAAAAGVT8QCZqrvM3e7_AMMaRxGMGvHkNvSVUSV_Ae0
```

**Frames** (§4), whole bytes `[type][length:3][body]`:

| Frame | Bytes |
|---|---|
| OPEN, TCP, `example.com:443` | `01000011010f6578616d706c652e636f6d3a343433` |
| OPEN, UDP, `1.1.1.1:53` | `0100000c020a312e312e312e313a3533` |
| DATA, `"hello"` | `0200000568656c6c6f` |
| PAD, 8-byte body (body ignored; only length is a signal) | `030000080000000000000000` |
| DGRAM, datagram `0a0b0c0d` | `040000040a0b0c0d` |
| CLOSE, code 0 (normal end) | `0500000100` |
| CLOSE, code 1 (error / refused) | `0500000101` |

Address encoding `[len:1]["host:port"]` for `example.com:443`: `0f6578616d706c652e636f6d3a343433`.

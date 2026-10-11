# Running a Kilvater server

This guide sets up `kilvaterd`, the server side of [Kilvater](KILVATER.md), on a Linux host with systemd.
Kilvater is **experimental**: read the [limits](KILVATER.md#8-limits) first.

You need:

- a Linux server with a public IP;
- a domain name whose A/AAAA record points at the server;
- TCP port 443 free on the server.

## 1. Install the binary

Download `kilvaterd` for your architecture from the
[latest release](https://github.com/tsyrenov1987/farvater-core/releases), check it, and install it:

```sh
VER=v0.1.2          # the release you picked
ARCH=amd64          # or arm64
curl -LO https://github.com/tsyrenov1987/farvater-core/releases/download/$VER/kilvaterd_${VER}_linux_${ARCH}.tar.gz
curl -LO https://github.com/tsyrenov1987/farvater-core/releases/download/$VER/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify kilvaterd_${VER}_linux_${ARCH}.tar.gz --repo tsyrenov1987/farvater-core   # optional, needs gh
tar xzf kilvaterd_${VER}_linux_${ARCH}.tar.gz
sudo install -m 0755 kilvaterd /usr/local/bin/kilvaterd
```

The `gh attestation verify` step is optional. It checks the build provenance signed by GitHub Actions: the
archive was built by this repository's release workflow from the tagged commit.

You can also build from source (Go 1.26+):

```sh
git clone https://github.com/tsyrenov1987/farvater-core && cd farvater-core
CGO_ENABLED=0 go build -trimpath -o kilvaterd ./cmd/kilvaterd
```

## 2. User, keys, decoy

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin kilvaterd
sudo install -d -o root -g kilvaterd -m 0750 /etc/kilvaterd
kilvaterd -genkey | sudo tee /etc/kilvaterd/keys.txt     # one key per line; add more with -genkey
sudo chown root:kilvaterd /etc/kilvaterd/keys.txt && sudo chmod 0640 /etc/kilvaterd/keys.txt
```

The decoy is what everyone without a key sees: browsers, scanners and active probers. **Put a real-looking
static site in it**, with an `index.html`, styles, images and a few pages. Do not leave it empty: an empty
decoy answers 404 at every URL, which looks like nothing real.

Clients use the decoy too. Each new connection starts the way a browser visit does: the client loads
`index.html`, then up to two same-origin stylesheets, scripts or images it links to, then `/favicon.ico`
([KILVATER.md §1](KILVATER.md#1-layers)). A page that links a stylesheet and has a `favicon.ico` makes
that visit look ordinary.

```sh
sudo install -d -o root -g kilvaterd -m 0755 /etc/kilvaterd/decoy
sudo cp -r /path/to/your/site/* /etc/kilvaterd/decoy/
```

## 3. Certificate

There are two ways.

**A. Built-in Let's Encrypt (simplest).** Run with `-acme your.domain`. kilvaterd obtains and renews the
certificate itself through TLS-ALPN-01, which needs **port 443** reachable from the internet. The certificate
is cached in `/var/lib/kilvaterd/acme`.

**B. Your own certificate** (another port, a wildcard, an existing ACME client). Run with
`-cert fullchain.pem -key key.pem`.

- kilvaterd reads the certificate **once at start**, so your ACME client's renew hook must restart it
  (`systemctl restart kilvaterd`), which drops live tunnels. To renew without a restart, put a proxy in
  front and let it hold the certificate (§9).
- The key file must be readable by the `kilvaterd` user.
- The unit sets `ProtectHome=true`, which hides `/root` and `/home`. If your ACME client keeps certificates
  there (acme.sh does), install them into `/etc/kilvaterd`, for example with
  `acme.sh --install-cert -d your.domain --fullchain-file /etc/kilvaterd/fullchain.pem --key-file /etc/kilvaterd/key.pem --reloadcmd "systemctl restart kilvaterd"`.

## 4. systemd

```sh
sudo curl -Lo /etc/systemd/system/kilvaterd.service \
  https://raw.githubusercontent.com/tsyrenov1987/farvater-core/main/deploy/kilvaterd.service
sudo sed -i 's/example.org/your.domain/' /etc/systemd/system/kilvaterd.service
sudo systemctl daemon-reload && sudo systemctl enable --now kilvaterd
journalctl -u kilvaterd -f        # expect "loaded N client key(s)" and "kilvaterd listening on :443"
```

Open the port in your firewall, for example `sudo ufw allow 443/tcp`.

## 5. Flags

| Flag | Default | Meaning |
|---|---|---|
| `-listen` | `:443` | address to listen on |
| `-acme` | — | domain for a built-in Let's Encrypt certificate; empty uses `-cert`/`-key` |
| `-acme-cache` | `/var/lib/kilvaterd/acme` | autocert cache directory |
| `-cert`, `-key` | `cert.pem`, `key.pem` | static certificate (TLS 1.3 only) |
| `-keys` | `keys.txt` | v1 client keys, one 64-hex key per line, `#` comments allowed (optional if `-master` is set) |
| `-master` | — | master key file (64 hex); enables v2 derived keys (§10). Empty disables v2 |
| `-revoked` | — | revoked v2 key ids, one 16-hex line each, `#` comments; reloaded on `SIGHUP` |
| `-decoy` | `/var/www/html` | static files served to everyone without a key |
| `-allow-private` | off | let clients reach loopback/private/link-local addresses |
| `-h2c` | off | serve cleartext HTTP/2 for a TLS-terminating proxy in front (§9); `-listen` may be `unix:/path` |
| `-pad` | `moderate` | downstream padding: `off` \| `moderate` \| `heavy`. Shapes record sizes so a tunnel looks less like one bulk transfer (KILVATER.md §4, §8). `moderate` adds well under 1 % of bytes and no goroutine; `heavy` adds ~1.4 % and keeps a pause from looking idle; `off` is v1 framing. One-sided — old clients read any mode the same way. |
| `-metrics` | — | serve Prometheus metrics on this address, e.g. `127.0.0.1:9900`; empty disables it. Keep it on the loopback (§11) |
| `-max-bytes-per-key` | `0` | refuse a key's new streams once it has carried this many payload bytes up+down; `0` is no limit (§11) |
| `-max-streams-per-key` | `0` | cap a key's concurrent streams; `0` is no limit (§11) |
| `-genkey` | — | print a new random v1 client key and exit |
| `-genmaster` | — | print a new random master key and exit |
| `-issue <id>` | — | with `-master`: print the key id and derived key for a subscriber id, and exit (§10) |
| `-version` | — | print the version and exit |

## 6. Client link

For each key, give the client a link:

```
kilvater://<key>@your.domain:443?sni=your.domain&fp=chrome#my-server
```

If you connect by IP, put the IP in the host part and keep `sni=your.domain`. The path defaults to `/connect`.
An optional `pad=off|moderate|heavy` parameter sets how the client shapes the frames it sends up (§5,
KILVATER.md §4); left out, it is `moderate`. For a v2 derived key (§10) add `&kid=<16-hex>`, with the derived
key as `<key>`; without `kid` the client sends v1 tags. Farvater and the reference CLI read this link
directly:

```sh
farvater probe -catalogue links.txt -url https://cp.cloudflare.com/generate_204
```

## 7. Check it

- **Without a key, you should see your decoy site:**
  `curl -sI https://your.domain/` should return `200` and your `index.html`.
- **With a key, the tunnel should work:**
  `farvater probe` should report `ok`.
- **Revoke a key:** delete its line from `keys.txt`, then `systemctl restart kilvaterd`.

## 8. Operating notes

- **Port choice.** Some networks freeze long-lived traffic to uncommon high ports on hosting networks, whatever
  the protocol. Prefer 443; 8443 or 8080 if 443 is taken.
- **Logs.** The server logs failed dials with the target address. If you do not want those, send stderr
  elsewhere.
- **Restarts** drop live tunnels; clients reconnect on their next connection. A certificate renewal is a
  restart (kilvaterd reads the certificate once), so it drops tunnels too — unless a proxy holds the
  certificate instead (§9).

## 9. Behind a TLS-terminating proxy (recommended for production)

By default kilvaterd terminates TLS itself with Go's `crypto/tls`. That works, but it has two costs:

- **The server's TLS fingerprint is Go's.** Its ServerHello is `crypto/tls`, not the OpenSSL a typical
  site serves. That is common on the web, but it is a fingerprint ([KILVATER.md §8](KILVATER.md#8-limits)).
- **A certificate renewal restarts kilvaterd** (it reads the certificate once), which drops live tunnels.

Putting an OpenSSL proxy (nginx) in front fixes both: the ServerHello an observer sees is the proxy's, and
the certificate lives on the proxy, so renewing it reloads the proxy and never touches kilvaterd. Run
kilvaterd with `-h2c` on a loopback address or a unix socket, and let the proxy terminate TLS and forward
the connection to it.

**Use the `stream` module, not `http`.** A kilvater tunnel is one long request whose body flows in both
directions at once (full duplex). An `http {}` reverse proxy forwards to the upstream over HTTP/1.1, which is
half duplex, and the tunnel stalls. The `stream {}` module terminates TLS at layer 4 and forwards the
decrypted bytes as a raw stream, so the HTTP/2 connection runs end to end between the client and kilvaterd
and full duplex is preserved.

```nginx
# nginx.conf — needs a build --with-stream and --with-stream_ssl_module
stream {
  server {
    listen 443 ssl;
    ssl_certificate     /etc/letsencrypt/live/your.domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_alpn h2;                 # the client negotiates h2; forward it as such
    proxy_pass 127.0.0.1:8081;   # kilvaterd -h2c -listen 127.0.0.1:8081
    proxy_timeout 300s;
  }
}
```

```sh
kilvaterd -h2c -listen 127.0.0.1:8081 -keys /etc/kilvaterd/keys.txt -decoy /var/www/html
# or over a unix socket, with no open port at all:
kilvaterd -h2c -listen unix:/run/kilvaterd/kilvaterd.sock ...
```

Renew the certificate with your ACME client's reload hook pointed at the proxy
(`--reloadcmd "nginx -s reload"`); nginx reloads gracefully and keeps live tunnels, and kilvaterd is never
restarted. A unix socket is group-readable (0660), so the proxy's user must share kilvaterd's group.

**What this does and does not hide.** The TLS layer becomes the proxy's (OpenSSL). The HTTP/2 layer is still
kilvaterd's, because kilvaterd, not the proxy, speaks HTTP/2 end to end through the `stream` — so kilvaterd
shapes its own server fingerprint: in `-h2c` mode it sends its SETTINGS and connection window in the order
and values of a stock nginx (`SETTINGS` MAX_CONCURRENT_STREAMS=128, INITIAL_WINDOW_SIZE=65536,
MAX_FRAME_SIZE=16777215, then a `WINDOW_UPDATE` to a 2³¹−1 window), the server-side counterpart of the
client shaping in [KILVATER.md §1](KILVATER.md#1-layers). An active prober reads those before it sends any
request, and they now read as nginx, not Go. What is not shaped is the HTTP/2 behaviour below the SETTINGS —
the order of a response's header fields, flow control, timing — so this is not a complete server disguise.

**Sharing the port with a real site.** If the host already serves a site on 443, split by SNI with
`ssl_preread` in a `stream` map: the site's names go to the existing server, your tunnel's name to the
`stream` server above. That keeps both on one port.

**Caddy** terminates TLS at layer 7 but proxies to an h2c upstream with full duplex intact
(`reverse_proxy h2c://127.0.0.1:8081`), and it renews certificates on its own, so it is the simplest way to
get the no-restart-on-renewal benefit. It does not change the TLS fingerprint, though: Caddy is written in Go
and uses the same `crypto/tls`. Choose nginx `stream` for the fingerprint, Caddy for the convenience.

## 10. Keys v2: master, per-client keys, revocation

v1 keys (§2) still work and need no change. v2 adds a **master key** from which each client's key is derived,
so you issue and revoke clients without editing the key file on every node (KILVATER.md §7).

**Set up a master** (once, shared across the nodes that should accept the same clients):

```sh
kilvaterd -genmaster > /etc/kilvaterd/master.txt   # keep this secret; it mints every client key
chmod 600 /etc/kilvaterd/master.txt
```

Point the service at it (and, optionally, a revocation list):

```
ExecStart=/usr/local/bin/kilvaterd -master /etc/kilvaterd/master.txt -revoked /etc/kilvaterd/revoked.txt ...
```

With a master set, `-keys` becomes optional; a node may run v2-only.

**Issue a client.** For a subscriber id of your choice (the server never sees it):

```sh
kilvaterd -master /etc/kilvaterd/master.txt -issue "subscriber-1234"
# kid=41285ebd3df3d88f key=1ca7d59d…2072c168
```

Give the client a link with that key and key id:

```
kilvater://1ca7d59d…2072c168@your.domain:443?sni=your.domain&fp=chrome&kid=41285ebd3df3d88f#my-server
```

Nothing is written on the server: the key derives from the master and the id on demand. The same subscriber
id always yields the same id and key, so you can re-issue a lost link without changing anything.

**Revoke a client.** Append its key id to the revocation file and reload — no restart, no cut to other
sessions:

```sh
echo 41285ebd3df3d88f >> /etc/kilvaterd/revoked.txt
systemctl reload kilvaterd        # or: kill -HUP $(pidof kilvaterd)
```

`SIGHUP` re-reads `-keys`, `-master` and `-revoked` and swaps them in atomically. A revocation applies to the
next authentication; tunnels already open are untouched. If a file is malformed at reload, the server logs it
and keeps the keys it already had, so a bad edit never locks everyone out. Add `ExecReload=/bin/kill -HUP $MAINPID`
to the unit so `systemctl reload kilvaterd` works.

**The scheme** (for a worker that issues keys in another language) is in KILVATER.md §7:
`keyID = HMAC-SHA256(master, "kilvater/kid\0"||subscriber)[0:8]`,
`key = HKDF-SHA256(master, "", "kilvater/key\0"||keyID, 32)`. Agree on it with the worker before handing v2
links to clients.

## 11. Metrics and per-key limits

`-metrics 127.0.0.1:9900` serves Prometheus text at `/metrics`. Everything else on that port is a 404, so the
port does one job.

**Keep it off the internet.** The endpoint names key ids and counts traffic. Bind it to the loopback (or a
management overlay), and let the monitor reach it over the channel you already use — for example
`ssh node curl -s localhost:9900/metrics` — rather than opening the port. A non-loopback `-metrics` only logs a
warning; fronting it with your own ACL is up to you. Nothing secret is in the output: a v2 key's series is
labelled by its **key id**, never the key bytes; the shared v1 keys are one series labelled `v1`; target
addresses never appear.

Per key (`key="<id>"` or `key="v1"`): `kilvater_key_up_bytes_total`, `kilvater_key_down_bytes_total`,
`kilvater_key_streams_total`, `kilvater_key_streams_open`. The label set grows only with subscribers that
actually connect (a rejected tag makes no series). Health, unlabelled: `kilvater_connections_total` /
`_open`, `kilvater_handshake_failures_total`, `kilvater_streams_total` / `_open`, `kilvater_auth_failures_total`
(a request whose tag cookie did not verify), `kilvater_replay_hits_total`, `kilvater_open_timeouts_total`,
`kilvater_limit_rejects_total`, `kilvater_up_bytes_total` / `_down_bytes_total`. Counters are over the
process's life and reset on restart.

**Per-key limits** are off by default. `-max-bytes-per-key N` refuses a key's *new* streams once it has carried
`N` payload bytes up+down; `-max-streams-per-key N` caps its concurrent streams. A refused request gets the
decoy, exactly like a bad tag, and a stream already running is never cut — the limits gate new streams only.
Byte totals are per process, so they reset on restart; enforce longer windows from the monitor.

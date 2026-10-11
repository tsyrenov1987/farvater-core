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
  (`systemctl restart kilvaterd`).
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
| `-keys` | `keys.txt` | client keys, one 64-hex key per line, `#` comments allowed |
| `-decoy` | `/var/www/html` | static files served to everyone without a key |
| `-allow-private` | off | let clients reach loopback/private/link-local addresses |
| `-genkey` | — | print a new random key and exit |
| `-version` | — | print the version and exit |

## 6. Client link

For each key, give the client a link:

```
kilvater://<key>@your.domain:443?sni=your.domain&fp=chrome#my-server
```

If you connect by IP, put the IP in the host part and keep `sni=your.domain`. The path defaults to `/connect`.
Farvater and the reference CLI read this link directly:

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
- **Restarts** drop live tunnels; clients reconnect on their next connection.

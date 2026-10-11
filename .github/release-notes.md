`kilvaterd` is the server for [Kilvater](https://github.com/tsyrenov1987/farvater-core/blob/main/docs/KILVATER.md),
a private HTTPS transport. Setup guide: [docs/KILVATERD.md](https://github.com/tsyrenov1987/farvater-core/blob/main/docs/KILVATERD.md).
`farvater` is the reference client CLI: a local SOCKS5 switchboard, plus `probe` for share links.

Changes since v0.1.0 (v0.1.1 was built with Go 1.26.8 by mistake and is withdrawn):

- **Security.** Built with Go 1.26.9 (the release now fails if the toolchain differs from go.mod or govulncheck finds anything in kilvaterd) and x/net 0.61. This clears 17 reachable advisories in net/http, HTTP/2 and
  crypto/tls (see govulncheck). If you run v0.1.0 or v0.1.1 `kilvaterd`, upgrade.
- Ports outside 0–65535 are refused before encoding (found by CodeQL).
- Fuzz targets for frame, address and tag parsing.
- Provenance is attached as `provenance.intoto.jsonl`.

Status: **experimental**.
- No independent security audit yet.
- Known limits are listed in docs/KILVATER.md §8.

To verify a download:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify <archive> --repo tsyrenov1987/farvater-core
```

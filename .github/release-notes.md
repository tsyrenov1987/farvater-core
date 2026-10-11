First public release of the farvater-core binaries.

- **`kilvaterd`** is the server for [Kilvater](https://github.com/tsyrenov1987/farvater-core/blob/main/docs/KILVATER.md),
  a private HTTPS transport. Setup guide: [docs/KILVATERD.md](https://github.com/tsyrenov1987/farvater-core/blob/main/docs/KILVATERD.md).
- **`farvater`** is the reference client CLI. It runs a local SOCKS5 switchboard and has a `probe` command for share links.

Status: **experimental**.
- No independent security audit yet.
- Known limits are listed in docs/KILVATER.md §8.

To verify a download:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify <archive> --repo tsyrenov1987/farvater-core
```

# Security policy

## Reporting a vulnerability

Please report security problems **privately** through GitHub:
[Security → Report a vulnerability](https://github.com/tsyrenov1987/farvater-core/security/advisories/new).
Do not open a public issue for them.

Include what is affected (package, binary, version or commit), how to reproduce it, and what an attacker gains.
We answer within 7 days and aim to ship a fix within 30 days for anything that exposes user traffic, keys or
the server. You will be credited in the advisory unless you ask not to be.

## Scope

In scope:

- the transports in `wire`;
- the Kilvater protocol (`kilvater`, [docs/KILVATER.md](docs/KILVATER.md));
- the `kilvaterd` server;
- the `switchboard`, `catalogue` and `mobile` packages;
- release artifacts.

Especially interesting:

- a way to tell a Kilvater server from an ordinary website without a key (active probing);
- authentication bypass or tag replay;
- reaching non-public addresses through `kilvaterd` without `-allow-private`;
- memory exhaustion from a peer.

Out of scope: the third-party code in `third_party/` (report it upstream), and traffic-analysis limits that
[docs/KILVATER.md §8](docs/KILVATER.md#8-limits) already lists.

## Supported versions

Only the latest release gets fixes.

## Verifying releases

Release binaries are built by GitHub Actions from the tagged commit. Each release has a `SHA256SUMS` file and
build-provenance attestations. You can check an archive with:

```sh
sha256sum --check --ignore-missing SHA256SUMS
gh attestation verify <archive> --repo tsyrenov1987/farvater-core
```

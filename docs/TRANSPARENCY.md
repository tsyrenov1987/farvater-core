# Transparency — what is inside a Farvater VPN build

Build: **Farvater VPN for iPhone 1.0 (6)**. Core: tag [`ios-1.0-6`](https://github.com/tsyrenov1987/farvater-core/tree/ios-1.0-6).
The core's Go code at that tag is the code of commit `ee86cd8`, from which the build's `FarvaterCore.xcframework` was made;
the tag adds only this document and `tools/composition.py`.

## The app around the core

| Part | Whose | What it does |
|---|---|---|
| Farvater app (SwiftUI) | ours | screens, catalogues, receipts, the live chart, Farvater Pro (StoreKit) |
| Packet-tunnel extension (Swift) | ours | the iOS VPN (Network Extension); runs the core and hev-socks5-tunnel |
| Widget (SwiftUI) | ours | the tunnel's state on the Home Screen |
| farvater-core (Go, this repository) | ours, Apache-2.0 | picks the path for every connection by delivery receipts; linked into the app (catalogue checks) and the tunnel extension |
| [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) 2.18.0-2-g2cdc169 | third party, MIT | turns the tunnel's packets into SOCKS connections for the core |

## What the core's machine code is made of

Measured on the arm64 slice of this build's `FarvaterCore.xcframework`: text symbols of the Go object, grouped by module.

| Part | Machine code | Share |
|---|---:|---:|
| Go runtime, standard library, golang.org/x | 4.23 MB | 49.5 % |
| Third-party libraries (below) | 3.84 MB | 45.0 % |
| Compiler-generated (type equality, wrappers, stubs) | 0.30 MB | 3.5 % |
| Our core (`brain`, `switchboard`, `wire`, `catalogue`, `mobile`) | 0.17 MB | 2.0 % |
| Total | 8.55 MB | |

Our part is small in bytes and is the part that decides: which path carries each connection, how delivery is
measured, when a path is bypassed and when it is tried again. The libraries speak the wire formats; the runtime
runs it all.

Not inside: sing-box / Libbox, gVisor, or any other ready-made client core. `github.com/sagernet/sing` appears in
`go.mod` only as an import path that `replace` points at our clean-room shim (`third_party/sing-shim`, see
[NOTICE](../NOTICE)); `go tool nm go.o | grep -c sagernet` prints 0 for this build.

### How to reproduce

```sh
git checkout ios-1.0-6
gomobile bind -target=ios/arm64 -iosversion 17.0 -trimpath -ldflags="-s -w" ./mobile   # upstream golang.org/x/mobile
lipo FarvaterCore.xcframework/ios-arm64/FarvaterCore.framework/FarvaterCore -thin arm64 -output core.a
ar -x core.a go.o
go tool nm -size go.o | python3 tools/composition.py
```

Built with go1.26.4 and gomobile from `golang.org/x/mobile` v0.0.0-20260908204917-8b95e45f8d3e.
`tools/licensegate.sh` checks that nothing GPL/AGPL is linked.

## Third-party modules in this build

Every module with machine code in the core, with the version and `go.sum` hash at the tag.

| Module | Version | License | Machine code | go.sum |
|---|---|---|---:|---|
| google.golang.org/protobuf | v1.36.11 | BSD-3-Clause | 693 KB | `h1:fV6ZwhNocDyBLK0dj+fg8ektcVegBBuEolpbTQyBNVE=` |
| github.com/apernet/quic-go | v0.63.1-0.20261004180939-a10df75c260c | MIT | 660 KB | `h1:cxK8qTA0YCsj68A7zLYDCfPgMTOyt3ePkHh+oXEmYU0=` |
| github.com/xtls/xray-core (protocol and transport packages) | v1.260327.0 | MPL-2.0 | 592 KB | `h1:g4TzxMwyPrxslZh6uD+FiG3lXKTrnNO+b4ky2OhogHE=` |
| google.golang.org/grpc | v1.79.3 | Apache-2.0 | 530 KB | `h1:sybAEdRIEtvcD68Gx7dmnwjZKlyfuc61Dyo9pGXXkKE=` |
| github.com/refraction-networking/utls | v1.8.3-0.20260301010127-aa6edf4b11af | BSD-3-Clause | 458 KB | `h1:er2acxbi3N1nvEq6HXHUAR1nTWEJmQfqiGR8EVT9rfs=` |
| github.com/miekg/dns | v1.1.72 | BSD-3-Clause | 298 KB | `h1:vhmr+TF2A3tuoGNkLDFK9zi36F2LS+hKTRW0Uf8kbzI=` |
| github.com/xtls/reality | v0.0.0-20260322125925-9234c772ba8f | MPL-2.0 | 296 KB | `h1:iy2JRioxmUpoJ3SzbFPyTxHZMbR/rSHP7dOOgYaq1O8=` |
| github.com/klauspost/compress | v1.17.9 | BSD-3-Clause, Apache-2.0 (per package) | 90 KB | `h1:6KIumPrER1LHsvBVuDa0r5xaG0Es51mhhB9BQB2qeMA=` |
| github.com/apernet/hysteria/core/v2 | v2.13.0 | MIT | 54 KB (with extras) | `h1:6hWhxnbGAH04VpInXrq/AVoH+kscha4YECx7Tj2yc9Y=` |
| github.com/apernet/hysteria/extras/v2 | v2.13.0 | MIT | (above) | `h1:cenZ6WcsvwyNvRAUjqNxjDcyAJH7GeGP8DLuSRFSfyo=` |
| github.com/gorilla/websocket | v1.5.3 | BSD-2-Clause | 50 KB | `h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=` |
| github.com/cloudflare/circl | v1.6.3 | BSD-3-Clause | 36 KB | `h1:9GPOhQGF9MCYUeXyMYlqTR6a5gTrgR/fBLXvUgtVcg8=` |
| github.com/andybalholm/brotli | v1.1.0 | MIT | 35 KB | `h1:eLKJA0d02Lf0mVpIDgYnqXcUn0GqVmEFny3VuID1U3M=` |
| github.com/pires/go-proxyproto | v0.11.0 | Apache-2.0 | 23 KB | `h1:gUQpS85X/VJMdUsYyEgyn59uLJvGqPhJV5YvG68wXH4=` |
| github.com/quic-go/qpack | v0.6.0 | MIT | 14 KB | `h1:g7W+BMYynC1LbYLSqRt8PBg5Tgwxn214ZZR34VIOjz8=` |
| github.com/klauspost/cpuid/v2 | v2.3.0 | MIT | 6 KB | `h1:S4CRMLnYUhGeDFDqkGriYKdfoFlDnMtqTiI/sFzhA9Y=` |
| github.com/juju/ratelimit | v1.0.2 | LGPL-3.0 with a static-linking exception | 4 KB | `h1:sRxmtRiajbvrcLQT7S+JbqU0ntsb9W2yhSdNN8tWfaI=` |
| github.com/stretchr/testify | v1.12.1 | MIT | 2 KB | `h1:EuwCh5fleGS7H32xRwO3wRGT7DxrDhLAT6FF8MpWDWE=` |
| google.golang.org/genproto/googleapis/rpc | v0.0.0-20251202230838-ff82c1b0f217 | Apache-2.0 | 2 KB | `h1:gRkg/vSppuSQoDjxyiGfN4Upv/h/DQmIR10ZU8dh4Ww=` |
| lukechampine.com/blake3 | v1.4.1 | MIT | 1 KB | `h1:I3Smz7gso8w4/TunLKec6K2fn+kyKtDxr/xcQEN84Wg=` |
| github.com/stretchr/objx | v0.5.3 | MIT | < 1 KB | `h1:jmXUvGomnU1o3W/V5h2VEradbpJDwGrzugQQvL0POH4=` |
| golang.org/x/mobile (bind runtime) | v0.0.0-20260908204917-8b95e45f8d3e | BSD-3-Clause | (counted with Go) | `h1:zYnHsDmxfxKH/x9DjYNAdoIdMsP8enB1Ncb10b3pdHk=` |

The license texts of all of them ship in the app (menu ⋯ → Open-source licenses) and are listed in
[NOTICE](../NOTICE).

## What the app stores and sends

- **Catalogues and settings:** only on the iPhone, in the app's private storage, left out of backups.
- **Receipts:** in memory for the current session. They are written to a file only when the user taps Export.
- **Per-network memory** (what each path delivered on each network): on the iPhone, forgotten after 7 days without
  use; a Wi-Fi network is known only by a hash of its router's address. It holds no sites and is never sent.
- **Network traffic:** catalogue requests to the addresses the user added; the user's traffic through the paths in
  those catalogues; one 256 KiB test download per connect through a path (the catalogue's test address or
  speed.cloudflare.com); when no path connects, a check of three well-known sites directly, at most once a minute
  (listed in the privacy policy).
- No accounts, no analytics, no advertising and no crash-reporting SDKs. NTSAUTOSIGA LLC receives nothing from
  the app. Privacy policy: https://ntsautosiga.com/farvater/privacy-ios/

## What the user sees of each choice

- **Status:** "Connected" only after the 256 KiB test has arrived; the leading path and the latest receipts.
- **Fairway:** a live chart of the paths — the leader, the reserve, scouting, bypassed paths, bursts where a
  connection ran into a block, bytes moving now. Only events from the core; no sites.
- **Log:** a receipt for every connection — bytes delivered, time to first byte, path, how it ended.
- **Paths:** each path's delivered share, its p90 first byte (once it has five answered connections) and its state:
  leading, in reserve, scouting or bypassing.

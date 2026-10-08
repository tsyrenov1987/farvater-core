# Transparency — what is inside a Farvater VPN build

Build: **Farvater VPN for iPhone 1.0 (11)**. Core: tag [`ios-1.0-11`](https://github.com/tsyrenov1987/farvater-core/tree/ios-1.0-11).
The core's Go code at that tag is the code of commit `aea2248`, from which the build's `FarvaterCore.xcframework` was made;
the tag adds only this document.

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
| Go runtime, standard library, golang.org/x | 2.90 MB | 67.9 % |
| Third-party libraries (below) | 1.07 MB | 24.9 % |
| Our core (`brain`, `switchboard`, `wire`, `kilvater`, `catalogue`, `mobile`) | 0.23 MB | 5.4 % |
| Compiler-generated (type equality, wrappers, stubs) | 0.08 MB | 1.8 % |
| Total | 4.28 MB | |

Our part is small in bytes and is the part that decides: which path carries each connection, how delivery is
measured, when a path is bypassed and when it is tried again. The libraries speak the wire formats; the runtime
runs it all.

Not inside: sing-box / Libbox, gVisor, Xray-core or any other ready-made client core. The wire formats (VLESS with
Vision and XUDP, Trojan, VMess, the REALITY client, WebSocket, gRPC framing, XHTTP) are this project's own code in
package `wire`; Xray-core served only as the protocol reference (see [NOTICE](../NOTICE)). For this build
`go tool nm go.o | grep -cE 'xtls/xray-core|xtls/reality|google.golang.org/grpc|google.golang.org/protobuf'` prints 0,
and `go tool nm go.o | grep -c sagernet` prints 0 (`github.com/sagernet/sing` appears in `go.mod` only as an import
path that `replace` points at our clean-room shim, `third_party/sing-shim`).

### How to reproduce

```sh
git checkout ios-1.0-11
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
| github.com/apernet/quic-go | v0.63.1-0.20261004180939-a10df75c260c | MIT | 470 KB | `h1:cxK8qTA0YCsj68A7zLYDCfPgMTOyt3ePkHh+oXEmYU0=` |
| github.com/refraction-networking/utls | v1.8.3-0.20260301010127-aa6edf4b11af | BSD-3-Clause | 411 KB | `h1:er2acxbi3N1nvEq6HXHUAR1nTWEJmQfqiGR8EVT9rfs=` |
| github.com/klauspost/compress | v1.17.9 | BSD-3-Clause, Apache-2.0 (per package) | 87 KB | `h1:6KIumPrER1LHsvBVuDa0r5xaG0Es51mhhB9BQB2qeMA=` |
| github.com/apernet/hysteria/core/v2 | v2.13.0 | MIT | 47 KB (with extras) | `h1:6hWhxnbGAH04VpInXrq/AVoH+kscha4YECx7Tj2yc9Y=` |
| github.com/apernet/hysteria/extras/v2 | v2.13.0 | MIT | (above) | `h1:cenZ6WcsvwyNvRAUjqNxjDcyAJH7GeGP8DLuSRFSfyo=` |
| github.com/andybalholm/brotli | v1.1.0 | MIT | 35 KB | `h1:eLKJA0d02Lf0mVpIDgYnqXcUn0GqVmEFny3VuID1U3M=` |
| github.com/quic-go/qpack | v0.6.0 | MIT | 13 KB | `h1:g7W+BMYynC1LbYLSqRt8PBg5Tgwxn214ZZR34VIOjz8=` |
| github.com/stretchr/testify | v1.12.1 | MIT | 2 KB | `h1:EuwCh5fleGS7H32xRwO3wRGT7DxrDhLAT6FF8MpWDWE=` |
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
  speed.cloudflare.com); sites the user lists under "Sites around VPN" go directly, not through a path; when
  no path connects, a check of three well-known sites directly, at most once a minute
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

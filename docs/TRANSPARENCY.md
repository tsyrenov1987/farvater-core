# Transparency — what is inside a Farvater VPN build (template; filled per release)

Build: Farvater VPN iOS [version (build)] — farvater-core tag [vX.Y.Z], commit [sha]

## Binary composition (from the linker map of this exact build)

| Part | Share | Source |
|---|---|---|
| Our code (brain, switchboard, adapters, app) | [N %] | this repository + app repository |
| Third-party transport libraries | [M %] | see SBOM below |
| Go runtime | [K %] | golang.org |

How to reproduce: build with `-map $(TARGET_TEMP_DIR)/link.map` in Other Linker Flags (Xcode) and
`go build -trimpath -ldflags="-s -w"`; run `tools/binmap.py link.map` (planned) to get the table above.

## SBOM

| Module | Version | License | Hash |
|---|---|---|---|
| github.com/xtls/xray-core (transport/internet/{reality,splithttp,websocket,tcp,tls}, proxy/vless/encoding) | [v] | MPL-2.0 | [h1] |
| github.com/apernet/hysteria/core/v2 | [v] | MIT | [h1] |
| github.com/heiher/hev-socks5-tunnel | [v] | MIT | [sha] |
| github.com/refraction-networking/utls | [v] | BSD-3-Clause | [h1] |

License gate: `go list -deps ./... | grep -E "sagernet|gvisor"` must be empty (CI).

## What the app stores and sends

- Delivery receipts and the decision journal: on device only (App Group container), rolling window.
- Catalogue URL(s) the user added: on device only.
- Optional quality feedback to the user's own provider: **off by default**; when on, aggregated counts per path, no destinations, no identifiers beyond what the provider's catalogue URL already carries.
- No accounts, no analytics SDKs, no advertising SDKs.

## Why your path was chosen

The app shows, for every path: posterior delivery rate, receipts in the last 15 minutes, the `cut16` flag
(connections that die at 12–28 KB), goodput, and the last decision with its reason. See ARCHITECTURE.md §4–§6.

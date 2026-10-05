# Farvater path catalogue — specification v1 (draft, 05 Oct 2026)

Media type: `application/farvater-catalogue+json`. A plain base64 subscription (list of `vless://`,
`hysteria2://`, `ss://` URIs) is also accepted; labels are then derived from the URIs.

```json
{
  "v": 1,
  "title": "My tunnels",
  "fingerprint": "sha256-…",
  "paths": [
    {"id": "p-reality-1", "uri": "vless://…", "labels": {"rail": "reality", "net": "any"}},
    {"id": "p-cdn-ws",   "uri": "vless://…", "labels": {"rail": "ws", "white": true, "budget_bytes": 32212254720}},
    {"id": "p-hy2-1",  "uri": "hysteria2://…", "labels": {"rail": "hy2", "udp": true}}
  ],
  "probe_urls": ["https://example.org/256k.bin"],
  "priors": { "cell": { "p-reality-1": {"a": 20, "b": 5} } },
  "feedback_url": null,
  "refresh_sec": 1800
}
```

## Fields

| Field | Meaning |
|---|---|
| `v` | schema version, integer |
| `title` | shown to the user |
| `fingerprint` | opaque hash of the path set; a change means "fleet changed" — the client refreshes seamlessly (new catalogue applies to new connections; live connections finish on their old transports) |
| `paths[].id` | stable identifier; evidence and priors are keyed by it |
| `paths[].uri` | standard share URI; the client supports `vless` (reality/xhttp/ws/tcp+tls), `hysteria2`; others ignored. A `vless` path must be encrypted: `security=none` or no `security` is refused |
| `labels.rail` | informational: `reality`, `xhttp`, `ws`, `hy2`, … |
| `labels.net` | `any` / `cell` / `wifi` — a hint about where the path is intended; never a restriction |
| `labels.white` | the path goes through an allow-listed entry; the client avoids spending probes on it |
| `labels.budget_bytes` | remaining traffic budget on a metered path; shown to the user, nothing is sold |
| `labels.udp` | the path can carry UDP |
| `probe_urls` | large objects for the 256 KB volume check right after connect (HTTP Range is used) |
| `priors` | optional weak priors per network context: Beta(a, b) per path id; capped so that 5 fresh receipts outweigh them |
| `feedback_url` | optional; if present AND the user opted in, the client POSTs aggregated receipts (no destinations) |
| `refresh_sec` | how often to refresh the catalogue |

## What is deliberately absent

No `only`, `skip`, `pin`, `deprioritize`, `force` or any other directive that narrows the client's choice.
A server may inform the client; it may not command it. This is a design rule of the core, not an omission.

## Feedback payload (opt-in)

```json
{"ctx": "cell", "paths": {"p-reality-1": {"a": 31, "b": 4, "cut16": false, "goodput_bps": 1840000}}, "v": 1}
```

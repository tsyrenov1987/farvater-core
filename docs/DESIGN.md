# farvater-core — design

Status: design stage, 2026-10. Numbers below are initial hypotheses; the simulator and field data calibrate them.

## 1. Problem

Multi-path proxy clients choose a path by the latency of a tiny health-check request (`urltest`, `fallback`,
`leastping`) and re-elect every few minutes. On networks with behavioural throttling this is blind:

- a path answers a 1 KB probe in 15 ms and then silently stops carrying after ~16–20 KB;
- a burst of parallel TLS handshakes to one SNI can trigger a temporary freeze of the whole path set —
  and a start-up "race of all paths" is exactly such a burst;
- latency correlates with geography, not with delivery; the nearest server is often the worst one.

Add-on fixes (throughput probes that *exclude* a node, remembering the last working path, pinning from the
outside through a control API) all fight the engine's own selector instead of replacing it. farvater-core
replaces it.

## 2. Principles

1. **Receipts over probes.** Evidence = bytes actually delivered on real user connections. Synthetic probes
   are a fallback for idle periods and are always volume probes (≥256 KB), never pings.
2. **The brain owns the choice; transports are dumb.** No transport contains selection logic, groups or fallbacks.
3. **No path is ever removed.** Bad paths get a low posterior and a small exploration budget; they can always recover.
4. **Switch only between connections and only on evidence.** Never inside a live connection. RTT is not a criterion anywhere.
5. **Handshake rate is a managed resource.** No start-up races; connection pools; per-SNI and per-IP limits.
6. **Every decision is explainable.** Decision journal with later outcomes; the UI can show "why this path".
7. **Provider-neutral by construction.** Paths come from an open catalogue; servers may send priors, never commands.

## 3. Components

```
 app (thin UI)  <-- IPC: state snapshots / commands -->  tunnel process
 ┌──────────────────────────────────────────────────────────────────────────────┐
 │ TUN -> tun2socks (hev-socks5-tunnel) -> SWITCHBOARD (Go)                     │
 │                                           │                                  │
 │   BRAIN: Ledger (receipts) <- flow counters                                  │
 │          Scorer (posteriors, forgetting, cut signature)                      │
 │          Selector (Thompson sampling + hysteresis + exploration floor) ──────┼─> "which wire for this flow"
 │          Governor (handshake rate per SNI / IP)                              │
 │          Diagnoser (path vs. local network vs. destination)                  │
 │          Memory (per network context, TTL) + Priors (from catalogue)         │
 │          Journal (decision -> outcome)                                       │
 │                                           ▼                                  │
 │   WIRES (dumb): VLESS+Reality(+Vision) · VLESS+XHTTP · VLESS+WS · Hysteria2  │
 └──────────────────────────────────────────────────────────────────────────────┘
```

## 4. Receipt

```json
{"path":"p1","ctx":"cell","t_wire_ready":180,"t_first_byte":410,"up":1830,"down":212340,"dur_ms":9400,
 "max_gap_ms":620,"stalls":0,"end":"remote_fin|local_close|wire_reset|stall_abandon|timeout",
 "down_at_fail":null,"dst_class":"tls443|dns|quic|other","explore":false}
```

- **First byte:** first downstream byte after the request was sent. None within `T_fb = max(3 s, 3·p90_fb(path, ctx))`
  → `timeout`, negative first-byte evidence.
- **Stall:** after the first byte, downstream silence ≥ `T_stall = max(4 s, 3·p90_gap)` while the local app has
  sent data after the last received byte (it is waiting). Local close inside the stall window → `stall_abandon`.
- **Delivered:** `down ≥ 32 KB` without a stall, or `remote_fin` after ≥1 KB without a stall.
- **Size classes:** <16 KB — first-byte evidence only; 16–256 KB — "not cut" evidence; >256 KB — also goodput.
- **Cut signature (`cut16`):** median `down_at_fail` over ≥3 failed flows in 12–28 KB. Detected from receipts alone.
- **Not evidence against a path:** local close before first byte within 1 s; destinations that failed on ≥2 paths in a row.

## 5. Scoring and selection

Per (path, context): `deliv ~ Beta(a,b)` (flows ≥16 KB completed without stall), `fb ~ Beta(a,b)` (first byte in time),
goodput EWMA (flows >256 KB), `cut16` flag, `last_evidence`. Exponential forgetting: half-life 10 min for receipts,
30 min for probes. Prior: `Beta(1,1)` + persisted context memory at half weight (TTL 7 days) + catalogue priors at
quarter weight; priors never outweigh 5 fresh receipts.

- **New flow:** Thompson sampling on `θ = deliv · fb`. A path with five bad receipts still gets roughly one flow in
  twenty; a path without data gets more until it has evidence. Floor: every path gets ≥1 flow per 10 minutes.
  Exploration flows are small-destination classes (dns, tls443) where possible; a flow that grows past 256 KB keeps
  going and is tagged `explore`.
- **Leader hysteresis:** the leader (≥80 % of flows) changes only if a challenger is `δ = 0.15` better in posterior
  mean with ≥5 own receipts in 15 min, or the leader stalled twice in a row.
- **Connect stage:** no first byte within `T_stagger = min(T_fb, p90_fb(leader)+300 ms)` → repeat the same connect
  (with the held first client segment) over the runner-up; first responder wins, the other is closed. The duplicate
  first segment is harmless for TLS and server-speaks-first protocols; accepted knowingly for the rest.
- **UDP/DNS:** DNS only through the wire (DoH/DoT); receipt = answer in time. UDP/443 follows the leader; if the
  leader cannot carry UDP or UDP first-byte rate < 30 %, UDP/443 is dropped (apps fall back to TCP).
- **Idle:** one 256 KB volume probe (HTTP Range to `probe_urls`) on the leader right after connect; status is
  "connecting" until it passes. Exploration probes ≤1 per 10 min per path, never on metered paths, never in bursts.

## 6. Fast reaction to active interference

The scoring layer in section 5 is deliberately slow: it must not flap on
ordinary jitter. But a DPI / throttling box does not produce jitter — it
produces sharp, recognisable damage: a RST injected mid-stream, a silent black
hole after the handshake, a sudden goodput collapse, dropped SYNs. Waiting for
five receipts and two stalls to react to that is too slow.

A circuit breaker makes the response **asymmetric**: promotion stays slow,
demotion is immediate.

**Signatures.** Every receipt is classified: *reset* (the wire was reset after
the first byte, often at the cut16 byte count — an active mid-stream reset);
*handshake* (failed before the wire was ready — a dropped SYN, a reset on
connect, or a behavioural freeze); *blackhole* (the wire connected but no first
byte arrived and it then timed out — a silent drop after the handshake);
*throttle* (the first byte arrived, then goodput collapsed or the flow stalled —
shaping).

**Trip.** A single *reset* trips a rail at once, since it is unambiguous. The
softer signatures must repeat inside a short window to trip. A tripped rail is
avoided as a primary for a signature-dependent cooldown (reset longest, throttle
shortest); if it was the current leader it is dethroned immediately, bypassing
the section 5 hysteresis.

**This is not narrowing.** A trip is client-side, per-user, reactive to measured
delivery, and always time-boxed. When the cooldown expires the rail re-enters
selection and the exploration floor re-probes it. No rail is ever removed: the
breaker heals a suffering user by adding live re-measurement, never by taking a
rail away, and the fallback set can never shrink to nothing.

**Diverse escape.** The connect-stage backup, and the third dial added in storm
mode, are chosen not only by delivery but biased toward a rail *unlike* the one
in trouble — a different protocol, a different server name, a different
address — because a block tends to strike one of those axes. A shared-name
sibling of a failing rail is not chosen as its own backup.

**Storm mode.** When several distinct rails trip inside the window the client is
under a coordinated disturbance. Exploration is raised and a third, diverse dial
is added, so delivery is re-measured across rails in parallel instead of leaning
on one leader; it collapses back to a single leader once one proves itself.

**Adaptive deadlines.** The abandon-and-migrate deadline for the first byte is
derived per rail from that rail's own measured P90 first-byte time, floored and
capped, so a healthy rail is given up on in well under two seconds while a
genuinely slow one is not misjudged. The handshake governor keeps the resulting
retries from clustering into a behavioural freeze.

All thresholds here are initial hypotheses, to be calibrated against field
measurement; none of them is a protocol constant.

## 7. Differential diagnosis

| Observation | Conclusion | Action |
|---|---|---|
| All paths without first byte, ≥2 flows | local network down | no receipts recorded; back-off |
| One destination fails on ≥2 paths, others fine | destination | path not punished; destination quarantined 5 min |
| One path: `cut16` or stalls, others fine | path throttled | posterior falls; journal entry |
| All paths of one SNI/IP stop for ~2 min after a handshake burst | behavioural freeze | governor tightens ×2 for 10 min; paths parked, not punished |
| Network context change | new (path, ctx) pair | previous state saved; new state seeded from memory |

## 8. Handshake governor

Token buckets: ≤2 new TLS handshakes per SNI per 400 ms, ≤4 per IP per 1 s; excess waits in a queue (the local
TCP SYN is acknowledged locally, the wire connects a few tens of ms later). Cold start: only the leader connects,
plus the staggered connect-stage retry. No race of all paths. Hysteria2 runs with standard congestion control
(BBR), not a fixed-bandwidth custom CC, because custom CCs are fingerprintable by their reaction to loss.

## 9. Context memory and priors

Context key: `wifi:<gateway-hash>` / `cell` / `wired`, cached per session, changed only after a 60 s debounce.
Stored: posteriors, `cut16`, goodput, timestamps; TTL 7 days. Catalogue priors are weak and advisory.

## 10. Catalogue

See `CATALOGUE-SPEC.md`. The schema has no `only/skip/pin` directives by design.

## 11. Engine and licensing

Own Go module. Wires from Xray-core packages (MPL-2.0: Reality dialer, VLESS encoding, XHTTP, WebSocket),
Hysteria `core/v2` (MIT), tun2socks via hev-socks5-tunnel (MIT), uTLS (BSD-3). No GPL/AGPL code is linked;
CI fails if any `sagernet/*` module appears in `go list -deps`. Built with `gomobile` into an xcframework / aar,
`-trimpath -ldflags="-s -w"`.

## 12. Platform notes

- iOS Network Extension: ~50 MiB budget → C tun2socks with small buffers, Go GC every second, fixed buffer pools,
  ring-buffer logs; watchdog cancels the tunnel if the switchboard stops answering (no "protected" status over a dead core).
- Android: VpnService + the same aar.

## 13. Verification

A deterministic simulator models paths (latency, cut-at-bytes, freeze on handshake bursts, late-onset throttling),
destinations (dead sites) and the local network (outages), and runs the same workload through farvater-core and
through a latency-baseline policy (`urltest`: lowest RTT every 3 min). Tests assert that the baseline fails and
farvater-core succeeds on throttled scenarios, that no path is ever starved, that no flow is switched mid-stream,
and that the governor limits hold. A second family of scenarios switches active interference on mid-run — injected
RST, silent black holes, and a coordinated multi-rail outage — and asserts that the circuit breaker (section 6)
reacts faster than the slow learner alone: it recovers success in the first minute after a reset storm, sends far
fewer flows into a silently dropped rail, and settles on a surviving rail under a coordinated storm. Every such
test also runs with the breaker switched off, so the breaker must demonstrably beat its own absence. Thresholds
are then calibrated on field receipts.

## 14. Non-goals

Accounts, payments, provider advertising, server-side forcing of clients, latency-based selection.

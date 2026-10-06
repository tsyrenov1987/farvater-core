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
 │   WIRES (dumb): VLESS · Trojan · VMess over Reality/TLS/WS/XHTTP/gRPC · Hy2  │
│                 olcRTC calls, run by the Android app behind a loopback door  │
 └──────────────────────────────────────────────────────────────────────────────┘
```

## 4. Receipt

```json
{"path":"p1","ctx":"cell","t_wire_ready":180,"t_first_byte":410,"up":1830,"down":212340,"dur_ms":9400,
 "max_gap_ms":620,"stalls":0,"end":"remote_fin|local_close|wire_reset|stall_abandon|timeout",
 "down_at_fail":null,"dst_class":"tls443|dns|quic|other","explore":false}
```

- **First byte:** first downstream byte after the app's first bytes. The clock starts when the app sends, not when
  the path connects: a connection the app has not used yet is waiting for nothing. None within
  `T_fb = max(3 s, 3·p90_fb(path, ctx))` → `timeout`, negative first-byte evidence.
- **Stall:** after the first byte, downstream silence ≥ `T_stall` (4 s) **in the middle of a TLS record** of the
  app's stream. Record headers travel in the clear and servers write records whole, so silence inside a record means
  bytes already sent are missing. Silence at a record boundary is a keep-alive connection with nothing to say (most of
  a real connection's life: HTTP/2 idles between requests and sends WINDOW_UPDATE/SETTINGS ACK that expect no reply)
  and is not evidence. Non-TLS streams get no stall verdict after they have answered. Local close inside a stall →
  `stall_abandon`.
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
  going and is tagged `explore`. Exploration takes at most 10 % of a minute's flows (60 % in a storm): at 20 % the
  simulator showed the same delivery for twice the dials an observer counts (`TestStealthReport`).
- **Leader hysteresis:** the leader (about 90 % of flows outside a storm) changes only if a challenger is `δ = 0.15` better in posterior
  mean with ≥5 own receipts in 15 min, or the leader stalled twice in a row.
- **Connect stage:** no first byte within `T_stagger = min(T_fb, p90_fb(leader)+300 ms)` → repeat the same connect
  (with the held first client segment) over the runner-up; first responder wins, the other is closed. The duplicate
  first segment is harmless for TLS and server-speaks-first protocols; accepted knowingly for the rest.
- **UDP:** an association (one per app socket and destination) rides the leader, then the other paths in the
  brain's order (a path that looks like no HTTP only as the first try, see §6); a path that cannot carry UDP is
  passed over, and one that ends an association at once with no answer goes to the back of that order for
  10 minutes (reordered, never removed). VLESS and VMess carry UDP as XUDP — the framing Vision requires, naming
  each datagram's address — Trojan in its own address-framed packets, and Hysteria 2 in its QUIC datagrams. UDP gives no delivery evidence and files no
  receipts. UDP/443 (QUIC) is refused, so browsers and apps fall back to TCP, where delivery is measured.
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
the section 5 hysteresis. The status reports each tripped rail's remaining
cooldown, so the apps show when it returns. It also carries each receipt's
signature and, per path, how many receipts were served and how many blocked,
so the apps word receipts and delivery shares exactly as the breaker reads them.

**This is not narrowing.** A trip is client-side, per-user, reactive to measured
delivery, and always time-boxed. When the cooldown expires the rail re-enters
selection and the exploration floor re-probes it. No rail is ever removed: the
breaker heals a suffering user by adding live re-measurement, never by taking a
rail away, and the fallback set can never shrink to nothing.

**Diverse escape.** The connect-stage backup, and the third dial added in storm
mode, are chosen not only by delivery but biased toward a rail *unlike* the one
in trouble — a different protocol, a different server name, a different
address — because a block tends to strike one of those axes. A shared-name
sibling of a failing rail is not chosen as its own backup. A path whose traffic
looks like no HTTP (Hysteria 2 under Salamander noise, an olcRTC video call) is never a backup: it
takes flows as the leader or on exploration, by proven delivery, but is never the
connect-stage backup, the storm's third dial, a failed flow's retry or a UDP
association's second try. Whoever blocks the path a flow went to sees the flow
retried only over HTTPS-shaped connections.

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
| No path connects, but allow-listed sites answer when dialled directly | restricted network (allow-list only) | its own context (§9); failures count again |
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

Context key: `wifi:<gateway-hash>` / `cell` / `wired`, reported by the app when the network changes and switched
at once, with no tunnel restart: the network left keeps its state for the session, the one entered resumes its
state or starts from memory. A flow that straddles the change is not evidence for either network (like a flow
the device slept through), so the handover does not pollute either memory and flapping costs nothing.

Stored per network: delivery and first-byte posteriors, `cut16`, goodput, time of the last evidence; TTL 7 days,
at most 16 networks. Memory counts at half weight and is capped like any prior, so five fresh receipts outweigh
it. A path without memory gets the catalogue's prior for the network, or for its kind (`wifi` for
`wifi:<hash>`). Catalogue priors are weak and advisory.

Restricted network (`<key>:wl`): a mobile network that lets only allow-listed addresses through. When no path
connects, the switchboard dials a few allow-listed sites directly (verified TLS, at most once a minute). An answer
means the network is up and shuts the paths out: the brain moves to the network's restricted variant, where the
paths that delivered there before go first (the first time, those the catalogue labels `white`), and for two
minutes after each answer a path that fails to connect is evidence against it, not a sign of a dead network.
When two of the paths that were silent at entry connect again, the brain returns to the plain network. Only the
order changes: every path stays in the fan.

## 10. Catalogue

See `CATALOGUE-SPEC.md`. The schema has no `only/skip/pin` directives by design.

## 11. Engine and licensing

Own Go module. Wires from Xray-core packages (MPL-2.0: Reality dialer, VLESS, Trojan and VMess encoding, XHTTP,
WebSocket, gRPC),
Hysteria `core/v2` (MIT), tun2socks via hev-socks5-tunnel (MIT), uTLS (BSD-3). No GPL/AGPL code is linked;
CI fails if any `sagernet/*` module appears in `go list -deps`. Built with `gomobile` into an xcframework / aar,
`-trimpath -ldflags="-s -w"`. olcRTC is not linked: the Android app runs olcRTC's own program beside the core (§12).

## 12. Platform notes

- iOS Network Extension: ~50 MiB budget → C tun2socks with small buffers, Go GC every second, fixed buffer pools,
  ring-buffer logs; watchdog cancels the tunnel if the switchboard stops answering (no "protected" status over a dead core).
- Android: VpnService + the same aar. The app excludes itself from the VPN (its own connections to the paths go out
  directly), routes 0.0.0.0/0 and ::/0 into hev-socks5-tunnel, and answers DNS with mapped addresses so the
  switchboard receives names. The interface comes up only after a delivery proof through the switchboard.
- Both apps hand UDP to the switchboard inside TCP (hev-socks5-tunnel's UDP-in-TCP command): every datagram is
  framed on the association's own loopback connection, so no UDP port is opened on the device. hev holds one
  returning datagram in 1500 bytes with its address; a larger one would end its session, so the switchboard drops it.
- Destinations that mean nothing at a path's exit (loopback, private, link-local, 100.64/10, 198.18/15) are refused
  at the SOCKS step with no dial and no receipt; otherwise Android's DNS-over-TLS probe of the tunnel's own DNS
  address files failures against healthy paths.
- The switchboard's loopback SOCKS5 port is reachable by every app on the device, and detection tools scan
  loopback ports for open proxies: through one, any app (including one the user keeps out of the tunnel) could
  learn the path's exit address. The mobile layer therefore issues fresh random credentials on each start and
  the port admits only them (RFC 1929); hev-socks5-tunnel presents them. No credentials, no proxy.
- While the delivery proof runs, the mobile layer reports how much of the probe has arrived and its announced
  size, so the apps can count real bytes up to "connected" instead of spinning.
- Hosted paths: olcRTC carries TCP through a video call (WB Stream, Telemost, Jitsi). The call needs a WebRTC stack
  the core does not link, so the Android app runs olcRTC's own program as a separate process (its crash cannot take
  the tunnel down) and hands the core a loopback SOCKS5 door with fresh credentials. The core carries flows through
  the door and judges the path like any other; it looks like no HTTP, so it is never a backup (§6). A call sits in a
  room other people share and costs traffic even idle, so the core asks for it only on need — while the network is
  restricted, while the path leads, or when the catalogue has nothing else — and for ten minutes after. The rest of
  the time the path sleeps: it is neither picked nor tried, its silence is no evidence, and once its door is up
  again the exploration floor gives it a flow at once. The iOS app runs no call (the extension's memory budget), so
  there such paths are skipped. Calls carry TCP only.

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

The simulator generates receipts directly, so the switchboard's byte meter has its own tests: completed responses
followed by keep-alive silence, and HTTP/2 control frames after a response, must not count as stalls; silence inside
a TLS record must. A live test drives real HTTP/2 traffic with idle pauses through the switchboard and requires
receipts without stalls and no tripped rail. (The first Android run showed why: idle browser connections were
scored as throttling and the best rail was benched.)

The simulator also counts what an observer of the client's connections sees (`sim/stealth.go`): servers per hour,
distinct tunnels per ten minutes, exploration dials, failures, a failure followed within a second by a server unseen
for ten minutes, and one followed within a second by a path that looks like no HTTP. `TestStealthReport` runs the
core and a browser-like prototype — retry on the same server only, QUIC only where TCP delivered lately, rarer
exploration — over an hour of a fleet shaped like a real one under the blocks seen in the field. Whether the core
takes up any of the prototype is decided on its delivery numbers; the prototype lives in the simulator alone.

## 14. Non-goals

Accounts, payments, provider advertising, server-side forcing of clients, latency-based selection.

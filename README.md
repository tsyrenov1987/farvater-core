# farvater-core

**Path selection by proven delivery, not by ping.** The routing core of Farvater VPN.

Status (05 Oct 2026): **Phases 0–1 done** — the decision core (`brain`) with an anti-interference circuit breaker,
a deterministic simulator (`sim`), real transports (`wire`: VLESS+Vision over Reality/TLS/WebSocket/XHTTP/gRPC, and
Hysteria 2 with Salamander), a SOCKS5 switchboard (`switchboard`) that turns live flows into receipts, and a reference CLI
(`cmd/farvater`). Full design: [docs/DESIGN.md](docs/DESIGN.md).

```
go test ./... -v
```

Seeded simulator results, success rate of real flows (farvater vs. `urltest` baseline):

| Scenario | farvater | urltest |
|---|---|---|
| fastest-ping path silently cuts at 18 KB, slow path carries | 0.99 | 0.42 |
| leader starts cutting at minute 10 (late onset) | 1.00 (min 13–30) | 0.42 |
| all paths healthy | 1.00 | 1.00 |
| dead destination (10 % of flows) | leader kept, posterior 0.99 | — |
| 2-minute local outage | not counted as evidence | — |
| handshake-burst freeze hypothesis (5 paths, one SNI, page loads) | 1.00, 0 freezes | 0.03, 6 freezes |
| 60 min: no path starved | every path ≥ 1 flow / 10 min | — |

Circuit-breaker scenarios (active interference switched on mid-run; farvater with the breaker vs. the slow learner alone):

| Scenario | with breaker | breaker off |
|---|---|---|
| leader injects RST on big flows — success in the first minute after onset | 0.97 | 0.81 |
| leader silently black-holes — wasted primary attempts on the dead rail | 11 | 37 |
| four of six rails die at once — wasted attempts on dead rails (first 2 min) | roughly halved | baseline |

The baseline is *required* to fail on the throttled scenarios — a test that passes on the old selection logic
would prove nothing.

## What is different

Every existing multi-path client picks the path with the lowest latency of a tiny health-check request
(`urltest`, `fallback`, `leastping`). On throttled networks this is blind: a path answers in 15 ms and then
silently stops carrying after 16–20 KB. farvater-core inverts the hierarchy:

- **Receipts, not probes.** The unit of evidence is a *delivery receipt* of a real user connection:
  time to first byte, bytes delivered, longest gap, how it ended, bytes at failure.
- **The brain owns the choice; transports are dumb.** Transports (VLESS+Reality, XHTTP, WebSocket, Hysteria2)
  contain no selection logic, groups or fallbacks.
- **Bayesian selection.** Per (path, network context): Beta posterior of "a ≥16 KB connection completed
  without a stall" with exponential forgetting, Thompson sampling, hysteresis for the leader, and a small
  exploration budget — so **no path is ever removed**, only demoted.
- **Switch only between connections and only on evidence.** At connect time: staggered retry over the
  runner-up path (Happy Eyeballs between paths). Inside a live connection: never.
- **Handshake governor.** At most 2 new TLS handshakes per SNI per 400 ms, no start-up race of all paths.
- **Differential diagnosis.** Path vs. local network vs. destination — a path is not punished for a dead site.
- **Explainable.** Every decision is journaled with its later outcome and shown to the user ("why this path").
- **Provider-neutral.** Paths come from an open *catalogue* format ([docs/CATALOGUE-SPEC.md](docs/CATALOGUE-SPEC.md));
  the schema has no `only/skip/pin` directives — servers may send priors, never commands.

## Non-goals

No accounts, no payments, no provider advertising, no server-side forcing of clients. The core is a library;
apps built on it decide their own UI and business model.

## Planned stack

Go module built with `gomobile`; transports from Xray-core packages (MPL-2.0), Hysteria `core/v2` (MIT),
TUN via hev-socks5-tunnel (MIT). License gate in CI: no GPL/AGPL in the dependency graph.

## License

Apache-2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

---

## По-русски

Ядро маршрутизации Farvater VPN: путь для каждого соединения выбирается по **квитанциям реальной доставки**
(первый байт, доставленные байты, паузы, где встал), а не по задержке крошечной пробы. Мозг владеет выбором,
транспорты глупые; ни один путь не удаляется — только понижается; смена пути только между соединениями и
только по доказательствам; темп рукопожатий ограничен; каждое решение объяснимо. Полный документ — [docs/DESIGN.md](docs/DESIGN.md) (англ.). Статус: проектирование, кода пока нет.

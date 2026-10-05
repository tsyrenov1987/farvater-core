# farvater-core

**Path selection by proven delivery, not by ping.** The routing core of Farvater VPN.

Status: design stage (05 Oct 2026). No code yet — see [docs/DESIGN.md](docs/DESIGN.md) for the full design.

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

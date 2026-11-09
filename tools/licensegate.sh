#!/bin/sh
# License gate: nothing GPL/AGPL may be compiled into farvater-core.
# Checked on what is actually linked (packages and the modules that provide
# them), not on the full module graph, which carries unused requirements of
# upstream go.mod files. The sing import path is allowed only when it resolves
# to our clean-room shim. gVisor is Apache 2.0 and allowed where the computers'
# packet engine needs it (desktop/engine.go); the phones' code must not link it.
set -e
cd "$(dirname "$0")/.."
bad=0
pkgs=$(go list -deps ./... 2>/dev/null)
for p in $(printf '%s\n' "$pkgs" | grep -E "sagernet|gvisor|shadowsocks-go|shadowsocks" || true); do
  case "$p" in
    github.com/sagernet/sing/common/control) ;;
    gvisor.dev/gvisor/*) ;;
    *) echo "forbidden package linked: $p"; bad=1 ;;
  esac
done
for m in $(go list -deps -f '{{if .Module}}{{.Module.Path}}={{with .Module.Replace}}{{.Path}}{{end}}{{end}}' ./... 2>/dev/null | sort -u | grep -E "sagernet|gvisor|shadowsocks" || true); do
  case "$m" in
    "github.com/sagernet/sing=./third_party/sing-shim") ;;
    "gvisor.dev/gvisor=") ;;
    *) echo "forbidden module linked: $m"; bad=1 ;;
  esac
done
if go list -deps ./mobile/... ./switchboard/... ./wire/... ./kilvater/... 2>/dev/null | grep -q '^gvisor\.dev/'; then
  echo "gVisor linked into the phones' code"; bad=1
fi
if [ "$bad" = 1 ]; then exit 1; fi
echo "license gate: ok (linked modules: $(go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./... | sort -u | grep -c .))"

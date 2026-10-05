#!/bin/sh
# License gate: nothing GPL/AGPL may be compiled into farvater-core.
# Checked on what is actually linked (packages and the modules that provide
# them), not on the full module graph, which carries unused requirements of
# upstream go.mod files. The sing import path is allowed only when it resolves
# to our clean-room shim.
set -e
cd "$(dirname "$0")/.."
bad=0
pkgs=$(go list -deps ./... 2>/dev/null)
for p in $(printf '%s\n' "$pkgs" | grep -E "sagernet|gvisor|shadowsocks-go|shadowsocks" || true); do
  case "$p" in
    github.com/sagernet/sing/common/control) ;;
    *) echo "forbidden package linked: $p"; bad=1 ;;
  esac
done
for m in $(go list -deps -f '{{if .Module}}{{.Module.Path}}={{with .Module.Replace}}{{.Path}}{{end}}{{end}}' ./... 2>/dev/null | sort -u | grep -E "sagernet|gvisor|shadowsocks" || true); do
  case "$m" in
    "github.com/sagernet/sing=./third_party/sing-shim") ;;
    *) echo "forbidden module linked: $m"; bad=1 ;;
  esac
done
if [ "$bad" = 1 ]; then exit 1; fi
echo "license gate: ok (linked modules: $(go list -deps -f '{{if .Module}}{{.Module.Path}}{{end}}' ./... | sort -u | grep -c .))"

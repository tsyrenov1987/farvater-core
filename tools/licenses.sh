#!/bin/sh
# Prints the license (and NOTICE) text of everything linked into the mobile bindings: the
# Go runtime, every module that provides a linked package, and x/mobile's
# bind runtime. The apps ship this as their open-source licenses page.
set -e
cd "$(dirname "$0")/.."
emit() { # label dir
  for f in LICENSE LICENSE.md LICENSE.txt LICENCE COPYING; do
    if [ -f "$2/$f" ]; then
      printf '==== %s ====\n\n' "$1"
      cat "$2/$f"
      printf '\n'
      for n in NOTICE NOTICE.txt NOTICE.md; do
        if [ -f "$2/$n" ]; then cat "$2/$n"; printf '\n'; fi
      done
      return 0
    fi
  done
  echo "licenses: no license file for $1 in $2" >&2
  exit 1
}
goroot=$(go env GOROOT)
[ -f "$goroot/LICENSE" ] || goroot="$goroot/.." # Homebrew keeps it one level up
emit "Go (runtime and standard library)" "$goroot"
GOOS=android GOARCH=arm64 CGO_ENABLED=1 go list -deps \
  -f '{{with .Module}}{{.Dir}}|{{.Path}}{{with .Replace}} (clean-room replacement in {{.Path}}){{end}}{{end}}' \
  ./mobile golang.org/x/mobile/bind/java golang.org/x/mobile/bind/seq |
  sort -u |
  while IFS='|' read -r dir label; do
    [ -n "$dir" ] && emit "$label" "$dir"
  done

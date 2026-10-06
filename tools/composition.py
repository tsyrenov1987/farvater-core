#!/usr/bin/env python3
"""What the core's machine code is made of, by module.

Reads `go tool nm -size` of the Go object in the iOS bindings (go.o, from the
arm64 slice of FarvaterCore.xcframework) on stdin and prints machine code
(text symbols) per part and per third-party module. See docs/TRANSPARENCY.md.
"""
import collections
import re
import sys

OURS = "github.com/tsyrenov1987/farvater-core"


def package(symbol):
    head = re.split(r"[\[(]", symbol, maxsplit=1)[0]
    dot = head.find(".", head.rfind("/") + 1)
    return head[:dot] if dot > 0 else None


def module(pkg):
    parts = pkg.split("/")
    if "." not in parts[0]:
        return "std"
    if pkg.startswith(OURS):
        return OURS
    if parts[0] in ("github.com", "golang.org"):
        return "/".join(parts[:3])
    return "/".join(parts[:2])


def part(mod):
    if mod is None:
        return "compiler-generated (type equality, wrappers, stubs)"
    if mod == OURS:
        return "our core (farvater-core)"
    if mod == "std" or mod.startswith("golang.org/x/"):
        return "Go runtime, standard library, golang.org/x"
    return "third-party libraries"


parts, mods = collections.Counter(), collections.Counter()
for line in sys.stdin:
    f = line.split(None, 3)
    if len(f) < 4 or f[2] not in ("T", "t"):
        continue
    size, name = int(f[1]), f[3].strip()
    pkg = None if name.startswith(("type:", "go:", "go.")) else package(name)
    mod = module(pkg) if pkg else None
    parts[part(mod)] += size
    if part(mod) == "third-party libraries":
        mods[mod] += size

total = sum(parts.values())
print(f"| Part | Machine code | Share |\n|---|---:|---:|")
for name, size in parts.most_common():
    print(f"| {name} | {size / 1e6:.2f} MB | {100 * size / total:.1f} % |")
print(f"| total | {total / 1e6:.2f} MB | |\n")
print("| Third-party module | Machine code |\n|---|---:|")
for name, size in mods.most_common():
    print(f"| {name} | {size / 1e3:.0f} KB |")

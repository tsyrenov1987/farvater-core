// Command ruip writes the Russian address ranges the switchboard sends around
// the paths (switchboard/ru.go) from a RIPE NCC delegation file:
//
//	curl -O https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest
//	go run ./tools/ruip delegated-ripencc-extended-latest switchboard
//
// Every ipv4/ipv6 block registered to RU (allocated or assigned) is kept,
// overlapping and touching blocks merged. ru4.bin holds big-endian uint32
// pairs [first, last]; ru6.bin holds big-endian uint64 pairs over the top 64
// bits of the address (RIPE delegates nothing longer than /48).
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type span struct{ lo, hi uint64 }

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: ruip <delegated-ripencc-extended-latest> <out dir>")
		os.Exit(2)
	}
	v4, v6, err := read(os.Args[1])
	if err == nil {
		err = write(filepath.Join(os.Args[2], "ru4.bin"), merge(v4), 4)
	}
	if err == nil {
		err = write(filepath.Join(os.Args[2], "ru6.bin"), merge(v6), 8)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "ruip:", err)
		os.Exit(1)
	}
	fmt.Printf("ipv4 %d ranges, ipv6 %d ranges\n", len(merge(v4)), len(merge(v6)))
}

func read(name string) (v4, v6 []span, err error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		r := strings.Split(sc.Text(), "|")
		if len(r) < 7 || r[1] != "RU" || (r[6] != "allocated" && r[6] != "assigned") {
			continue
		}
		a, err := netip.ParseAddr(r[3])
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(r[4], 10, 64)
		if err != nil || n == 0 {
			continue
		}
		switch {
		case r[2] == "ipv4" && a.Is4():
			lo := uint64(binary.BigEndian.Uint32(a.AsSlice()))
			if lo+n-1 > 1<<32-1 {
				return nil, nil, fmt.Errorf("ipv4 %s+%d overflows", r[3], n)
			}
			v4 = append(v4, span{lo, lo + n - 1})
		case r[2] == "ipv6" && a.Is6():
			if n > 64 { // the count is the prefix length
				return nil, nil, fmt.Errorf("ipv6 %s/%d is longer than /64", r[3], n)
			}
			b := a.As16()
			lo := binary.BigEndian.Uint64(b[:8])
			size := uint64(1)<<(64-n) - 1
			v6 = append(v6, span{lo, lo | size})
		}
	}
	return v4, v6, sc.Err()
}

func merge(s []span) []span {
	s = slices.Clone(s)
	slices.SortFunc(s, func(a, b span) int {
		if a.lo < b.lo {
			return -1
		}
		if a.lo > b.lo {
			return 1
		}
		return 0
	})
	var out []span
	for _, x := range s {
		if n := len(out); n > 0 && (x.lo <= out[n-1].hi || x.lo == out[n-1].hi+1) {
			out[n-1].hi = max(out[n-1].hi, x.hi)
			continue
		}
		out = append(out, x)
	}
	return out
}

func write(name string, s []span, width int) error {
	b := make([]byte, 0, len(s)*2*width)
	for _, x := range s {
		if width == 4 {
			b = binary.BigEndian.AppendUint32(b, uint32(x.lo))
			b = binary.BigEndian.AppendUint32(b, uint32(x.hi))
		} else {
			b = binary.BigEndian.AppendUint64(b, x.lo)
			b = binary.BigEndian.AppendUint64(b, x.hi)
		}
	}
	return os.WriteFile(name, b, 0o644)
}

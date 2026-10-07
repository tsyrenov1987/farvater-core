package wire

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// Proxy headers name a destination by its address type and address. Two
// layouts are in use: VLESS, VMess and Mux.Cool write the port first and
// number the types 1 IPv4, 2 domain, 3 IPv6; Trojan follows SOCKS5, the port
// last and the types 1, 3, 4.

const (
	addrIPv4 = iota
	addrDomain
	addrIPv6
)

// addrKind classifies host: an IP literal (an IPv4-mapped IPv6 address counts
// as IPv4) or a domain of at most 255 bytes.
func addrKind(host string) (kind int, ip netip.Addr, err error) {
	if a, perr := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); perr == nil {
		a = a.Unmap().WithZone("")
		if a.Is4() {
			return addrIPv4, a, nil
		}
		return addrIPv6, a, nil
	}
	if host == "" || len(host) > 255 {
		return 0, netip.Addr{}, errors.New("wire: bad destination host " + strconv.Quote(host))
	}
	return addrDomain, netip.Addr{}, nil
}

// appendAddr writes the address part (type, then the address) with the
// given type numbers for IPv4, domain and IPv6.
func appendAddr(b []byte, host string, types [3]byte) ([]byte, error) {
	kind, ip, err := addrKind(host)
	if err != nil {
		return b, err
	}
	b = append(b, types[kind])
	switch kind {
	case addrDomain:
		b = append(b, byte(len(host)))
		return append(b, host...), nil
	default:
		return append(b, ip.AsSlice()...), nil
	}
}

var (
	portFirstTypes = [3]byte{1, 2, 3}
	socksTypes     = [3]byte{1, 3, 4}
)

// appendPortAddr writes a destination as VLESS, VMess and Mux.Cool do.
func appendPortAddr(b []byte, t Target) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, uint16(t.Port))
	return appendAddr(b, t.Host, portFirstTypes)
}

// appendSocksAddr writes a destination as Trojan does.
func appendSocksAddr(b []byte, t Target) ([]byte, error) {
	b, err := appendAddr(b, t.Host, socksTypes)
	if err != nil {
		return b, err
	}
	return binary.BigEndian.AppendUint16(b, uint16(t.Port)), nil
}

// readAddr reads the address part written with the given type numbers.
func readAddr(r io.Reader, types [3]byte) (string, error) {
	var t [1]byte
	if _, err := io.ReadFull(r, t[:]); err != nil {
		return "", err
	}
	var n int
	switch t[0] {
	case types[addrIPv4]:
		n = 4
	case types[addrIPv6]:
		n = 16
	case types[addrDomain]:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", err
		}
		d := make([]byte, l[0])
		if _, err := io.ReadFull(r, d); err != nil {
			return "", err
		}
		return string(d), nil
	default:
		return "", errors.New("wire: unknown address type " + strconv.Itoa(int(t[0])))
	}
	a := make([]byte, n)
	if _, err := io.ReadFull(r, a); err != nil {
		return "", err
	}
	ip, _ := netip.AddrFromSlice(a)
	return ip.Unmap().String(), nil
}

func readPort(r io.Reader) (int, error) {
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(p[:])), nil
}

// readPortAddr reads a destination written as Mux.Cool writes it.
func readPortAddr(r io.Reader) (Target, error) {
	port, err := readPort(r)
	if err != nil {
		return Target{}, err
	}
	host, err := readAddr(r, portFirstTypes)
	return Target{Host: host, Port: port}, err
}

// readSocksAddr reads a destination written as Trojan writes it.
func readSocksAddr(r io.Reader) (Target, error) {
	host, err := readAddr(r, socksTypes)
	if err != nil {
		return Target{}, err
	}
	port, err := readPort(r)
	return Target{Host: host, Port: port}, err
}

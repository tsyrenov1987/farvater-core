package switchboard

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// socksRequest is a parsed SOCKS5 CONNECT.
type socksRequest struct {
	Host string // domain or IP literal
	Port int
}

// readSocks5 negotiates no-auth SOCKS5 and parses a CONNECT request. It does not
// send the success reply; the caller replies after the wire is ready (or fails).
func readSocks5(c net.Conn) (socksRequest, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return socksRequest{}, err
	}
	if hdr[0] != 5 {
		return socksRequest{}, fmt.Errorf("socks: version %d", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return socksRequest{}, err
	}
	if _, err := c.Write([]byte{5, 0}); err != nil {
		return socksRequest{}, err
	}
	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return socksRequest{}, err
	}
	if req[1] != 1 {
		_ = replySocks5(c, 7)
		return socksRequest{}, errors.New("socks: only CONNECT is supported")
	}
	var host string
	switch req[3] {
	case 1:
		var a [4]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return socksRequest{}, err
		}
		host = net.IP(a[:]).String()
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return socksRequest{}, err
		}
		d := make([]byte, int(l[0]))
		if _, err := io.ReadFull(c, d); err != nil {
			return socksRequest{}, err
		}
		host = string(d)
	case 4:
		var a [16]byte
		if _, err := io.ReadFull(c, a[:]); err != nil {
			return socksRequest{}, err
		}
		host = net.IP(a[:]).String()
	default:
		_ = replySocks5(c, 8)
		return socksRequest{}, errors.New("socks: address type")
	}
	var p [2]byte
	if _, err := io.ReadFull(c, p[:]); err != nil {
		return socksRequest{}, err
	}
	return socksRequest{Host: host, Port: int(binary.BigEndian.Uint16(p[:]))}, nil
}

// replySocks5 sends a CONNECT reply with the given status (0 = success).
func replySocks5(c net.Conn, status byte) error {
	_, err := c.Write([]byte{5, status, 0, 1, 0, 0, 0, 0, 0, 0})
	return err
}

func (r socksRequest) String() string { return net.JoinHostPort(r.Host, strconv.Itoa(r.Port)) }

// Package wire holds the transports ("wires"). A wire knows how to carry one
// flow to one server; it contains no selection logic of any kind.
package wire

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Kind is the protocol family of a path.
type Kind string

const (
	KindVLESS     Kind = "vless"
	KindHysteria2 Kind = "hysteria2"
)

// PathSpec is a parsed, provider-neutral description of one path.
type PathSpec struct {
	ID   string
	Kind Kind
	Host string
	Port int

	// VLESS
	UUID        string
	Flow        string // "" or xtls-rprx-vision
	Network     string // tcp | ws | xhttp | grpc
	Security    string // none | tls | reality
	SNI         string
	Fingerprint string
	ALPN        []string
	Insecure    bool
	PublicKey   []byte // reality
	ShortID     []byte // reality
	SpiderX     string // reality
	Path        string // ws / xhttp
	HostHeader  string // ws / xhttp
	Mode        string // xhttp mode: auto | packet-up | stream-up | stream-one
	ServiceName string // grpc
	Authority   string // grpc :authority override

	// Hysteria2
	Auth      string // full userinfo: "user:pass" (userpass mode) or "pass"
	Obfs      string // "" | salamander
	ObfsPass  string
	PinSHA256 string
}

// Rail is the informational label of the path's transport.
func (p PathSpec) Rail() string {
	switch p.Kind {
	case KindHysteria2:
		return "hy2"
	case KindVLESS:
		switch p.Network {
		case "xhttp":
			return "xhttp"
		case "ws":
			return "ws"
		case "grpc":
			return "grpc"
		}
		if p.Security == "reality" {
			return "reality"
		}
		return "tls"
	}
	return string(p.Kind)
}

// ServerSNI is the TLS server name the wire presents (for the handshake governor).
func (p PathSpec) ServerSNI() string {
	if p.SNI != "" {
		return p.SNI
	}
	if p.HostHeader != "" {
		return p.HostHeader
	}
	return p.Host
}

// ParseURI parses a vless:// or hysteria2:// share link.
func ParseURI(raw string) (PathSpec, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return PathSpec{}, err
	}
	q := u.Query()
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return PathSpec{}, fmt.Errorf("host:port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return PathSpec{}, fmt.Errorf("port: %w", err)
	}
	spec := PathSpec{Host: host, Port: port}
	if f, err := url.PathUnescape(u.Fragment); err == nil && f != "" {
		spec.ID = f
	} else {
		spec.ID = u.Host
	}
	switch strings.ToLower(u.Scheme) {
	case "vless":
		spec.Kind = KindVLESS
		if u.User == nil {
			return spec, errors.New("vless: missing uuid")
		}
		spec.UUID = u.User.Username()
		spec.Flow = q.Get("flow")
		spec.Network = strings.ToLower(first(q.Get("type"), "tcp"))
		if spec.Network == "splithttp" {
			spec.Network = "xhttp"
		}
		spec.Security = strings.ToLower(first(q.Get("security"), "none"))
		spec.SNI = q.Get("sni")
		spec.Fingerprint = q.Get("fp")
		if a := q.Get("alpn"); a != "" {
			spec.ALPN = strings.Split(a, ",")
		}
		spec.Insecure = q.Get("allowInsecure") == "1" || q.Get("insecure") == "1"
		if pbk := q.Get("pbk"); pbk != "" {
			b, err := decodeB64(pbk)
			if err != nil {
				return spec, fmt.Errorf("pbk: %w", err)
			}
			spec.PublicKey = b
		}
		if sid := q.Get("sid"); sid != "" {
			b, err := hex.DecodeString(sid)
			if err != nil {
				return spec, fmt.Errorf("sid: %w", err)
			}
			spec.ShortID = b
		}
		spec.SpiderX = first(q.Get("spx"), "/")
		spec.Path = first(q.Get("path"), "/")
		spec.HostHeader = q.Get("host")
		spec.Mode = first(q.Get("mode"), "auto")
		spec.ServiceName = q.Get("serviceName")
		spec.Authority = q.Get("authority")
		if spec.Security == "reality" && (len(spec.PublicKey) == 0 || spec.SNI == "") {
			return spec, errors.New("reality: pbk and sni are required")
		}
		if spec.Security == "none" {
			// VLESS itself does not encrypt; a tunnel that carries traffic in the clear
			// is not one (and Play's VpnService policy requires encryption to the endpoint).
			return spec, errors.New("vless: security=none: a path must be encrypted (tls or reality)")
		}
	case "hysteria2", "hy2":
		// Mirrors the reference client (apernet/hysteria app/v2, cmd/client.go
		// parseURI): the auth string is the whole userinfo, "user:pass" when a
		// password is present — servers in userpass mode reject anything else.
		spec.Kind = KindHysteria2
		if u.User != nil {
			username := u.User.Username()
			if pw, ok := u.User.Password(); ok {
				spec.Auth = username + ":" + pw
			} else {
				spec.Auth = username
			}
		}
		spec.SNI = q.Get("sni")
		if b, err := strconv.ParseBool(q.Get("insecure")); err == nil {
			spec.Insecure = b
		}
		spec.Obfs = strings.ToLower(q.Get("obfs"))
		spec.ObfsPass = q.Get("obfs-password")
		spec.PinSHA256 = q.Get("pinSHA256")
	default:
		return spec, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	return spec, nil
}

func first(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

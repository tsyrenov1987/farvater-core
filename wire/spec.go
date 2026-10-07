// Package wire holds the transports ("wires"). A wire knows how to carry one
// flow to one server; it contains no selection logic of any kind.
package wire

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	KindTrojan    Kind = "trojan"
	KindVMess     Kind = "vmess"
	KindHysteria2 Kind = "hysteria2"
	KindOlcRTC    Kind = "olcrtc"
	KindKilvater  Kind = "kilvater"
)

// PathSpec is a parsed, provider-neutral description of one path.
type PathSpec struct {
	ID   string
	Kind Kind
	Host string
	Port int

	// VLESS, Trojan, VMess
	UUID        string // VLESS, VMess
	Password    string // Trojan
	Cipher      string // VMess body cipher: auto | aes-128-gcm | chacha20-poly1305 | none | zero
	Flow        string // VLESS: "" or xtls-rprx-vision
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

	// olcRTC: TCP through a video call. The app runs the call beside the core
	// (see Hosted) and the core reaches it through the app's loopback door.
	Provider      string // the call service: wbstream | telemost | jitsi
	Transport     string // how bytes ride the call: vp8channel | datachannel | seichannel | videochannel
	TransportOpts string // the transport's parameters, "key=value&key=value" as the link has them
	Room          string
	Key           string // the tunnel's key, 64 hex
}

// Rail is the informational label of the path's transport.
func (p PathSpec) Rail() string {
	switch p.Kind {
	case KindKilvater:
		return "kilvater"
	case KindHysteria2:
		return "hy2"
	case KindVLESS, KindTrojan, KindVMess:
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

// HTTPLike reports whether the path's traffic looks like HTTP(S) to an
// observer: TLS, REALITY, WebSocket, gRPC, XHTTP, or QUIC with no
// obfuscation. Salamander turns Hysteria 2 into noise that resembles nothing;
// olcRTC is a video call (WebRTC).
func (p PathSpec) HTTPLike() bool {
	return !(p.Kind == KindHysteria2 && p.Obfs != "") && p.Kind != KindOlcRTC
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

// ParseURI parses a vless://, trojan://, vmess://, hysteria2:// or olcrtc://
// share link; vmess:// also in v2rayN's form, the base64 of a JSON object.
func ParseURI(raw string) (PathSpec, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 9 && strings.EqualFold(raw[:9], "olcrtc://") {
		return parseOlcRTC(raw[9:])
	}
	if len(raw) > 8 && strings.EqualFold(raw[:8], "vmess://") {
		if b64, name, _ := strings.Cut(raw[8:], "#"); !strings.Contains(b64, "@") {
			if n, err := url.PathUnescape(name); err == nil {
				name = n
			}
			return parseVMessJSON(b64, name)
		}
	}
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
		return spec, parseStream(q, &spec, "none")
	case "trojan":
		// The password is the whole userinfo; Trojan is TLS unless the link says otherwise.
		spec.Kind = KindTrojan
		if u.User == nil {
			return spec, errors.New("trojan: missing password")
		}
		spec.Password = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			spec.Password += ":" + pw
		}
		if q.Get("sni") == "" && q.Get("peer") != "" {
			q.Set("sni", q.Get("peer")) // older clients' name for it
		}
		return spec, parseStream(q, &spec, "tls")
	case "vmess":
		// Xray's share link: the encryption parameter is VMess's own cipher.
		spec.Kind = KindVMess
		if u.User == nil {
			return spec, errors.New("vmess: missing uuid")
		}
		spec.UUID = u.User.Username()
		spec.Cipher = strings.ToLower(first(q.Get("encryption"), "auto"))
		return spec, parseStream(q, &spec, "none")
	case "kilvater":
		spec.Kind = KindKilvater
		if u.User == nil {
			return spec, errors.New("kilvater: missing key")
		}
		spec.Key = u.User.Username()
		spec.SNI = q.Get("sni")
		spec.Fingerprint = first(q.Get("fp"), "chrome")
		spec.Path = first(q.Get("path"), "/connect")
		spec.HostHeader = q.Get("host")
		if spec.SNI == "" {
			spec.SNI = spec.Host
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

// parseStream reads the transport and security of a vless, trojan or vmess
// link, in the query layout of Xray's share links.
func parseStream(q url.Values, spec *PathSpec, security string) error {
	spec.Network = strings.ToLower(first(q.Get("type"), "tcp"))
	if spec.Network == "splithttp" {
		spec.Network = "xhttp"
	}
	spec.Security = strings.ToLower(first(q.Get("security"), security))
	spec.SNI = q.Get("sni")
	spec.Fingerprint = q.Get("fp")
	if a := q.Get("alpn"); a != "" {
		spec.ALPN = strings.Split(a, ",")
	}
	spec.Insecure = q.Get("allowInsecure") == "1" || q.Get("insecure") == "1"
	if pbk := q.Get("pbk"); pbk != "" {
		b, err := decodeB64(pbk)
		if err != nil {
			return fmt.Errorf("pbk: %w", err)
		}
		spec.PublicKey = b
	}
	if sid := q.Get("sid"); sid != "" {
		b, err := hex.DecodeString(sid)
		if err != nil {
			return fmt.Errorf("sid: %w", err)
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
		return errors.New("reality: pbk and sni are required")
	}
	if spec.Security == "none" {
		// VLESS and Trojan do not encrypt by themselves, and Play's VpnService
		// policy requires encryption to the endpoint. VMess does, but bare it
		// looks like no protocol at all, which marks it out: every path here
		// looks like HTTPS.
		return fmt.Errorf("%s: security=none: a path must be encrypted (tls or reality)", spec.Kind)
	}
	return nil
}

// vmessJSON is v2rayN's share format (vmess:// and the base64 of this object).
// Fields match the JSON keys case-insensitively: ps, add, port, id, scy, net,
// type, host, path, tls, sni, alpn, fp, and pbk/sid/spx for REALITY.
type vmessJSON struct {
	PS, Add, ID, Scy, Net, Type, Host, Path, TLS, SNI, ALPN, FP, PBK, SID, SPX string
	Port                                                                       jsonText
}

// jsonText takes a JSON string or number: links write the port both ways.
type jsonText string

func (t *jsonText) UnmarshalJSON(b []byte) error {
	var s string
	if json.Unmarshal(b, &s) == nil {
		*t = jsonText(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*t = jsonText(n.String())
	return nil
}

func parseVMessJSON(b64, name string) (PathSpec, error) {
	raw, err := decodeB64(b64)
	if err != nil {
		return PathSpec{}, fmt.Errorf("vmess: %w", err)
	}
	var j vmessJSON
	if err := json.Unmarshal(raw, &j); err != nil {
		return PathSpec{}, fmt.Errorf("vmess: %w", err)
	}
	port, err := strconv.Atoi(string(j.Port))
	if err != nil {
		return PathSpec{}, fmt.Errorf("vmess port: %w", err)
	}
	q := url.Values{}
	for k, v := range map[string]string{"type": j.Net, "security": j.TLS, "sni": j.SNI, "fp": j.FP, "alpn": j.ALPN,
		"host": j.Host, "path": j.Path, "pbk": j.PBK, "sid": j.SID, "spx": j.SPX} {
		if v != "" {
			q.Set(k, v)
		}
	}
	mode := j.Type != "" && j.Type != "none"
	switch strings.ToLower(j.Net) {
	case "grpc": // v2rayN: path is the service name, host the authority, type the mode
		q.Set("serviceName", j.Path)
		q.Set("authority", j.Host)
		if mode {
			q.Set("mode", j.Type)
		}
	case "xhttp", "splithttp":
		if mode {
			q.Set("mode", j.Type)
		}
	case "", "tcp":
		if mode {
			return PathSpec{}, fmt.Errorf("vmess: tcp header %q is not supported", j.Type)
		}
	}
	spec := PathSpec{ID: first(name, first(j.PS, net.JoinHostPort(j.Add, strconv.Itoa(port)))), Kind: KindVMess,
		Host: j.Add, Port: port, UUID: j.ID, Cipher: strings.ToLower(first(j.Scy, "auto"))}
	return spec, parseStream(q, &spec, "none")
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

// parseOlcRTC reads olcRTC's compact link (its docs/uri.md), the part after
// "olcrtc://": <provider>?<transport>[<key=value&...>]@<room>#<key hex>$<comment>.
// The comment names the path.
func parseOlcRTC(body string) (PathSpec, error) {
	spec := PathSpec{Kind: KindOlcRTC}
	provider, rest, _ := strings.Cut(body, "?")
	transport, rest, _ := strings.Cut(rest, "@")
	if t, opts, ok := strings.Cut(transport, "<"); ok {
		if !strings.HasSuffix(opts, ">") {
			return spec, errors.New("olcrtc: the transport's parameters must end with >")
		}
		transport, spec.TransportOpts = t, strings.TrimSuffix(opts, ">")
	}
	room, rest, _ := strings.Cut(rest, "#")
	key, name, _ := strings.Cut(rest, "$")
	spec.Provider, spec.Transport, spec.Room, spec.Key = strings.ToLower(provider), strings.ToLower(transport), room, key
	if spec.Provider == "" || spec.Transport == "" || spec.Room == "" {
		return spec, errors.New("olcrtc: provider, transport and room are required")
	}
	if b, err := hex.DecodeString(key); err != nil || len(b) != 32 {
		return spec, errors.New("olcrtc: the key must be 64 hex digits")
	}
	if n, err := url.PathUnescape(name); err == nil {
		name = n
	}
	spec.ID = strings.TrimSpace(name)
	if spec.ID == "" {
		spec.ID = spec.Provider + "/" + spec.Room
	}
	return spec, nil
}

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
	"slices"
	"strconv"
	"strings"

	"github.com/tsyrenov1987/farvater-core/kilvater"
)

// Kind is the protocol family of a path.
type Kind string

const (
	KindVLESS       Kind = "vless"
	KindTrojan      Kind = "trojan"
	KindVMess       Kind = "vmess"
	KindHysteria2   Kind = "hysteria2"
	KindOlcRTC      Kind = "olcrtc"
	KindKilvater    Kind = "kilvater"
	KindShadowsocks Kind = "ss"
)

// PathSpec is a parsed, provider-neutral description of one path.
type PathSpec struct {
	ID   string
	Kind Kind
	Host string
	Port int

	// VLESS, Trojan, VMess
	UUID        string // VLESS, VMess
	Password    string // Trojan, Shadowsocks
	Cipher      string // VMess body cipher: auto | aes-128-gcm | chacha20-poly1305 | none | zero; Shadowsocks method
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
	Mode        string // xhttp mode: auto | packet-up | stream-up | stream-one; kilvater: "" | split | split-post
	// SplitExt, set by a kilvater link's "ext=ts", ends every split request's
	// path in a file extension (<sid>/d.ts, <sid>/u/<n>.ts): CDN Timeweb
	// (CDNvideo edges) refuses a path whose last segment has none (403,
	// x-reason-code 7, measured 19.11).
	SplitExt string
	// XQuery, set by the link's "xquery=1", is the CDN shape of xhttp
	// packet-up: the path is a file and stays without a trailing slash, the
	// session and sequence ride the query (sid, page) and the padding is a
	// base62 query value (t). CDN filters drop the default shape (a path
	// ending in "/", 'X' runs in the Referer).
	XQuery bool
	// XQ is the xquery shape's knobs, all from the link, so a new CDN (or a
	// CDN's new filter) is a catalogue change, not an app update. Zero
	// values are the defaults the nodes use today (see xqDefaults).
	XQ          XQuerySpec
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
	Key           string // the tunnel's key, 64 hex (also kilvater)

	// Pad is the kilvater padding mode (off | moderate | heavy), from the
	// link's optional "pad" parameter. Empty means the default (moderate).
	Pad string

	// KeyID is the kilvater v2 key id (16 hex), from the link's optional "kid"
	// parameter. Set, the client sends v2 tags (the server verifies in O(1) by
	// id); empty, it sends v1 tags. The link's key is the derived key.
	KeyID string

	// TURN, set, carries the path's TCP connection through VK's call relays
	// to the node instead of dialing Host:Port (a vkturn:// link; see vkturn.go).
	TURN *TURNSpec

	// Legs are a kilbond:// path's kilvater links, one per route (bond.go).
	Legs []PathSpec
	// Spare, on a bond's leg: a route to spare (see kilvater.JoinSpare).
	Spare bool
}

// XQuerySpec names what the xquery shape puts where and how it pads: the
// request profile. Every knob mirrors an Xray xhttpSettings field, so a new CDN
// (or a CDN's new filter) is a catalogue line plus the node's own settings —
// no app update.
//
//	xsk  session key (default sid)     xqk  sequence key (default page)
//	xpk  padding key (default t; "-" = no padding)
//	xpad padding length in characters, "min-max" (default 200-600)
//	xct  uplink Content-Type (default application/octet-stream)
//	xchunk  largest uplink request in KiB (default 256; 3 when the data
//	        rides headers or cookies: Xray's serverMaxHeaderBytes is 8192
//	        unless the node sets more)
//	xinfl   uplink requests in flight (default 4)
//
// The profile (sessionPlacement, seqPlacement, xPaddingPlacement, ...):
//
//	xsp  session placement: query (default) | path | header | cookie
//	xqp  sequence placement: query (default) | path | header | cookie
//	xpp  padding placement: query (default) | header | queryInHeader | cookie
//	xph  padding header (xPaddingHeader; default X-Padding, Referer for queryInHeader)
//	xpm  padding method: tokenish (default) | repeat-x
//	xum  uplink HTTP method (uplinkHTTPMethod; default POST, GET only with
//	     the data in headers or cookies)
//	xdp  uplink data placement: body (default) | header | cookie
//	xdk  uplink data key (uplinkDataKey; default X-Data, x_data for cookies)
//	xdc  one header's or cookie's share of the data in characters
//	     (uplinkChunkSize; default 3072 for headers, 2048 for cookies)
//	xh   extra request headers, "Name:Value|Name:Value" (headers)
//
// Keys left out follow the placement as Xray's do (X-Session / x_session,
// X-Seq / x_seq, x_padding), except the query defaults the nodes use (sid,
// page, t). A value the core does not know drops the link (ParseURI fails),
// so a profile an older build cannot speak never reaches it half-understood.
type XQuerySpec struct {
	SessionKey  string
	SeqKey      string
	PadKey      string
	PadMin      int
	PadMax      int
	ContentType string
	ChunkKiB    int
	InFlight    int

	SessPlace string
	SeqPlace  string
	PadPlace  string
	PadHeader string
	PadMethod string
	UpMethod  string
	DataPlace string
	DataKey   string
	DataChunk int
	Headers   [][2]string
}

func parseXQuerySpec(q url.Values) (XQuerySpec, error) {
	x := XQuerySpec{SessionKey: q.Get("xsk"), SeqKey: q.Get("xqk"), PadKey: q.Get("xpk"), ContentType: q.Get("xct"),
		SessPlace: q.Get("xsp"), SeqPlace: q.Get("xqp"), PadPlace: q.Get("xpp"), PadHeader: q.Get("xph"),
		PadMethod: q.Get("xpm"), UpMethod: strings.ToUpper(q.Get("xum")), DataPlace: q.Get("xdp"), DataKey: q.Get("xdk")}
	if a, b, ok := strings.Cut(q.Get("xpad"), "-"); ok {
		lo, e1 := strconv.Atoi(a)
		hi, e2 := strconv.Atoi(b)
		if e1 == nil && e2 == nil && lo >= 0 && hi >= lo && hi <= 4000 {
			x.PadMin, x.PadMax = lo, hi
		}
	}
	if n, err := strconv.Atoi(q.Get("xchunk")); err == nil && n >= 1 && n <= 4096 {
		x.ChunkKiB = n
	}
	if n, err := strconv.Atoi(q.Get("xinfl")); err == nil && n >= 1 && n <= 16 {
		x.InFlight = n
	}
	if n, err := strconv.Atoi(q.Get("xdc")); err == nil && n >= 64 && n <= 16384 {
		x.DataChunk = n
	}
	for _, kv := range strings.Split(q.Get("xh"), "|") {
		if kv == "" {
			continue
		}
		k, v, ok := strings.Cut(kv, ":")
		k = strings.TrimSpace(k)
		if !ok || k == "" || strings.EqualFold(k, "host") || strings.ContainsAny(k, " :\r\n") || strings.ContainsAny(v, "\r\n") {
			return x, errors.New("xquery: bad header " + kv)
		}
		x.Headers = append(x.Headers, [2]string{k, strings.TrimSpace(v)})
	}
	return x, x.check()
}

// check refuses a profile value this core does not know.
func (x XQuerySpec) check() error {
	in := func(v string, ok ...string) bool { return v == "" || slices.Contains(ok, v) }
	switch {
	case !in(x.SessPlace, "query", "path", "header", "cookie"):
		return errors.New("xquery: xsp " + x.SessPlace)
	case !in(x.SeqPlace, "query", "path", "header", "cookie"):
		return errors.New("xquery: xqp " + x.SeqPlace)
	case !in(x.PadPlace, "query", "header", "queryInHeader", "cookie"):
		return errors.New("xquery: xpp " + x.PadPlace)
	case !in(x.PadMethod, "tokenish", "repeat-x"):
		return errors.New("xquery: xpm " + x.PadMethod)
	case !in(x.UpMethod, "POST", "PUT", "PATCH", "GET"):
		return errors.New("xquery: xum " + x.UpMethod)
	case !in(x.DataPlace, "body", "header", "cookie"):
		return errors.New("xquery: xdp " + x.DataPlace)
	case x.UpMethod == "GET" && (x.DataPlace == "" || x.DataPlace == "body"):
		return errors.New("xquery: a GET uplink needs xdp header or cookie")
	}
	return nil
}

// Rail is the informational label of the path's transport.
func (p PathSpec) Rail() string {
	if p.Kind == KindBond {
		return "kilbond"
	}
	if p.TURN != nil {
		return "vkturn"
	}
	switch p.Kind {
	case KindKilvater:
		return "kilvater"
	case KindHysteria2:
		return "hy2"
	case KindShadowsocks:
		return "ss"
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
// olcRTC is a video call (WebRTC), and so is a path over VK's call relays.
func (p PathSpec) HTTPLike() bool {
	return !(p.Kind == KindHysteria2 && p.Obfs != "") && p.Kind != KindOlcRTC && p.Kind != KindShadowsocks && p.TURN == nil && p.Kind != KindBond
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

// ParseURI parses a vless://, trojan://, vmess://, hysteria2://, olcrtc:// or vkturn://
// share link; vmess:// also in v2rayN's form, the base64 of a JSON object.
func ParseURI(raw string) (PathSpec, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) > 9 && strings.EqualFold(raw[:9], "olcrtc://") {
		return parseOlcRTC(raw[9:])
	}
	if len(raw) > 10 && strings.EqualFold(raw[:10], "kilbond://") {
		return parseBond(raw)
	}
	if len(raw) > 9 && strings.EqualFold(raw[:9], "vkturn://") {
		return parseVKTurn(raw)
	}
	if len(raw) > 5 && strings.EqualFold(raw[:5], "ss://") {
		return parseShadowsocks(raw[5:])
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
		if q.Get("insecure") == "1" || q.Get("allowInsecure") == "1" {
			return spec, errors.New("kilvater: insecure certificates are not allowed")
		}
		spec.Key = u.User.Username()
		spec.SNI = q.Get("sni")
		spec.Fingerprint = first(kilvaterProfile(q.Get("fpc")), first(q.Get("fp"), "chrome"))
		spec.Pad = q.Get("pad")
		spec.KeyID = q.Get("kid")
		spec.Path = u.Path
		if spec.Path == "" || spec.Path == "/" {
			spec.Path = "/connect"
		}
		spec.HostHeader = q.Get("host")
		// mode=split carries each flow as separate requests, for a CDN that
		// will not stream a request body: split-post sends the uplink in POST
		// bodies, split in GET headers (kilvater_split.go).
		switch m := q.Get("mode"); m {
		case "", "split", "split-post":
			spec.Mode = m
		default:
			return spec, errors.New("kilvater: unknown mode " + m)
		}
		if e := q.Get("ext"); e != "" {
			if !kilvater.SplitExtOK(e) {
				return spec, errors.New("kilvater: bad ext " + e)
			}
			spec.SplitExt = "." + e
		}
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
	spec.XQuery = q.Get("xquery") == "1"
	if spec.XQuery {
		x, err := parseXQuerySpec(q)
		if err != nil {
			return err
		}
		spec.XQ = x
	}
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

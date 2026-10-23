package catalogue

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tsyrenov1987/farvater-core/wire"
)

const pbk = "cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk"
const uid = "11111111-2222-3333-4444-555555555555"

// Mihomo's own field names (wiki.metacubex.one, proxies/*).
const clashBody = `mixed-port: 7890
proxies:
  - name: "NL reality"
    type: vless
    server: 203.0.113.10
    port: 443
    uuid: ` + uid + `
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.example.com
    client-fingerprint: chrome
    reality-opts:
      public-key: ` + pbk + `
      short-id: "0123"
  - name: ws vmess
    type: vmess
    server: vm.example.com
    port: 8443
    uuid: ` + uid + `
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: cdn.example.com
  - name: grpc trojan
    type: trojan
    server: tr.example.com
    port: 443
    password: "p@ss:w"
    network: grpc
    sni: tr.example.com
    grpc-opts:
      grpc-service-name: svc
  - name: hy
    type: hysteria2
    server: 203.0.113.11
    port: 8443
    password: hp
    sni: www.example.com
    obfs: salamander
    obfs-password: x
  - name: ss
    type: ss
    server: 203.0.113.12
    port: 8388
    cipher: aes-128-gcm
    password: s
proxy-groups:
  - name: auto
    type: url-test
    proxies: [NL reality]
`

func TestParseClashYAML(t *testing.T) {
	c, err := Parse([]byte(clashBody))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) != 5 {
		t.Fatalf("want 5 paths, got %d: %+v", len(c.Paths), c.Paths)
	}
	if ss := c.Paths[4].Spec; ss.Kind != wire.KindShadowsocks || ss.Cipher != "aes-128-gcm" || ss.Password != "s" || ss.Port != 8388 {
		t.Fatalf("ss: %+v", ss)
	}
	r, v, tr, hy := c.Paths[0].Spec, c.Paths[1].Spec, c.Paths[2].Spec, c.Paths[3].Spec
	if r.ID != "NL reality" || r.Security != "reality" || r.SNI != "www.example.com" || len(r.PublicKey) != 32 || r.Flow != "xtls-rprx-vision" || r.Fingerprint != "chrome" {
		t.Fatalf("reality: %+v", r)
	}
	if v.Kind != wire.KindVMess || v.Network != "ws" || v.Path != "/ray" || v.HostHeader != "cdn.example.com" || v.Security != "tls" {
		t.Fatalf("vmess: %+v", v)
	}
	if tr.Kind != wire.KindTrojan || tr.Password != "p@ss:w" || tr.Network != "grpc" || tr.ServiceName != "svc" {
		t.Fatalf("trojan: %+v", tr)
	}
	if hy.Kind != wire.KindHysteria2 || hy.Auth != "hp" || hy.Obfs != "salamander" || !c.Paths[3].Labels.UDP {
		t.Fatalf("hy2: %+v", hy)
	}
}

func TestParseBase64ClashYAML(t *testing.T) {
	c, err := Parse([]byte(base64.StdEncoding.EncodeToString([]byte(clashBody))))
	if err != nil || len(c.Paths) != 5 {
		t.Fatal(err, c)
	}
}

// sing-box's documented outbound fields (sing-box.sagernet.org/configuration/outbound).
const singBody = `{
  "log": {"level": "warn"},
  "outbounds": [
    {"type": "selector", "tag": "proxy", "outbounds": ["a", "b"]},
    {"type": "vless", "tag": "a", "server": "203.0.113.10", "server_port": 443, "uuid": "` + uid + `",
     "flow": "xtls-rprx-vision",
     "tls": {"enabled": true, "server_name": "www.example.com", "utls": {"enabled": true, "fingerprint": "chrome"},
             "reality": {"enabled": true, "public_key": "` + pbk + `", "short_id": "0123"}}},
    {"type": "trojan", "tag": "b", "server": "tr.example.com", "server_port": 443, "password": "pw",
     "tls": {"enabled": true, "server_name": "tr.example.com"},
     "transport": {"type": "ws", "path": "/t", "headers": {"Host": "cdn.example.com"}}},
    {"type": "hysteria2", "tag": "c", "server": "203.0.113.11", "server_port": 8443, "password": "hp",
     "tls": {"enabled": true, "server_name": "www.example.com"}},
    {"type": "shadowsocks", "tag": "d", "server": "203.0.113.12", "server_port": 8388, "method": "aes-128-gcm", "password": "s"},
    {"type": "direct", "tag": "direct"}
  ]
}`

func TestParseSingBoxJSON(t *testing.T) {
	c, err := Parse([]byte(singBody))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) != 4 {
		t.Fatalf("want 4, got %+v", c.Paths)
	}
	a, b, hy := c.Paths[0].Spec, c.Paths[1].Spec, c.Paths[2].Spec
	if ss := c.Paths[3].Spec; ss.ID != "d" || ss.Kind != wire.KindShadowsocks || ss.Cipher != "aes-128-gcm" {
		t.Fatalf("ss: %+v", ss)
	}
	if a.ID != "a" || a.Security != "reality" || len(a.ShortID) != 2 || a.Port != 443 {
		t.Fatalf("a: %+v", a)
	}
	if b.Kind != wire.KindTrojan || b.Network != "ws" || b.HostHeader != "cdn.example.com" || b.SNI != "tr.example.com" {
		t.Fatalf("b: %+v", b)
	}
	if hy.Kind != wire.KindHysteria2 || hy.SNI != "www.example.com" {
		t.Fatalf("hy: %+v", hy)
	}
}

// An array of whole Xray configs, one per server, as Remnawave's XRAY_JSON
// and Happ's JSON subscriptions serve; the second uses newer Xray's flat
// settings and xhttp.
const xrayBody = `[
  {"remarks": "🇳🇱 NL", "outbounds": [
    {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [{"address": "203.0.113.10", "port": 443,
      "users": [{"id": "` + uid + `", "flow": "xtls-rprx-vision", "encryption": "none"}]}]},
     "streamSettings": {"network": "tcp", "security": "reality",
      "realitySettings": {"serverName": "www.example.com", "fingerprint": "chrome", "publicKey": "` + pbk + `", "shortId": "0123", "spiderX": "/"}}},
    {"tag": "direct", "protocol": "freedom"},
    {"tag": "block", "protocol": "blackhole"}]},
  {"remarks": "DE xhttp", "outbounds": [
    {"tag": "proxy", "protocol": "vless", "settings": {"address": "de.example.com", "port": 443, "id": "` + uid + `", "encryption": "none"},
     "streamSettings": {"network": "xhttp", "security": "tls", "tlsSettings": {"serverName": "de.example.com", "alpn": ["h2"]},
      "xhttpSettings": {"path": "/x", "mode": "packet-up"}}}]},
  {"remarks": "trojan", "outbounds": [
    {"protocol": "trojan", "settings": {"servers": [{"address": "tr.example.com", "port": 443, "password": "pw"}]},
     "streamSettings": {"network": "grpc", "security": "tls", "grpcSettings": {"serviceName": "g"}}}]}
]`

func TestParseXrayJSON(t *testing.T) {
	c, err := Parse([]byte(xrayBody))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Paths) != 3 {
		t.Fatalf("want 3, got %+v", c.Paths)
	}
	nl, de, tr := c.Paths[0].Spec, c.Paths[1].Spec, c.Paths[2].Spec
	if nl.ID != "🇳🇱 NL" || nl.Security != "reality" || nl.Flow != "xtls-rprx-vision" {
		t.Fatalf("nl: %+v", nl)
	}
	if de.Host != "de.example.com" || de.Network != "xhttp" || de.Mode != "packet-up" || de.Path != "/x" || strings.Join(de.ALPN, ",") != "h2" {
		t.Fatalf("de: %+v", de)
	}
	if tr.Kind != wire.KindTrojan || tr.ServiceName != "g" {
		t.Fatalf("tr: %+v", tr)
	}
	// A single config object, not an array, is read the same way.
	one := xrayBody[strings.Index(xrayBody, "{") : strings.Index(xrayBody, `{"remarks": "DE`)-4]
	if c, err := Parse([]byte(one)); err != nil || len(c.Paths) != 1 {
		t.Fatal(err, one)
	}
}

// SIP008, Outline's and shadowsocks' JSON; a server with a plugin is left out.
func TestParseSIP008(t *testing.T) {
	c, err := Parse([]byte(`{"version":1,"servers":[
	  {"id":"1","remarks":"NL","server":"203.0.113.12","server_port":8388,"method":"aes-256-gcm","password":"s"},
	  {"server":"203.0.113.13","server_port":8388,"method":"aes-256-gcm","password":"s","plugin":"v2ray-plugin"}]}`))
	if err != nil || len(c.Paths) != 1 || c.Paths[0].Spec.ID != "NL" || c.Paths[0].Spec.Cipher != "aes-256-gcm" {
		t.Fatal(err, c)
	}
}

func TestParseRejectsJSONItCannotRead(t *testing.T) {
	for _, body := range []string{
		`{"hello":"world"}`,
		`<html><body>Subscription</body></html>`,
	} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Fatalf("parsed %q", body)
		}
	}
}

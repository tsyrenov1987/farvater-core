package wire

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseVLESSReality(t *testing.T) {
	s, err := ParseURI("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:33443?security=reality&encryption=none&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&fp=firefox&sni=www.example.com&sid=0123abcd&spx=%2F&flow=xtls-rprx-vision&type=tcp#p-reality-1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != KindVLESS || s.Security != "reality" || s.Flow != "xtls-rprx-vision" || s.Rail() != "reality" || s.ID != "p-reality-1" {
		t.Fatalf("bad spec: %+v", s)
	}
	if len(s.PublicKey) != 32 || len(s.ShortID) != 4 || s.Fingerprint != "firefox" || s.ServerSNI() != "www.example.com" {
		t.Fatalf("bad reality fields: %+v", s)
	}
}

func TestParseXHTTPAndWS(t *testing.T) {
	s, err := ParseURI("vless://11111111-2222-3333-4444-555555555555@203.0.113.10:2053?security=reality&encryption=none&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&sni=www.example.com&type=xhttp&path=%2Fabc&mode=stream-one#x")
	if err != nil || s.Network != "xhttp" || s.Path != "/abc" || s.Mode != "stream-one" || s.Rail() != "xhttp" {
		t.Fatalf("xhttp: %v %+v", err, s)
	}
	w, err := ParseURI("vless://11111111-2222-3333-4444-555555555555@cdn.example.net:443?encryption=none&security=tls&type=ws&host=cdn.example.net&path=%2Fws&sni=cdn.example.net#w")
	if err != nil || w.Network != "ws" || w.Security != "tls" || w.Rail() != "ws" || w.HostHeader != "cdn.example.net" {
		t.Fatalf("ws: %v %+v", err, w)
	}
}

func TestPlaintextVLESSIsRefused(t *testing.T) {
	// Traffic to a path must be encrypted, and Play's VpnService policy requires it:
	// security=none, or no security at all, is plain VLESS on the wire.
	for _, raw := range []string{
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:80?security=none&type=ws&path=%2Fws#plain",
		"vless://11111111-2222-3333-4444-555555555555@203.0.113.10:80?type=tcp#bare",
	} {
		if s, err := ParseURI(raw); err == nil {
			t.Fatalf("plaintext path accepted: %+v", s)
		}
	}
}

func TestParseAndBuildGRPC(t *testing.T) {
	s, err := ParseURI("vless://11111111-2222-3333-4444-555555555555@203.0.113.12:443?security=reality&encryption=none&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&fp=firefox&type=grpc&mode=gun&sni=www.example.com&sid=0123#g")
	if err != nil || s.Network != "grpc" || s.Rail() != "grpc" {
		t.Fatalf("grpc parse: %v %+v", err, s)
	}
	if _, err := Build(s); err != nil {
		t.Fatalf("grpc wire must build: %v", err)
	}
}

func TestParseHysteria2(t *testing.T) {
	// userpass mode: the auth string is the whole userinfo.
	s, err := ParseURI("hysteria2://alice:s3cret@203.0.113.11:8443?sni=www.example.com&insecure=1&obfs=Salamander&obfs-password=secret#h")
	if err != nil || s.Kind != KindHysteria2 || s.Auth != "alice:s3cret" || s.Obfs != "salamander" || s.ObfsPass != "secret" || !s.Insecure || s.Rail() != "hy2" {
		t.Fatalf("hy2 userpass: %v %+v", err, s)
	}
	// password mode: no colon, the username is the password.
	p, err := ParseURI("hysteria2://onlypass@203.0.113.11:8443?insecure=true#p")
	if err != nil || p.Auth != "onlypass" || !p.Insecure {
		t.Fatalf("hy2 password: %v %+v", err, p)
	}
}

func TestHysteriaPinFailsClosed(t *testing.T) {
	if got := normalizePin("AB:CD-ef"); got != "abcdef" {
		t.Fatalf("normalizePin = %q", got)
	}
	w, err := newHysteria(PathSpec{Kind: KindHysteria2, Host: "203.0.113.11", Port: 8443, Auth: "a:b", PinSHA256: "not-a-real-pin"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := w.config()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSConfig.VerifyPeerCertificate == nil {
		t.Fatal("a malformed pin must still be enforced, not dropped")
	}
	if cfg.TLSConfig.VerifyPeerCertificate([][]byte{[]byte("some cert")}, nil) == nil {
		t.Fatal("a non-matching pin must fail the handshake")
	}
}

// Salamander turns Hysteria 2 into noise that looks like no HTTP; without it
// Hysteria 2 is QUIC, as HTTP/3 is, and every VLESS transport is TLS-shaped.
func TestHTTPLike(t *testing.T) {
	for raw, want := range map[string]bool{
		"hysteria2://pw@203.0.113.11:8443?sni=www.example.com&obfs=salamander&obfs-password=x#s":                                                                      false,
		"hysteria2://pw@203.0.113.11:443?sni=www.example.com#q":                                                                                                       true,
		"vless://11111111-2222-3333-4444-555555555555@cdn.example.net:443?encryption=none&security=tls&type=ws&host=cdn.example.net&path=%2Fws&sni=cdn.example.net#w": true,
		"olcrtc://wbstream?vp8channel@room-1#" + testOlcKey + "$o":                                                                                                    false,
	} {
		s, err := ParseURI(raw)
		if err != nil {
			t.Fatal(err)
		}
		if got := s.HTTPLike(); got != want {
			t.Errorf("%s: HTTPLike = %v, want %v", s.ID, got, want)
		}
	}
}

func TestParseTrojan(t *testing.T) {
	// The password is the whole userinfo; with no security given, Trojan is TLS.
	s, err := ParseURI("trojan://p%40ss@203.0.113.13:443?peer=www.example.com&type=ws&path=%2Ft&host=cdn.example.net#tr")
	if err != nil || s.Kind != KindTrojan || s.Password != "p@ss" || s.Security != "tls" || s.SNI != "www.example.com" ||
		s.Network != "ws" || s.Path != "/t" || s.HostHeader != "cdn.example.net" || s.Rail() != "ws" || s.ID != "tr" {
		t.Fatalf("trojan ws: %v %+v", err, s)
	}
	r, err := ParseURI("trojan://pw@203.0.113.13:443?security=reality&pbk=cV6nKp-RGtPLOht6cg1Up0Tos0qaw8nITDsJCxOKvQk&fp=firefox&sni=www.example.com&sid=0123#r")
	if err != nil || r.Security != "reality" || r.Rail() != "reality" {
		t.Fatalf("trojan reality: %v %+v", err, r)
	}
	if _, err := Build(r); err != nil {
		t.Fatalf("trojan wire must build: %v", err)
	}
}

func TestParseVMess(t *testing.T) {
	// v2rayN's form: gRPC keeps the service name in path, the authority in host
	// and the mode in type; the port may be a number.
	js := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm 1","add":"203.0.113.14","port":443,"id":"11111111-2222-3333-4444-555555555555","aid":"0","scy":"chacha20-poly1305","net":"grpc","type":"multi","host":"auth.example.com","path":"svc","tls":"tls","sni":"www.example.com"}`))
	s, err := ParseURI("vmess://" + js)
	if err != nil || s.Kind != KindVMess || s.ID != "vm 1" || s.Host != "203.0.113.14" || s.Port != 443 ||
		s.UUID != "11111111-2222-3333-4444-555555555555" || s.Cipher != "chacha20-poly1305" || s.Network != "grpc" ||
		s.ServiceName != "svc" || s.Authority != "auth.example.com" || s.Mode != "multi" || s.Security != "tls" || s.SNI != "www.example.com" {
		t.Fatalf("vmess json: %v %+v", err, s)
	}
	if _, err := Build(s); err != nil {
		t.Fatalf("vmess wire must build: %v", err)
	}
	if n, err := ParseURI("vmess://" + js + "#renamed"); err != nil || n.ID != "renamed" {
		t.Fatalf("vmess json with a name: %v %+v", err, n)
	}
	u, err := ParseURI("vmess://11111111-2222-3333-4444-555555555555@203.0.113.14:8443?security=tls&type=ws&path=%2Fv&sni=www.example.com#u")
	if err != nil || u.Kind != KindVMess || u.Cipher != "auto" || u.Network != "ws" || u.Rail() != "ws" || u.ID != "u" {
		t.Fatalf("vmess url: %v %+v", err, u)
	}
}

// Every path looks like HTTPS: no Trojan in the clear, no VMess without TLS or
// REALITY, and no TCP header disguise, which this core cannot speak.
func TestTrojanAndVMessMustLookLikeHTTPS(t *testing.T) {
	bare := base64.StdEncoding.EncodeToString([]byte(`{"add":"203.0.113.14","port":"80","id":"11111111-2222-3333-4444-555555555555","net":"ws","path":"/v"}`))
	header := base64.StdEncoding.EncodeToString([]byte(`{"add":"203.0.113.14","port":"443","id":"11111111-2222-3333-4444-555555555555","net":"tcp","type":"http","tls":"tls"}`))
	for _, raw := range []string{
		"trojan://pw@203.0.113.13:80?security=none&type=ws#bare",
		"vmess://11111111-2222-3333-4444-555555555555@203.0.113.14:80?type=ws#bare",
		"vmess://" + bare,
		"vmess://" + header,
	} {
		if s, err := ParseURI(raw); err == nil {
			t.Fatalf("accepted %+v", s)
		}
	}
}

const testOlcKey = "d823fa01cb3e0609b67322f7cf984c4ee2e4ce2e294936fc24ef38c9e59f4799"

// olcRTC's compact link: provider?transport[<params>]@room#key$comment.
func TestParseOlcRTC(t *testing.T) {
	s, err := ParseURI("olcrtc://WBStream?vp8channel<vp8-fps=25&vp8-batch=4>@room-01#" + testOlcKey + "$RU%20%2F%20wb%201")
	if err != nil || s.Kind != KindOlcRTC || s.Provider != "wbstream" || s.Transport != "vp8channel" ||
		s.TransportOpts != "vp8-fps=25&vp8-batch=4" || s.Room != "room-01" || s.Key != testOlcKey || s.ID != "RU / wb 1" ||
		s.Rail() != "olcrtc" || s.Host != "" || s.Port != 0 {
		t.Fatalf("olcrtc: %v %+v", err, s)
	}
	// No parameters, a comment with spaces as written, none at all.
	if s, err = ParseURI("olcrtc://telemost?datachannel@r#" + testOlcKey + "$RU / olc free sub"); err != nil || s.TransportOpts != "" || s.ID != "RU / olc free sub" {
		t.Fatalf("plain comment: %v %+v", err, s)
	}
	if s, err = ParseURI("olcrtc://wbstream?vp8channel@r2#" + testOlcKey); err != nil || s.ID != "wbstream/r2" {
		t.Fatalf("no comment: %v %+v", err, s)
	}
	for _, bad := range []string{
		"olcrtc://wbstream?vp8channel@r#" + testOlcKey[:62] + "$short key",
		"olcrtc://wbstream?vp8channel@r#" + strings.Repeat("zz", 32) + "$not hex",
		"olcrtc://wbstream?vp8channel@#" + testOlcKey + "$no room",
		"olcrtc://wbstream@r#" + testOlcKey + "$no transport",
		"olcrtc://?vp8channel@r#" + testOlcKey + "$no provider",
		"olcrtc://wbstream?vp8channel<vp8-fps=25@r#" + testOlcKey + "$open parameters",
	} {
		if s, err := ParseURI(bad); err == nil {
			t.Errorf("%s parsed: %+v", bad, s)
		}
	}
}

func TestParseKilvater(t *testing.T) {
	s, err := ParseURI("kilvater://" + testOlcKey + "@node.example.com:443/connect?sni=www.example.com&fp=chrome&host=www.example.com")
	if err != nil || s.Kind != KindKilvater || s.Key != testOlcKey || s.Host != "node.example.com" || s.Port != 443 ||
		s.Path != "/connect" || s.SNI != "www.example.com" || s.Fingerprint != "chrome" || s.HostHeader != "www.example.com" ||
		s.Rail() != "kilvater" || !s.HTTPLike() {
		t.Fatalf("kilvater: %v %+v", err, s)
	}
	// The link's URL path is honoured, not dropped for the default.
	if s, err = ParseURI("kilvater://" + testOlcKey + "@n:443/secret?sni=x"); err != nil || s.Path != "/secret" {
		t.Fatalf("path from url: %v %+v", err, s)
	}
	// SNI falls back to the host; path falls back to /connect.
	if s, err = ParseURI("kilvater://" + testOlcKey + "@n:8443"); err != nil || s.SNI != "n" || s.Path != "/connect" {
		t.Fatalf("defaults: %v %+v", err, s)
	}
	// Insecure is refused outright; a missing key too.
	for _, bad := range []string{
		"kilvater://" + testOlcKey + "@n:443/connect?insecure=1",
		"kilvater://" + testOlcKey + "@n:443/connect?allowInsecure=1",
		"kilvater://n:443/connect",
	} {
		if s, err := ParseURI(bad); err == nil {
			t.Errorf("%s parsed: %+v", bad, s)
		}
	}
}

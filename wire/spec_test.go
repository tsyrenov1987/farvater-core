package wire

import (
	"encoding/base64"
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

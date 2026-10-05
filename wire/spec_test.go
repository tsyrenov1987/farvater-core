package wire

import "testing"

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

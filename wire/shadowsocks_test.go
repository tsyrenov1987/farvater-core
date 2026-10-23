package wire

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestParseShadowsocks(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:p@ss:w"))
	old := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@203.0.113.5:8388"))
	for raw, want := range map[string]PathSpec{
		"ss://" + ui + "@203.0.113.5:8388#%F0%9F%87%B3%F0%9F%87%B1%20NL": {Kind: KindShadowsocks, ID: "🇳🇱 NL", Host: "203.0.113.5", Port: 8388, Cipher: "chacha20-ietf-poly1305", Password: "p@ss:w"},
		"ss://aes-128-gcm:a%2Fb@[2001:db8::1]:443/?outline=1#x":          {Kind: KindShadowsocks, ID: "x", Host: "2001:db8::1", Port: 443, Cipher: "aes-128-gcm", Password: "a/b"},
		"ss://" + old + "#old": {Kind: KindShadowsocks, ID: "old", Host: "203.0.113.5", Port: 8388, Cipher: "aes-256-gcm", Password: "pw"},
	} {
		got, err := ParseURI(raw)
		if err != nil || got.Kind != want.Kind || got.ID != want.ID || got.Host != want.Host || got.Port != want.Port || got.Cipher != want.Cipher || got.Password != want.Password {
			t.Fatalf("%s: %+v %v", raw, got, err)
		}
	}
	for _, raw := range []string{
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("rc4-md5:x")) + "@h:1",
		"ss://2022-blake3-aes-128-gcm:a2V5@h:1",
		"ss://" + ui + "@h:1?plugin=obfs-local%3Bobfs%3Dhttp",
	} {
		if _, err := ParseURI(raw); err == nil {
			t.Fatalf("parsed %s", raw)
		}
	}
}

// TestShadowsocksAgainstSingBox runs each method against a sing-box server
// (an independent implementation) when sing-box is installed.
func TestShadowsocksAgainstSingBox(t *testing.T) {
	bin, err := exec.LookPath("sing-box")
	if err != nil {
		t.Skip("sing-box not installed")
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	for i, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"} {
		port := 47100 + i
		cfg := fmt.Sprintf(`{"log":{"level":"error"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,"method":%q,"password":"pw-%d"}],"outbounds":[{"type":"direct"}]}`, port, method, i)
		p := filepath.Join(t.TempDir(), "c.json")
		os.WriteFile(p, []byte(cfg), 0o600)
		cmd := exec.Command(bin, "run", "-c", p)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		defer cmd.Process.Kill()
		for j := 0; j < 50; j++ {
			if c, err := net.Dial("tcp", fmt.Sprint("127.0.0.1:", port)); err == nil {
				c.Close()
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		w, err := Build(PathSpec{Kind: KindShadowsocks, ID: method, Host: "127.0.0.1", Port: port, Cipher: method, Password: fmt.Sprint("pw-", i)})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		sess, err := w.Dial(ctx)
		if err != nil {
			t.Fatal(err)
		}
		big := bytes.Repeat([]byte("0123456789abcdef"), 5000) // more than one chunk
		up := make(chan []byte, 1)
		up <- big
		close(up)
		var down bytes.Buffer
		sess.Run(ctx, Target{Host: "127.0.0.1", Port: echo.Addr().(*net.TCPAddr).Port}, []byte("hello "), up, &down, nopMeter{})
		cancel()
		if want := append([]byte("hello "), big...); !bytes.Equal(down.Bytes(), want) {
			t.Fatalf("%s: got %d bytes, want %d", method, down.Len(), len(want))
		}
	}
}

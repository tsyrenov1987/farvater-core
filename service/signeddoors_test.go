package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func signedBlob(t *testing.T, k *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	h := sha256.Sum256([]byte(payload))
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func TestVerifyDoors(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	at := func(d time.Duration) string { return strconv.FormatInt(now.Add(d).Unix(), 10) }
	list := "https://a.example,https://b.example/, http://c.example,https://a.example,https://d.example/x,https://u@e.example"
	good := signedBlob(t, k, "v1|"+list+"|"+at(-time.Hour))
	if got := strings.Join(verifyDoors(good, &k.PublicKey, now), " "); got != "https://a.example https://b.example" {
		t.Fatalf("doors %q", got)
	}
	// The resolver splits a long record and may keep the padding.
	if verifyDoors(strings.Replace(good, ".", "==.", 1), &k.PublicKey, now) == nil {
		t.Fatal("padding refused")
	}
	p, s, _ := strings.Cut(good, ".")
	tampered := base64.RawURLEncoding.EncodeToString([]byte("v1|https://evil.example|"+at(0))) + "." + s
	for name, blob := range map[string]string{
		"other key": signedBlob(t, other, "v1|"+list+"|"+at(0)),
		"tampered":  tampered,
		"stale":     signedBlob(t, k, "v1|"+list+"|"+at(-91*24*time.Hour)),
		"ahead":     signedBlob(t, k, "v1|"+list+"|"+at(48*time.Hour)),
		"version":   signedBlob(t, k, "v2|"+list+"|"+at(0)),
		"no sig":    p,
		"empty":     "",
	} {
		if d := verifyDoors(blob, &k.PublicKey, now); d != nil {
			t.Errorf("%s: %v", name, d)
		}
	}
}

// FARVATER_DOORS holds the DoorSpec a release is built with: the build checks
// it before it goes into the binary.
func TestDoorSpecOfThisBuild(t *testing.T) {
	spec := os.Getenv("FARVATER_DOORS")
	if spec == "" {
		t.Skip("FARVATER_DOORS")
	}
	setDoors(spec)
	t.Cleanup(func() { setDoors(testDoors) })
	if len(plainDoors) == 0 || len(serviceHosts) == 0 || signedName == "" {
		t.Fatalf("doors %d, hosts %d, txt %q", len(plainDoors), len(serviceHosts), signedName)
	}
	for i, d := range plainDoors {
		if u, err := url.Parse(d); err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "/api" {
			t.Errorf("door %d is not https://host/api", i+1)
		}
	}
	der, err := base64.StdEncoding.DecodeString(signedKey)
	if err != nil {
		t.Fatal(err)
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if pub, ok := k.(*ecdsa.PublicKey); err != nil || !ok || pub.Curve != elliptic.P256() {
		t.Fatalf("%T %v", k, err)
	}
}

func TestNoDoorSpec(t *testing.T) {
	setDoors("")
	t.Cleanup(func() { setDoors(testDoors) })
	got := mirrors("https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB")
	if strings.Join(got, " ") != "https://myorden.ru/hsub/ORDEN-AAAAA-BBBBB https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB" {
		t.Fatalf("%v", got)
	}
	if _, err := Source("https://service.example/sub/abc"); err == nil {
		t.Fatal("a name the build was not given is not Orden's")
	}
	if isDoor("https://door-a.example/api/hsub/x") || SignedDoors() != nil {
		t.Fatal("no doors without a spec")
	}
}

func TestSignedMirrors(t *testing.T) {
	tried := mirrors("https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB")
	list := func() []string {
		return []string{"https://door-b.example", "https://n.example", "https://N.example", "https://service.example"}
	}
	got := signedMirrors("https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB", list, tried)
	if strings.Join(got, " ") != "https://n.example/api/hsub/ORDEN-AAAAA-BBBBB" {
		t.Fatalf("%v", got)
	}
	// Another provider's link never makes the app look Orden's list up.
	asked := false
	if got := signedMirrors("https://example.com/hsub/x", func() []string { asked = true; return list() }, nil); got != nil || asked {
		t.Fatalf("not Orden's: %v asked=%v", got, asked)
	}
}

func TestSignedDoorsFailingKeepTheBuiltInError(t *testing.T) {
	w := newWorld(t)
	w.fetch = func(u string) error {
		if strings.HasPrefix(u, "https://n.example/") {
			return errors.New("catalogue: HTTP 404")
		}
		return errors.New("timeout")
	}
	h := w.hooks()
	h.Doors = func() []string { return []string{"https://n.example"} }
	s := New(t.TempDir(), h, t.Logf)
	_, err := s.fetch(t.Context(), "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB")
	if err == nil || err.Error() != "timeout" {
		t.Fatalf("%v", err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if n := len(w.fetched); n != 6 || w.fetched[5] != "https://n.example/api/hsub/ORDEN-AAAAA-BBBBB" {
		t.Fatalf("%v", w.fetched)
	}
}

func TestSignedDoorsAfterEveryMirror(t *testing.T) {
	w := newWorld(t)
	w.fetch = func(u string) error {
		if strings.HasPrefix(u, "https://n.example/") {
			return nil
		}
		return errors.New("timeout")
	}
	var asked atomic.Int32
	h := w.hooks()
	h.Doors = func() []string { asked.Add(1); return []string{"https://door-b.example", "https://n.example"} }
	s := New(t.TempDir(), h, t.Logf)
	s.prefs.Source = "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"
	t.Cleanup(func() { s.Close(false) })
	s.Connect()
	waitState(t, s, "on")
	w.mu.Lock()
	defer w.mu.Unlock()
	if asked.Load() != 1 || len(w.fetched) != 6 || w.fetched[5] != "https://n.example/api/hsub/ORDEN-AAAAA-BBBBB" {
		t.Fatalf("asked=%d %v", asked.Load(), w.fetched)
	}
}

func TestServerAnswerDoesNotAskSignedDoors(t *testing.T) {
	w := newWorld(t)
	w.fetch = func(string) error { return errors.New("catalogue: HTTP 404") }
	var asked atomic.Int32
	h := w.hooks()
	h.Doors = func() []string { asked.Add(1); return []string{"https://n.example"} }
	s := New(t.TempDir(), h, t.Logf)
	s.prefs.Source = "https://joinorden.com/hsub/ORDEN-AAAAA-BBBBB"
	t.Cleanup(func() { s.Close(false) })
	s.Connect()
	waitState(t, s, "failed")
	if asked.Load() != 0 {
		t.Fatalf("asked %d", asked.Load())
	}
}

// FARVATER_LIVE_TXT=1 reads the published list through the real resolvers,
// at the record and with the key FARVATER_DOORS gives.
func TestSignedDoorsLive(t *testing.T) {
	if os.Getenv("FARVATER_LIVE_TXT") != "1" || os.Getenv("FARVATER_DOORS") == "" {
		t.Skip("FARVATER_LIVE_TXT=1 FARVATER_DOORS=<spec>")
	}
	setDoors(os.Getenv("FARVATER_DOORS"))
	t.Cleanup(func() { setDoors(testDoors) })
	if n := len(SignedDoors()); n == 0 {
		t.Fatal("no verified doors")
	} else {
		t.Logf("%d doors verified", n)
	}
}

package kilvater

// Spec test vectors (docs/KILVATER.md §9). One golden file, testdata/vectors.json,
// fixes the exact bytes of the tag, the v2 key derivation and every frame for a
// set of frozen inputs. Two things check against it:
//
//   - this test, proving the production code reproduces the golden bytes and that
//     the production verifier accepts the golden tags;
//   - the independent Python reference in reference/python, proving a second
//     implementation agrees on the same bytes (cross-compat, run in CI).
//
// Regenerate the golden file after a deliberate protocol change with:
//
//	KV_UPDATE_VECTORS=1 go test ./kilvater -run TestVectors
//
// The keys here are frozen test constants (incrementing bytes), never real keys.

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Frozen inputs. Not real keys: 0x00..0x1f and 0x40..0x5f, so no one mistakes a
// vector for a secret.
var (
	vecV1Key      = seqKey(0x00)
	vecMaster     = seqKey(0x40)
	vecSubscriber = "subscriber-1"
	vecPath       = "/connect"
	vecTS         = int64(1700000000) // 2023-11-14T22:13:20Z, frozen
	vecNonceV1    = []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	vecNonceV2    = []byte{0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00}
)

func seqKey(start byte) Key {
	var k Key
	for i := range k {
		k[i] = start + byte(i)
	}
	return k
}

type vecTagV1 struct {
	Key   string `json:"key"`
	Path  string `json:"path"`
	TS    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	MAC   string `json:"mac"`
	Raw   string `json:"raw"`
	Tag   string `json:"tag"`
}

type vecTagV2 struct {
	Master     string `json:"master"`
	Subscriber string `json:"subscriber"`
	KeyID      string `json:"key_id"`
	DerivedKey string `json:"derived_key"`
	Path       string `json:"path"`
	TS         int64  `json:"ts"`
	Nonce      string `json:"nonce"`
	MAC        string `json:"mac"`
	Raw        string `json:"raw"`
	Tag        string `json:"tag"`
}

type vecFrame struct {
	Name string `json:"name"`
	Type byte   `json:"type"`
	Desc string `json:"desc"`
	Hex  string `json:"hex"`
}

type vecAddr struct {
	HostPort string `json:"hostport"`
	Desc     string `json:"desc"`
	Hex      string `json:"hex"`
}

type vectors struct {
	Note   string     `json:"note"`
	V1Tag  vecTagV1   `json:"v1_tag"`
	V2     vecTagV2   `json:"v2"`
	Addr   vecAddr    `json:"addr"`
	Frames []vecFrame `json:"frames"`
}

func frameHex(t *testing.T, typ byte, body []byte) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteFrame(&b, typ, body); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b.Bytes())
}

// buildVectors recomputes every vector from the frozen inputs using the
// production code. The golden file must equal this, byte for byte.
func buildVectors(t *testing.T) vectors {
	t.Helper()
	tsb := make([]byte, 8)
	binary.BigEndian.PutUint64(tsb, uint64(vecTS))

	// v1 tag.
	m1 := mac(vecV1Key, tsb, vecNonceV1, vecPath)
	raw1 := append(append(append([]byte{}, tsb...), vecNonceV1...), m1...)

	// v2 key id, derived key, tag.
	id := KeyIDFor(vecMaster, []byte(vecSubscriber))
	dk := DeriveKey(vecMaster, id)
	m2 := macV2(dk, id, tsb, vecNonceV2, vecPath)
	raw2 := []byte{tagVersion2}
	raw2 = append(raw2, id[:]...)
	raw2 = append(raw2, tsb...)
	raw2 = append(raw2, vecNonceV2...)
	raw2 = append(raw2, m2...)

	openTCP := append([]byte{NetTCP}, mustAddr(t, "example.com:443")...)
	openUDP := append([]byte{NetUDP}, mustAddr(t, "1.1.1.1:53")...)

	return vectors{
		Note: "Kilvater wire-format test vectors (docs/KILVATER.md §9). " +
			"The keys are frozen test constants, never real keys. All byte strings are hex. " +
			"Regenerate with KV_UPDATE_VECTORS=1 go test ./kilvater -run TestVectors.",
		V1Tag: vecTagV1{
			Key:   hex.EncodeToString(vecV1Key[:]),
			Path:  vecPath,
			TS:    vecTS,
			Nonce: hex.EncodeToString(vecNonceV1),
			MAC:   hex.EncodeToString(m1),
			Raw:   hex.EncodeToString(raw1),
			Tag:   base64.RawURLEncoding.EncodeToString(raw1),
		},
		V2: vecTagV2{
			Master:     hex.EncodeToString(vecMaster[:]),
			Subscriber: vecSubscriber,
			KeyID:      id.String(),
			DerivedKey: hex.EncodeToString(dk[:]),
			Path:       vecPath,
			TS:         vecTS,
			Nonce:      hex.EncodeToString(vecNonceV2),
			MAC:        hex.EncodeToString(m2),
			Raw:        hex.EncodeToString(raw2),
			Tag:        base64.RawURLEncoding.EncodeToString(raw2),
		},
		Addr: vecAddr{
			HostPort: "example.com:443",
			Desc:     "address encoding ([len:1][host:port]), as used inside an OPEN body",
			Hex:      hex.EncodeToString(mustAddr(t, "example.com:443")),
		},
		Frames: []vecFrame{
			{"open_tcp", FrameOpen, "OPEN, TCP, example.com:443", frameHex(t, FrameOpen, openTCP)},
			{"open_udp", FrameOpen, "OPEN, UDP, 1.1.1.1:53", frameHex(t, FrameOpen, openUDP)},
			{"data", FrameData, `DATA "hello"`, frameHex(t, FrameData, []byte("hello"))},
			{"pad", FramePad, "PAD, body ignored (here 8 zero bytes); only its length is a signal", frameHex(t, FramePad, make([]byte, 8))},
			{"dgram", FrameDgram, "DGRAM, one UDP datagram (here 0a0b0c0d)", frameHex(t, FrameDgram, []byte{0x0a, 0x0b, 0x0c, 0x0d})},
			{"close_ok", FrameClose, "CLOSE, code 0 (normal end)", frameHex(t, FrameClose, []byte{0})},
			{"close_err", FrameClose, "CLOSE, code 1 (error / refused)", frameHex(t, FrameClose, []byte{1})},
		},
	}
}

func mustAddr(t *testing.T, hostport string) []byte {
	t.Helper()
	b, err := AppendAddr(nil, hostport)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func vectorsPath() string { return filepath.Join("testdata", "vectors.json") }

// TestVectors proves the production code reproduces the committed golden
// vectors byte for byte, and that the production verifier accepts the golden
// tags. A protocol change in the Go code breaks this until the golden file is
// regenerated on purpose; a divergence in the Python reference breaks its own
// test against the same file.
func TestVectors(t *testing.T) {
	got := buildVectors(t)

	if os.Getenv("KV_UPDATE_VECTORS") == "1" {
		out, err := json.MarshalIndent(got, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, '\n')
		if err := os.WriteFile(vectorsPath(), out, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", vectorsPath())
		return
	}

	raw, err := os.ReadFile(vectorsPath())
	if err != nil {
		t.Fatalf("read golden vectors: %v (regenerate with KV_UPDATE_VECTORS=1)", err)
	}
	var want vectors
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}

	// Field-by-field, so a mismatch says which byte string drifted.
	eq := func(name, a, b string) {
		if a != b {
			t.Errorf("%s: production %q != golden %q", name, a, b)
		}
	}
	eq("v1.mac", got.V1Tag.MAC, want.V1Tag.MAC)
	eq("v1.raw", got.V1Tag.Raw, want.V1Tag.Raw)
	eq("v1.tag", got.V1Tag.Tag, want.V1Tag.Tag)
	eq("v2.key_id", got.V2.KeyID, want.V2.KeyID)
	eq("v2.derived_key", got.V2.DerivedKey, want.V2.DerivedKey)
	eq("v2.mac", got.V2.MAC, want.V2.MAC)
	eq("v2.raw", got.V2.Raw, want.V2.Raw)
	eq("v2.tag", got.V2.Tag, want.V2.Tag)
	eq("addr", got.Addr.Hex, want.Addr.Hex)
	if len(got.Frames) != len(want.Frames) {
		t.Fatalf("frame count: production %d != golden %d", len(got.Frames), len(want.Frames))
	}
	for i, g := range got.Frames {
		w := want.Frames[i]
		if g.Name != w.Name {
			t.Errorf("frame %d name: %q != %q", i, g.Name, w.Name)
		}
		eq("frame "+g.Name, g.Hex, w.Hex)
	}

	// The production verifier accepts the golden tags at the frozen clock.
	now := time.Unix(vecTS, 0)
	v1 := NewVerifier([]Key{vecV1Key})
	if n := v1.Verify(want.V1Tag.Tag, vecPath, now); n < 0 {
		t.Error("the production verifier rejected the golden v1 tag")
	}
	v2 := NewVerifierConfig(VerifierConfig{Master: &vecMaster})
	if n := v2.Verify(want.V2.Tag, vecPath, now); n < 0 {
		t.Error("the production verifier rejected the golden v2 tag")
	}
}

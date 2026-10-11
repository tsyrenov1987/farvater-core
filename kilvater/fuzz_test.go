package kilvater

import (
	"bytes"
	"testing"
	"time"
)

// Everything below parses bytes a peer controls; none of it may panic or
// allocate past MaxFrame.

func FuzzReadFrame(f *testing.F) {
	var b bytes.Buffer
	WriteFrame(&b, FrameData, []byte("hello"))
	f.Add(b.Bytes())
	f.Add([]byte{FrameOpen, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, in []byte) {
		r := bytes.NewReader(in)
		var buf []byte
		for {
			_, body, err := ReadFrame(r, buf)
			if err != nil {
				return
			}
			if len(body) > MaxFrame {
				t.Fatalf("body %d > MaxFrame", len(body))
			}
			buf = body[:0]
		}
	})
}

func FuzzParseAddr(f *testing.F) {
	ok, _ := AppendAddr(nil, "example.org:443")
	f.Add(ok)
	f.Add([]byte{5, '[', ':', ':', ']', ':'})
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, in []byte) {
		addr, rest, err := ParseAddr(in)
		if err != nil {
			return
		}
		if len(addr)+1+len(rest) != len(in) {
			t.Fatalf("lengths do not add up: %q %d %d", addr, len(rest), len(in))
		}
	})
}

func FuzzVerify(f *testing.F) {
	var k Key
	now := time.Unix(1_800_000_000, 0)
	f.Add(NewTag(k, "/connect", now), "/connect")
	f.Add("", "/")
	f.Add("AAAA", "/connect")
	f.Fuzz(func(t *testing.T, tag, path string) {
		v := NewVerifier([]Key{k})
		if i := v.Verify(tag, path, now); i >= 0 && v.Verify(tag, path, now) >= 0 {
			t.Fatal("a tag was accepted twice")
		}
	})
}

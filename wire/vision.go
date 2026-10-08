package wire

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"math/big"
	"reflect"
	"sync"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

// Vision (xtls-rprx-vision) is VLESS's flow that pads the first frames to
// hide the VLESS header's shape and then, once it sees the inner traffic is
// TLS 1.3, stops wrapping and lets the already-encrypted records pass
// straight through. This is our own implementation of the client side; the
// wire format matches Xray's so our client talks to an Xray server.
//
// A frame is: [cmd:1][contentLen:2 BE][paddingLen:2 BE][content][padding],
// and the very first frame the client sends is prefixed with the 16-byte
// account UUID. Commands: 0 continue, 1 end (stop padding), 2 direct (the
// rest of the stream is the raw inner connection).

const (
	visCmdContinue = 0
	visCmdEnd      = 1
	visCmdDirect   = 2

	visBufSize    = 8192 // Xray's buffer size; the reshape thresholds depend on it
	visFilterPkts = 8
)

var (
	tls13SupportedVersions = []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	tlsClientHelloStart    = []byte{0x16, 0x03}
	tlsServerHelloStart    = []byte{0x16, 0x03, 0x03}
	tlsAppDataStart        = []byte{0x17, 0x03, 0x03}
)

var visTestseed = []int32{900, 500, 900, 256}

// visionState is the padding/TLS-detection state shared by the one writer and
// the one reader of a Vision flow. The top-level fields are touched by both
// goroutines (TLS filtering), so a mutex guards them; the per-direction fields
// are each used by one side only.
type visionState struct {
	mu                     sync.Mutex
	uuid                   []byte
	numberOfPacketToFilter int
	isTLS                  bool
	isTLS12orAbove         bool
	enableXtls             bool
	cipher                 uint16
	remainingServerHello   int32

	// uplink writer (client → server)
	wPadding bool
	wDirect  bool
	// downlink reader (server → client)
	rWithinPadding bool
	rRemainingCmd  int32
	rRemainingLen  int32
	rRemainingPad  int32
	rCurrentCmd    int
	rDirect        bool
}

func newVisionState(uuid []byte) *visionState {
	return &visionState{
		uuid:                   append([]byte(nil), uuid...),
		numberOfPacketToFilter: visFilterPkts,
		remainingServerHello:   -1,
		wPadding:               true,
		rWithinPadding:         true,
		rRemainingCmd:          -1,
		rRemainingLen:          -1,
		rRemainingPad:          -1,
	}
}

// xtlsPadding builds one frame around content (which may be empty).
func xtlsPadding(content []byte, command byte, uuid *[]byte, longPadding bool) []byte {
	contentLen := int32(len(content))
	var paddingLen int32
	if contentLen < visTestseed[0] && longPadding {
		paddingLen = randInt32(visTestseed[1]) + visTestseed[2] - contentLen
	} else {
		paddingLen = randInt32(visTestseed[3])
	}
	if paddingLen > int32(visBufSize)-21-contentLen {
		paddingLen = int32(visBufSize) - 21 - contentLen
	}
	var b []byte
	if *uuid != nil {
		b = append(b, *uuid...)
		*uuid = nil
	}
	b = append(b, command, byte(contentLen>>8), byte(contentLen), byte(paddingLen>>8), byte(paddingLen))
	b = append(b, content...)
	b = append(b, make([]byte, paddingLen)...)
	return b
}

func randInt32(n int32) int32 {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int32(v.Int64())
}

// isCompleteRecord reports whether b is exactly a whole number of TLS
// application-data records (17 03 03 len …).
func isCompleteRecord(b []byte) bool {
	for len(b) > 0 {
		if len(b) < 5 {
			return false
		}
		if b[0] != 0x17 || b[1] != 0x03 || b[2] != 0x03 {
			return false
		}
		n := int(b[3])<<8 | int(b[4])
		if len(b)-5 < n {
			return false
		}
		b = b[5+n:]
	}
	return true
}

// filterTLS inspects a chunk for the TLS handshake, learning whether the
// inner traffic is TLS 1.3 (so Vision may switch to direct). It mutates the
// shared counters and must be called under st.mu.
func (st *visionState) filterTLS(b []byte) {
	st.numberOfPacketToFilter--
	if len(b) >= 6 {
		if bytes.Equal(b[:3], tlsServerHelloStart) && b[5] == 0x02 {
			st.remainingServerHello = (int32(b[3])<<8 | int32(b[4])) + 5
			st.isTLS12orAbove = true
			st.isTLS = true
			if len(b) >= 79 && st.remainingServerHello >= 79 {
				sessionIDLen := int32(b[43])
				st.cipher = uint16(b[43+sessionIDLen+1])<<8 | uint16(b[43+sessionIDLen+2])
			}
		} else if bytes.Equal(b[:2], tlsClientHelloStart) && b[5] == 0x01 {
			st.isTLS = true
		}
	}
	if st.remainingServerHello > 0 {
		end := st.remainingServerHello
		if end > int32(len(b)) {
			end = int32(len(b))
		}
		st.remainingServerHello -= int32(len(b))
		if bytes.Contains(b[:end], tls13SupportedVersions) {
			// 0x1305 is TLS_AES_128_CCM_8_SHA256; Xray does not enable Vision for it.
			if st.cipher != 0x1305 && st.cipher >= 0x1301 && st.cipher <= 0x1304 {
				st.enableXtls = true
			}
			st.numberOfPacketToFilter = 0
		} else if st.remainingServerHello <= 0 {
			st.numberOfPacketToFilter = 0
		}
	}
}

// visionWriter wraps the TLS connection and pads the client's uplink.
type visionWriter struct {
	raw    io.Writer // the TLS connection
	direct io.Writer // the TCP connection under it: every write after a Direct frame goes here, as Xray reads it
	st     *visionState
	uuid   []byte
}

// newVisionWriter writes through raw; direct may be nil when the flow never
// goes direct (XUDP).
func newVisionWriter(raw, direct io.Writer, st *visionState) *visionWriter {
	return &visionWriter{raw: raw, direct: direct, st: st, uuid: append([]byte(nil), st.uuid...)}
}

func (w *visionWriter) Write(p []byte) (int, error) {
	st := w.st
	st.mu.Lock()
	if st.wDirect && w.direct != nil {
		st.mu.Unlock()
		return w.direct.Write(p)
	}
	if st.numberOfPacketToFilter > 0 {
		st.filterTLS(p)
	}
	if !st.wPadding {
		st.mu.Unlock()
		return w.raw.Write(p)
	}
	// Split a chunk that is too large to pad in one frame at the last TLS
	// record boundary (else near the middle), as Xray reshapes.
	pieces := reshape(p)
	isComplete := isCompleteRecord(p)
	longPadding := st.isTLS
	var out []byte
pad:
	for i, piece := range pieces {
		switch {
		case st.isTLS && len(piece) >= 6 && bytes.Equal(piece[:3], tlsAppDataStart) && isComplete:
			if st.enableXtls {
				st.wDirect = true
			}
			command := byte(visCmdContinue)
			if i == len(pieces)-1 {
				command = visCmdEnd
				if st.enableXtls {
					command = visCmdDirect
				}
			}
			out = append(out, xtlsPadding(piece, command, &w.uuid, true)...)
			st.wPadding = false
			longPadding = false
			// The pieces after it are still padded, the last one carrying End
			// or Direct (Xray's `continue`): the server reads them as frames.
		case !st.isTLS12orAbove && st.numberOfPacketToFilter <= 1:
			st.wPadding = false
			out = append(out, xtlsPadding(piece, visCmdEnd, &w.uuid, longPadding)...)
			// the remaining pieces go unpadded in this same write
			for _, rest := range pieces[i+1:] {
				out = append(out, rest...)
			}
			break pad
		default:
			command := byte(visCmdContinue)
			if i == len(pieces)-1 && !st.wPadding {
				command = visCmdEnd
				if st.enableXtls {
					command = visCmdDirect
				}
			}
			out = append(out, xtlsPadding(piece, command, &w.uuid, longPadding)...)
		}
	}
	st.mu.Unlock()
	// The frame that says Direct still goes through TLS; the writes after it
	// go to the TCP connection.
	if _, err := w.raw.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// writeFirst sends the first Vision frame, which carries the UUID. content
// may be empty (a long padding frame that hides the header).
func (w *visionWriter) writeFirst(content []byte) error {
	st := w.st
	st.mu.Lock()
	if st.numberOfPacketToFilter > 0 && len(content) > 0 {
		st.filterTLS(content)
	}
	if len(content) == 0 {
		frame := xtlsPadding(nil, visCmdContinue, &w.uuid, true)
		st.mu.Unlock()
		_, err := w.raw.Write(frame)
		return err
	}
	st.mu.Unlock()
	_, err := w.Write(content)
	return err
}

// reshape splits a buffer that is too large to carry in one padded frame.
func reshape(p []byte) [][]byte {
	if len(p) < visBufSize-21 {
		return [][]byte{p}
	}
	idx := bytes.LastIndex(p, tlsAppDataStart)
	if idx < 21 || idx > visBufSize-21 {
		idx = visBufSize / 2
	}
	return [][]byte{p[:idx], p[idx:]}
}

// visionReader wraps the TLS connection and strips padding from the server's
// downlink, switching to the raw connection when the server sends Direct.
type visionReader struct {
	src    io.Reader // the TLS connection
	st     *visionState
	raw    io.Reader // where to read after a Direct command (the TCP conn)
	drain  func() []byte
	buf    []byte // unpadded bytes not yet returned
	direct bool
}

func newVisionReader(src io.Reader, st *visionState, raw io.Reader, drain func() []byte) *visionReader {
	return &visionReader{src: src, st: st, raw: raw, drain: drain}
}

func (r *visionReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.direct {
			return r.raw.Read(p)
		}
		chunk := make([]byte, 32*1024)
		n, err := r.src.Read(chunk)
		if n > 0 {
			out, switched := r.process(chunk[:n])
			r.buf = out
			if switched {
				r.direct = true
				if r.drain != nil {
					r.buf = append(r.buf, r.drain()...)
				}
			}
		}
		if len(r.buf) == 0 && err != nil {
			return 0, err
		}
		if err != nil && len(r.buf) == 0 {
			return 0, err
		}
		if n == 0 && err == nil {
			continue
		}
		if len(r.buf) == 0 && err == nil {
			continue
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// process unpads a chunk and reports whether the server switched to direct.
func (r *visionReader) process(b []byte) (out []byte, switched bool) {
	st := r.st
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rDirect {
		return b, false
	}
	if st.rWithinPadding || st.numberOfPacketToFilter > 0 {
		out = r.unpad(b)
		switch {
		case st.rRemainingLen > 0 || st.rRemainingPad > 0 || st.rCurrentCmd == 0:
			st.rWithinPadding = true
		case st.rCurrentCmd == 1:
			st.rWithinPadding = false
		case st.rCurrentCmd == 2:
			st.rWithinPadding = false
			st.rDirect = true
			switched = true
		}
	} else {
		out = b
	}
	if st.numberOfPacketToFilter > 0 && len(out) > 0 {
		st.filterTLS(out)
	}
	return out, switched
}

// unpad consumes b through the padding state machine, returning the content.
// It mirrors Xray's XtlsUnpadding and runs under st.mu.
func (r *visionReader) unpad(b []byte) []byte {
	st := r.st
	if st.rRemainingCmd == -1 && st.rRemainingLen == -1 && st.rRemainingPad == -1 {
		if len(b) >= 21 && bytes.Equal(st.uuid, b[:16]) {
			b = b[16:]
			st.rRemainingCmd = 5
		} else {
			return b
		}
	}
	var out []byte
	for len(b) > 0 {
		switch {
		case st.rRemainingCmd > 0:
			data := b[0]
			b = b[1:]
			switch st.rRemainingCmd {
			case 5:
				st.rCurrentCmd = int(data)
			case 4:
				st.rRemainingLen = int32(data) << 8
			case 3:
				st.rRemainingLen |= int32(data)
			case 2:
				st.rRemainingPad = int32(data) << 8
			case 1:
				st.rRemainingPad |= int32(data)
			}
			st.rRemainingCmd--
		case st.rRemainingLen > 0:
			n := st.rRemainingLen
			if int32(len(b)) < n {
				n = int32(len(b))
			}
			out = append(out, b[:n]...)
			b = b[n:]
			st.rRemainingLen -= n
		default: // remainingPad > 0
			n := st.rRemainingPad
			if int32(len(b)) < n {
				n = int32(len(b))
			}
			b = b[n:]
			st.rRemainingPad -= n
		}
		if st.rRemainingCmd <= 0 && st.rRemainingLen <= 0 && st.rRemainingPad <= 0 {
			if st.rCurrentCmd == 0 {
				st.rRemainingCmd = 5
			} else {
				st.rRemainingCmd, st.rRemainingLen, st.rRemainingPad = -1, -1, -1
				if len(b) > 0 {
					out = append(out, b...)
				}
				break
			}
		}
	}
	return out
}

// utlsBuffers reaches a uTLS connection's buffered plaintext (input) and
// ciphertext (rawInput), which Vision drains when it switches to reading the
// raw connection directly. uTLS exposes no accessor, so this reads the
// unexported fields by their offset, as Xray does.
func utlsBuffers(u *utls.UConn) (drain func() []byte, raw io.Reader, err error) {
	if u.ConnectionState().Version != utls.VersionTLS13 {
		return nil, nil, errors.New("vision needs TLS 1.3")
	}
	t := reflect.TypeOf(u.Conn).Elem()
	base := unsafe.Pointer(u.Conn)
	fi, ok1 := t.FieldByName("input")
	fr, ok2 := t.FieldByName("rawInput")
	if !ok1 || !ok2 {
		return nil, nil, errors.New("vision: cannot locate uTLS buffers")
	}
	input := (*bytes.Reader)(unsafe.Add(base, fi.Offset))
	rawInput := (*bytes.Buffer)(unsafe.Add(base, fr.Offset))
	drain = func() []byte {
		var out []byte
		if input.Len() > 0 {
			b := make([]byte, input.Len())
			input.Read(b)
			out = append(out, b...)
		}
		if rawInput.Len() > 0 {
			out = append(out, rawInput.Bytes()...)
			rawInput.Reset()
		}
		return out
	}
	return drain, u.NetConn(), nil
}

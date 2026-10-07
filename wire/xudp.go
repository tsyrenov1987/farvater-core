package wire

import (
	"bytes"
	"io"
	"sync"
)

// XUDP (Mux.Cool over VLESS/VMess) carries UDP datagrams inside one stream to
// the virtual host v1.mux.cool:666. Each datagram is a Mux frame that names
// its own address, so one association serves a whole socket. This is our own
// framing; it matches Xray's so our client talks to an Xray server.
//
// Frame: [metaLen:2 BE][meta][dataLen:2 BE][data]. The first frame's meta is
// a New (status 1) that opens the session and carries an 8-byte global id;
// later frames are Keep (status 2) that re-state the address.

type xudpWriter struct {
	w       io.Writer
	mu      sync.Mutex
	started bool
}

func newXUDPWriter(w io.Writer) *xudpWriter { return &xudpWriter{w: w} }

func (x *xudpWriter) WritePacket(p []byte, target Target) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(p) == 0 || len(p)+666 > visBufSize {
		return nil // XUDP cannot carry it; drop as Xray does
	}
	meta := []byte{0, 0} // session id 0
	if !x.started {
		meta = append(meta, 1, 1, 2) // New, Opt=1, network UDP
		var err error
		meta, err = appendPortAddr(meta, target)
		if err != nil {
			return err
		}
		meta = append(meta, make([]byte, 8)...) // global id (zero)
		x.started = true
	} else {
		meta = append(meta, 2, 1, 2) // Keep, Opt=1, network UDP
		var err error
		meta, err = appendPortAddr(meta, target)
		if err != nil {
			return err
		}
	}
	// The length prefix counts the whole meta block (session id included);
	// the meta is followed by the datagram with its own 2-byte length.
	frame := make([]byte, 0, 2+len(meta)+2+len(p))
	frame = append(frame, byte(len(meta)>>8), byte(len(meta)))
	frame = append(frame, meta...)
	frame = append(frame, byte(len(p)>>8), byte(len(p)))
	frame = append(frame, p...)
	_, err := x.w.Write(frame)
	return err
}

type xudpReader struct {
	r  io.Reader
	mu sync.Mutex
}

func newXUDPReader(r io.Reader) *xudpReader { return &xudpReader{r: r} }

func (x *xudpReader) ReadPacket() ([]byte, Target, error) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for {
		var lc [2]byte
		if _, err := io.ReadFull(x.r, lc[:]); err != nil {
			return nil, Target{}, err
		}
		metaLen := int(lc[0])<<8 | int(lc[1])
		if metaLen < 4 {
			return nil, Target{}, io.EOF
		}
		meta := make([]byte, metaLen)
		if _, err := io.ReadFull(x.r, meta); err != nil {
			return nil, Target{}, err
		}
		status, opt := meta[2], meta[3]
		var from Target
		discard := false
		switch status {
		case 2: // Keep
			if metaLen > 4 && meta[4] == 2 { // names a UDP address
				t, err := readPortAddr(bytes.NewReader(meta[5:]))
				if err != nil {
					return nil, Target{}, err
				}
				from = t
			}
		case 4: // KeepAlive
			discard = true
		default:
			return nil, Target{}, io.EOF
		}
		if opt&1 == 0 { // no data on this frame
			continue
		}
		var dc [2]byte
		if _, err := io.ReadFull(x.r, dc[:]); err != nil {
			return nil, Target{}, err
		}
		n := int(dc[0])<<8 | int(dc[1])
		if n == 0 {
			continue
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(x.r, data); err != nil {
			return nil, Target{}, err
		}
		if discard {
			continue
		}
		return data, from, nil
	}
}

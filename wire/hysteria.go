package wire

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/extras/v2/obfs"
	"github.com/xtls/xray-core/common/buf"
)

type hyWire struct {
	spec PathSpec
	mu   sync.Mutex
	cl   client.Client
}

func newHysteria(spec PathSpec) (*hyWire, error) {
	if spec.Password == "" {
		return nil, errors.New("hysteria2: missing password")
	}
	if spec.Obfs != "" && spec.Obfs != "salamander" {
		return nil, errors.New("hysteria2: unsupported obfs " + spec.Obfs)
	}
	return &hyWire{spec: spec}, nil
}

func (w *hyWire) ID() string     { return w.spec.ID }
func (w *hyWire) Spec() PathSpec { return w.spec }

func (w *hyWire) NeedsHandshake() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cl == nil
}

func (w *hyWire) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cl != nil {
		err := w.cl.Close()
		w.cl = nil
		return err
	}
	return nil
}

type salamanderFactory struct{ psk []byte }

func (f salamanderFactory) New(net.Addr) (net.PacketConn, error) {
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return obfs.WrapPacketConnSalamander(c, f.psk)
}

func (w *hyWire) config() (*client.Config, error) {
	addr, err := net.ResolveUDPAddr("udp", w.spec.Host+":"+itoa(w.spec.Port))
	if err != nil {
		return nil, err
	}
	cfg := &client.Config{
		ServerAddr: addr,
		Auth:       w.spec.Password,
		TLSConfig: client.TLSConfig{
			ServerName:         w.spec.ServerSNI(),
			InsecureSkipVerify: w.spec.Insecure,
		},
		FastOpen: true,
		// BandwidthConfig left zero: the congestion controller stays BBR.
	}
	if w.spec.Obfs == "salamander" {
		cfg.ConnFactory = salamanderFactory{psk: []byte(w.spec.ObfsPass)}
	}
	if pin := normalizePin(w.spec.PinSHA256); pin != "" {
		cfg.TLSConfig.InsecureSkipVerify = true
		cfg.TLSConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			for _, rc := range rawCerts {
				sum := sha256.Sum256(rc)
				if hex.EncodeToString(sum[:]) == pin {
					return nil
				}
			}
			return errors.New("hysteria2: certificate pin mismatch")
		}
	}
	return cfg, nil
}

func normalizePin(p string) string {
	p = strings.ToLower(strings.ReplaceAll(p, ":", ""))
	if len(p) != 64 {
		return ""
	}
	return p
}

// Dial makes sure the QUIC session exists. The handshake only happens when
// there is none; NeedsHandshake tells the caller which case it is.
func (w *hyWire) Dial(ctx context.Context) (Session, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cl == nil {
		cfg, err := w.config()
		if err != nil {
			return nil, err
		}
		type res struct {
			cl  client.Client
			err error
		}
		ch := make(chan res, 1)
		go func() {
			cl, _, err := client.NewClient(cfg)
			ch <- res{cl, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				return nil, r.err
			}
			w.cl = r.cl
		case <-ctx.Done():
			go func() {
				if r := <-ch; r.cl != nil {
					r.cl.Close()
				}
			}()
			return nil, ctx.Err()
		}
	}
	return &hySession{w: w, cl: w.cl}, nil
}

func (w *hyWire) dropIf(cl client.Client) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cl == cl {
		w.cl = nil
		go cl.Close()
	}
}

type hySession struct {
	w  *hyWire
	cl client.Client
}

func (s *hySession) Close() error { return nil }

func (s *hySession) Run(ctx context.Context, target Target, prelude []byte, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	c, err := s.cl.TCP(target.String())
	if err != nil {
		var closed coreErrs.ClosedError
		if errors.As(err, &closed) {
			s.w.dropIf(s.cl)
			return OutcomeError, ErrWireDead
		}
		return OutcomeError, err
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		c.Close()
	}()
	if len(prelude) > 0 {
		if _, err := c.Write(prelude); err != nil {
			return OutcomeError, err
		}
	}
	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, buf.NewWriter(c), m, nil) }()
	downErr := make(chan error, 1)
	go func() {
		p := make([]byte, 32*1024)
		for {
			n, err := c.Read(p)
			if n > 0 {
				m.Down(n)
				if _, werr := down.Write(p[:n]); werr != nil {
					downErr <- werr
					return
				}
			}
			if err != nil {
				if err == io.EOF {
					downErr <- nil
				} else {
					downErr <- err
				}
				return
			}
		}
	}()
	idle := time.AfterFunc(IdleTimeout, cancel)
	defer idle.Stop()
	return settle(ctx, upErr, downErr, cancel, nil, func() { idle.Reset(2 * time.Second) })
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}

package wire

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/signal"
)

// pumpUp forwards app chunks to a buf.Writer until the channel closes
// (returns io.EOF), the context ends, or a write fails.
func pumpUp(ctx context.Context, up <-chan []byte, w buf.Writer, m Meter, timer *signal.ActivityTimer) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p, ok := <-up:
			if !ok {
				return io.EOF
			}
			m.Up(p)
			if timer != nil {
				timer.Update()
			}
			if err := w.WriteMultiBuffer(buf.MergeBytes(nil, p)); err != nil {
				return err
			}
		}
	}
}

// downWriter counts downstream bytes and hands them to the app.
type downWriter struct {
	w io.Writer
	m Meter
}

func (d *downWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	for _, b := range mb {
		if b.IsEmpty() {
			continue
		}
		d.m.Down(b.Bytes())
		if _, err := d.w.Write(b.Bytes()); err != nil {
			return err
		}
	}
	return nil
}

// settle waits for the two pumps and maps their results onto an Outcome.
// upErr/downErr deliver exactly one value each; closeConn must unblock the
// downstream reader.
func settle(ctx context.Context, upErr, downErr <-chan error, cancel func(), timer *signal.ActivityTimer, afterClientFin func()) (Outcome, error) {
	clientDone := false
	for {
		select {
		case err := <-downErr:
			cancel()
			if err == nil || err == io.EOF {
				if clientDone {
					return OutcomeClientFin, nil
				}
				return OutcomeRemoteFin, nil
			}
			if ctx.Err() != nil {
				return OutcomeCanceled, ctx.Err()
			}
			return OutcomeError, err
		case err := <-upErr:
			upErr = nil
			if err == io.EOF {
				clientDone = true
				if afterClientFin != nil {
					afterClientFin()
				}
				continue
			}
			if ctx.Err() != nil {
				// The caller canceled; let the downstream side report.
				continue
			}
			cancel()
			<-downErr
			return OutcomeError, err
		}
	}
}

// nextPacket returns the next datagram r yields and the address it came from,
// keeping the rest of what one read brought in pend.
func nextPacket(r buf.Reader, pend *buf.MultiBuffer) ([]byte, Target, error) {
	for len(*pend) == 0 {
		mb, err := r.ReadMultiBuffer()
		*pend = append(*pend, mb...)
		if err != nil && len(*pend) == 0 {
			return nil, Target{}, err
		}
	}
	b := (*pend)[0]
	*pend = (*pend)[1:]
	defer b.Release()
	var from Target
	if b.UDP != nil {
		from = Target{Host: b.UDP.Address.String(), Port: int(b.UDP.Port)}
	}
	return append([]byte(nil), b.Bytes()...), from, nil
}

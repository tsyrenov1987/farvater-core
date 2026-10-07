package wire

import (
	"context"
	"io"
	"time"
)

// pumpUp forwards the app's chunks to w until the channel closes (returns
// io.EOF), the context ends, or a write fails.
func pumpUp(ctx context.Context, up <-chan []byte, w io.Writer, m Meter, it *idleTimer) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case p, ok := <-up:
			if !ok {
				return io.EOF
			}
			m.Up(p)
			if it != nil {
				it.touch()
			}
			if _, err := w.Write(p); err != nil {
				return err
			}
		}
	}
}

// pumpDown hands what r yields to the app until r ends (nil) or fails.
func pumpDown(r io.Reader, down io.Writer, m Meter, it *idleTimer) error {
	p := make([]byte, 32*1024)
	for {
		n, err := r.Read(p)
		if n > 0 {
			if it != nil {
				it.touch()
			}
			m.Down(p[:n])
			if _, werr := down.Write(p[:n]); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// settle waits for the two pumps and maps their results onto an Outcome.
// upErr/downErr deliver exactly one value each; cancel must unblock the
// downstream reader.
func settle(ctx context.Context, upErr, downErr <-chan error, cancel func(), afterClientFin func()) (Outcome, error) {
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

// runStream carries one flow over conn once the proxy request is out: the
// app's chunks go up through w, what r yields comes down, and the flow ends
// when either side finishes, nothing moves for IdleTimeout, or ctx ends.
// After the app finishes, the remote gets 2 s of quiet to finish too.
// conn is closed on return.
func runStream(ctx context.Context, conn io.Closer, w io.Writer, r io.Reader, up <-chan []byte, down io.Writer, m Meter) (Outcome, error) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	it := newIdleTimer(IdleTimeout, cancel)
	defer it.stop()
	go func() {
		<-ctx.Done()
		conn.Close() // unblocks the downstream reader
	}()
	upErr := make(chan error, 1)
	go func() { upErr <- pumpUp(ctx, up, w, m, it) }()
	downErr := make(chan error, 1)
	go func() { downErr <- pumpDown(r, down, m, it) }()
	return settle(ctx, upErr, downErr, cancel, func() { it.setTimeout(2 * time.Second) })
}

// settleClose is settle for a flow whose caller set up its own pumps (to read
// a response header first): it closes conn and maps the two pumps' results.
func settleClose(ctx context.Context, conn io.Closer, upErr, downErr <-chan error, cancel func(), afterClientFin func()) (Outcome, error) {
	defer conn.Close()
	return settle(ctx, upErr, downErr, cancel, afterClientFin)
}

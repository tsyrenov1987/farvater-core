package kilvater

import (
	"io"
	"math/rand/v2"
	"strings"
	"sync"
	"time"
)

// PadMode is how hard the shaper works to make a tunnel's record sizes and
// timing look less like one long bulk transfer and more like ordinary web
// traffic. The zero value is PadModerate, so a Server or client that sets
// nothing still gets the default shaping.
//
// The shaping is one-sided and needs no agreement: it only changes how DATA is
// split into frames and how many PAD frames ride between them. A peer running
// v1 (or PadOff) reads the stream exactly as before — it already joins DATA
// frames back together and ignores PAD — so every mode interoperates with
// every other, in both directions.
type PadMode int

const (
	// PadModerate (the default) breaks the run of max-size records a bulk
	// transfer would otherwise be into a spread of sizes, with the odd PAD
	// mixed in. It roughly doubles the frame count and adds well under 1 % to
	// the bytes, and starts no background goroutine.
	PadModerate PadMode = iota
	// PadOff reproduces v1 framing exactly: DATA in 16 KiB chunks, no extra
	// PAD. The opening PAD (WritePad) is unchanged in every mode.
	PadOff
	// PadHeavy leans further toward a web-like size distribution (more small
	// records) and, on top of the inline PAD, sends a small PAD during a pause
	// so a silent connection is not plainly idle. It costs more frames and a
	// little steady traffic while idle.
	PadHeavy
)

func (m PadMode) String() string {
	switch m {
	case PadOff:
		return "off"
	case PadHeavy:
		return "heavy"
	default:
		return "moderate"
	}
}

// ParsePadMode reads a mode name, defaulting an empty or unknown value to
// PadModerate so an old share link without the parameter, or one from a newer
// build naming a mode this one does not know, still runs (seamlessly, at the
// default).
func ParsePadMode(s string) PadMode {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "off", "none", "0":
		return PadOff
	case "heavy", "max", "high":
		return PadHeavy
	default:
		return PadModerate
	}
}

// defaultIdlePad is how long a PadHeavy connection may stay silent before it
// sends a small PAD. The real wait jitters up from here so the gaps are not a
// clock.
const defaultIdlePad = 500 * time.Millisecond

// Shaper writes a tunnel's DATA and PAD frames to one direction of a stream,
// sizing and spacing them by its PadMode. One Shaper serves one direction; the
// two directions of a tunnel each have their own. All writes go through its
// lock, so the idle-PAD goroutine (PadHeavy) and the data writer never cut
// into each other's frames.
type Shaper struct {
	w    io.Writer
	mode PadMode
	idle time.Duration

	mu     sync.Mutex
	active bool // data written since the last idle tick

	stop      chan struct{}
	done      chan struct{}
	closeOnce sync.Once
}

// NewShaper returns a Shaper writing to w in the given mode. For PadHeavy it
// starts the idle-PAD goroutine; Close stops it.
func NewShaper(w io.Writer, mode PadMode) *Shaper {
	return newShaper(w, mode, defaultIdlePad)
}

func newShaper(w io.Writer, mode PadMode, idle time.Duration) *Shaper {
	s := &Shaper{w: w, mode: mode, idle: idle}
	if mode == PadHeavy {
		s.stop = make(chan struct{})
		s.done = make(chan struct{})
		s.active = true // first tick waits for a real pause, not the open
		go s.idleLoop()
	}
	return s
}

// WriteData writes p as one or more DATA frames whose sizes follow the mode's
// distribution, with the occasional PAD frame between them. All of p is sent
// (or an error is returned); a reader reassembles it exactly, PAD or not.
func (s *Shaper) WriteData(p []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = true
	for len(p) > 0 {
		n := s.nextChunk(len(p))
		if err := WriteFrame(s.w, FrameData, p[:n]); err != nil {
			return err
		}
		p = p[n:]
		if len(p) > 0 && s.inlinePad() {
			if err := s.writePadLocked(inlinePadSize(s.mode)); err != nil {
				return err
			}
		}
	}
	return nil
}

// WritePad writes the opening PAD, a random 16–271 bytes, which varies the
// size of the first record a peer sees. Same range in every mode.
func (s *Shaper) WritePad() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = true
	return s.writePadLocked(16 + rand.IntN(256))
}

// Close stops the idle goroutine (PadHeavy) and waits for it, so no PAD is
// written after Close returns. It does not close the underlying writer.
func (s *Shaper) Close() error {
	s.closeOnce.Do(func() {
		if s.stop != nil {
			close(s.stop)
			<-s.done
		}
	})
	return nil
}

func (s *Shaper) writePadLocked(n int) error {
	return WriteFrame(s.w, FramePad, make([]byte, n))
}

// idleLoop sends a small PAD whenever a whole interval passes with no data, so
// a PadHeavy connection in a lull still puts something on the wire.
func (s *Shaper) idleLoop() {
	defer close(s.done)
	t := time.NewTimer(s.jitterIdle())
	defer t.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-t.C:
			s.mu.Lock()
			quiet := !s.active
			s.active = false
			if quiet {
				_ = s.writePadLocked(16 + rand.IntN(81)) // 16–96
			}
			s.mu.Unlock()
			t.Reset(s.jitterIdle())
		}
	}
}

func (s *Shaper) jitterIdle() time.Duration {
	if s.idle <= 0 {
		return defaultIdlePad
	}
	return s.idle + time.Duration(rand.Int64N(int64(s.idle/2)+1))
}

// nextChunk is how many bytes the next DATA frame carries: a size drawn for
// the mode, capped at what is left and at MaxFrame.
func (s *Shaper) nextChunk(remaining int) int {
	var sz int
	switch s.mode {
	case PadOff:
		sz = MaxFrame
	case PadHeavy:
		sz = heavyChunk()
	default:
		sz = moderateChunk()
	}
	if sz > remaining {
		sz = remaining
	}
	if sz < 1 {
		sz = 1
	}
	return sz
}

// moderateChunk draws a DATA size for PadModerate: mostly large, but a real
// spread of medium and small, so the histogram is no longer a single spike at
// the maximum.
func moderateChunk() int {
	switch r := rand.IntN(100); {
	case r < 10:
		return 64 + rand.IntN(448) // 64–511
	case r < 35:
		return 1024 + rand.IntN(4977) // 1024–6000
	default:
		return 8000 + rand.IntN(MaxFrame-8000+1) // 8000–16384
	}
}

// heavyChunk draws a DATA size for PadHeavy: a larger mass of small records,
// closer to a browsing session, at the cost of more frames.
func heavyChunk() int {
	switch r := rand.IntN(100); {
	case r < 30:
		return 32 + rand.IntN(225) // 32–256
	case r < 65:
		return 256 + rand.IntN(2745) // 256–3000
	default:
		return 6000 + rand.IntN(MaxFrame-6000+1) // 6000–16384
	}
}

// inlinePad reports whether to slip a PAD frame in after a DATA frame.
func (s *Shaper) inlinePad() bool {
	switch s.mode {
	case PadHeavy:
		return rand.IntN(6) == 0
	case PadModerate:
		return rand.IntN(12) == 0
	default:
		return false
	}
}

func inlinePadSize(mode PadMode) int {
	if mode == PadHeavy {
		return 16 + rand.IntN(145) // 16–160
	}
	return 16 + rand.IntN(65) // 16–80
}

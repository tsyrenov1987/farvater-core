package mobile

import (
	"testing"
	"time"
)

// Off, nothing is refused; on, a burst is refused but one flow in each
// shedTrickle still gets in.
func TestPressedLetsATrickleIn(t *testing.T) {
	defer pressedOn.Store(false)
	pressedOn.Store(false)
	if pressed() {
		t.Fatal("not pressed, yet a flow was refused")
	}
	pressedOn.Store(true)
	lastLetIn.Store(0)
	shed0 := shedCount.Load()
	in := 0
	for range 100 {
		if !pressed() {
			in++
		}
	}
	if in != 1 || shedCount.Load()-shed0 != 99 {
		t.Fatalf("burst of 100 under pressure: %d let in, %d shed; want 1 and 99", in, shedCount.Load()-shed0)
	}
	time.Sleep(shedTrickle + 20*time.Millisecond)
	if pressed() {
		t.Fatal("after shedTrickle the next flow should get in")
	}
}

func resetBurst() {
	burstMu.Lock()
	burstStart, burstPrev, burstNow = time.Time{}, 0, 0
	burstMu.Unlock()
}

// A burst of flows is weighed at the door: under a line the memory cannot
// reach, all get in; under a line it is already past, the first burstFlows get
// in (an ordinary pace never reads the memory) and the rest only as the trickle.
func TestPressedWeighsABurstAtTheDoor(t *testing.T) {
	defer valveAt.Store(0)
	defer pressedOn.Store(false)
	defer resetBurst()
	pressedOn.Store(false)

	valveAt.Store(1 << 40)
	resetBurst()
	for i := range 200 {
		if pressed() {
			t.Fatalf("flow %d refused under a line memory cannot reach", i)
		}
	}

	valveAt.Store(1) // the runtime holds more than this
	resetBurst()
	lastLetIn.Store(time.Now().UnixMilli()) // trickle slot just used
	in := 0
	for range 100 {
		if !pressed() {
			in++
		}
	}
	if in != burstFlows {
		t.Fatalf("burst of 100 past the line: %d let in, want %d", in, burstFlows)
	}

	// Once the window has passed twice, the count starts over.
	burstMu.Lock()
	burstStart = time.Now().Add(-2 * burstWindow)
	burstMu.Unlock()
	if pressed() {
		t.Fatal("a flow after a quiet spell was refused")
	}
}

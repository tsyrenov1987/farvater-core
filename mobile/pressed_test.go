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

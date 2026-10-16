//go:build chaos

package switchboard

import "time"

// SetLabSleep tells the core the device sleeps for d from at, as the chaos
// lab stops the process to play an iPhone asleep: flows open at at count it as
// slept once it is over. Only the lab's build has it.
func SetLabSleep(at time.Time, d time.Duration) {
	labSleep = func(start, now time.Time) time.Duration {
		if start.Before(at) && now.Sub(at) >= d {
			return d
		}
		return 0
	}
}

//go:build chaos

package switchboard

import (
	"crypto/x509"
	"time"
)

// SetLabProbe makes sweeps verify the probe's certificate against roots, the
// lab's own. Only the lab's build has it.
func SetLabProbe(roots *x509.CertPool) { probeRoots = roots }

// SetLabTune changes the config of every switchboard made after it: the lab
// runs its scenarios under settings it compares. Only the lab's build has it.
func SetLabTune(f func(*Config)) { labTune = f }

// SetLabSleep tells the core the device sleeps for d from at, as the chaos
// lab stops the process to play an iPhone asleep: flows open at at count it as
// slept once it is over. Only the lab's build has it.
func SetLabSleep(at time.Time, d time.Duration) {
	f := func(start, now time.Time) time.Duration {
		if start.Before(at) && now.Sub(at) >= d {
			return d
		}
		return 0
	}
	labSleep.Store(&f)
}

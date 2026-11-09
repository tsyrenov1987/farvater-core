//go:build !darwin && !windows

package desktop

import (
	"errors"
	"net/netip"
)

// StateDir is unused off macOS and Windows.
const StateDir = ""

// System is not available on this OS.
type System struct{ *tunPackets }

// Up is not available on this OS.
func Up(Options) (*System, error) { return nil, errors.New("desktop: macOS and Windows only") }

// Down does nothing here.
func (s *System) Down() {}

// Off does nothing here.
func Off() error { return nil }

var _ = netip.Addr{}

// Package control is a clean-room stand-in for the socket-control helper API
// that Xray-core's transport layer references. farvater-core replaces the
// original module with this one so that no GPL/AGPL code is linked.
//
// Only the API surface actually referenced by the packages farvater-core
// imports is provided. Interface binding is not needed on the platforms this
// core targets (the host app protects sockets itself), so BindToInterface
// returns a no-op controller.
package control

import "syscall"

// Func is applied to a socket before connect/listen.
type Func = func(network, address string, conn syscall.RawConn) error

// Append chains two controllers; nil entries are skipped.
func Append(oldFunc, newFunc Func) Func {
	if oldFunc == nil {
		return newFunc
	}
	if newFunc == nil {
		return oldFunc
	}
	return func(network, address string, conn syscall.RawConn) error {
		if err := oldFunc(network, address, conn); err != nil {
			return err
		}
		return newFunc(network, address, conn)
	}
}

// Raw runs block with the raw file descriptor of conn.
func Raw(conn syscall.RawConn, block func(fd uintptr) error) error {
	var inner error
	if err := conn.Control(func(fd uintptr) { inner = block(fd) }); err != nil {
		return err
	}
	return inner
}

// InterfaceFinder resolves interface names to indexes.
type InterfaceFinder interface {
	Update() error
	InterfaceIndexByName(name string) (int, error)
}

// DefaultInterfaceFinder is a finder with no interfaces.
type DefaultInterfaceFinder struct{}

// NewDefaultInterfaceFinder returns an empty finder.
func NewDefaultInterfaceFinder() *DefaultInterfaceFinder { return &DefaultInterfaceFinder{} }

// Update does nothing.
func (f *DefaultInterfaceFinder) Update() error { return nil }

// InterfaceIndexByName reports that the interface is unknown.
func (f *DefaultInterfaceFinder) InterfaceIndexByName(string) (int, error) {
	return 0, syscall.ENODEV
}

// BindToInterface returns a controller that does nothing: socket protection is
// the host application's job on iOS/Android, and the CLI runs without binding.
func BindToInterface(InterfaceFinder, string, int) Func {
	return func(string, string, syscall.RawConn) error { return nil }
}

//go:build windows && windowslive

package main

import (
	"testing"

	"golang.org/x/sys/windows"
)

func TestLiveHoldConsole(t *testing.T) {
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("AllocConsole")
	_, _, _ = proc.Call()
	name, _ := windows.UTF16PtrFromString("CONIN$")
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetStdHandle(windows.STD_INPUT_HANDLE, h); err != nil {
		t.Fatal(err)
	}
	mode := func() uint32 {
		var m uint32
		if err := windows.GetConsoleMode(h, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	if err := windows.SetConsoleMode(h, mode()|windows.ENABLE_QUICK_EDIT_MODE|windows.ENABLE_EXTENDED_FLAGS); err != nil {
		t.Fatal(err)
	}
	before := mode()
	t.Logf("before %#x", before)
	release := holdConsole()
	if m := mode(); m&windows.ENABLE_QUICK_EDIT_MODE != 0 {
		t.Errorf("QuickEdit still on: %#x", m)
	}
	release()
	if m := mode(); m&windows.ENABLE_QUICK_EDIT_MODE == 0 {
		t.Errorf("QuickEdit not restored: %#x", m)
	}
}

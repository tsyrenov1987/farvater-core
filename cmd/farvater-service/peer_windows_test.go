//go:build windows

package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/ipc/namedpipe"
)

func TestJudge(t *testing.T) {
	const w = `C:\Program Files\Farvater\Farvater.exe`
	for _, c := range []struct {
		window, image string
		admin, ok     bool
	}{
		{w, `C:\Program Files\Farvater\Farvater.exe`, false, true},
		{w, `c:\program files\farvater\FARVATER.EXE`, false, true},
		{w, `C:\Users\anna\Farvater.exe`, false, false},
		{w, `C:\Program Files\Farvater\app\Farvater.exe`, false, false},
		{w, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, false, false},
		{w, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, true, true},
		{"", `C:\Users\anna\Farvater\Farvater.exe`, false, false},
		{"", `C:\Users\anna\Farvater\Farvater.exe`, true, true},
	} {
		if _, ok := judge(c.window, c.image, c.admin); ok != c.ok {
			t.Errorf("%q %q admin=%v: %v", c.window, c.image, c.admin, ok)
		}
	}
}

func TestWithin(t *testing.T) {
	for _, c := range []struct {
		dir, root string
		ok        bool
	}{
		{`C:\Program Files\Farvater`, `C:\Program Files`, true},
		{`c:\program files\Farvater`, `C:\Program Files\`, true},
		{`C:\Program Files (x86)\Farvater`, `C:\Program Files`, false},
		{`C:\Program FilesX\Farvater`, `C:\Program Files`, false},
		{`C:\Users\anna\Farvater`, `C:\Program Files`, false},
	} {
		if within(c.dir, c.root) != c.ok {
			t.Errorf("%q in %q", c.dir, c.root)
		}
	}
}

// The pipe names the process on its other end: this test, from both sides.
func TestClientOfPipe(t *testing.T) {
	path := fmt.Sprintf(`\\.\pipe\farvater-test-%d`, os.Getpid())
	l, err := (&namedpipe.ListenConfig{}).Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := namedpipe.DialTimeout(path, 5*time.Second); err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	pid, image, admin, err := client(c)
	if err != nil {
		t.Fatal(err)
	}
	exe, _ := os.Executable()
	if int(pid) != os.Getpid() || !strings.EqualFold(image, exe) {
		t.Fatalf("pid %d %s, want %d %s", pid, image, os.Getpid(), exe)
	}
	t.Logf("admin: %v", admin)
	var lines []string
	ps := &peers{window: `C:\Program Files\Farvater\Farvater.exe`, said: map[uint32]string{}, logf: func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) }}
	if got := ps.admit(c); got != admin {
		t.Fatalf("admit %v, admin %v", got, admin)
	}
	ps.admit(c)
	if len(lines) != 1 {
		t.Fatalf("log: %q", lines)
	}
}

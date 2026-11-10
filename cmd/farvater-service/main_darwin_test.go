//go:build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppBundle(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/Farvater.app/Contents/MacOS/farvater-service":     "/Applications/Farvater.app",
		"/Volumes/Farvater/Farvater.app/Contents/MacOS/farvater-service": "/Volumes/Farvater/Farvater.app",
		"/Library/PrivilegedHelperTools/app.farvater.daemon":             "",
	} {
		if got := appBundle(exe); got != want {
			t.Errorf("%s: %q", exe, got)
		}
	}
}

func TestInstalledApp(t *testing.T) {
	for app, want := range map[string]bool{
		"/Applications/Farvater.app":                                 true,
		"/Users/anna/Applications/Farvater.app":                      true,
		"/Volumes/Farvater/Farvater.app":                             false,
		"/Users/anna/Downloads/Farvater.app":                         false,
		"/private/var/folders/x/AppTranslocation/ABC/d/Farvater.app": false,
		"/Applications/x/AppTranslocation/Farvater.app":              false,
		"": false,
	} {
		if got := installedApp(app); got != want {
			t.Errorf("%s: %v", app, got)
		}
	}
}

func TestAllowedUID(t *testing.T) {
	for uid, want := range map[uint32]bool{0: true, 1: false, 88: false, 500: false, 501: true, 502: true, 1000001: true, 4294967294: false} {
		if allowedUID(uid) != want {
			t.Errorf("uid %d", uid)
		}
	}
}

func TestPlistIsValid(t *testing.T) {
	cmd := exec.Command("plutil", "-lint", "-")
	cmd.Stdin = strings.NewReader(plist())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

// macOS 27 refuses to start a plain program whose path ends in a bundle
// extension such as ".service".
func TestHelperPathIsNoBundle(t *testing.T) {
	for _, ext := range []string{".service", ".app", ".bundle", ".plugin", ".framework", ".kext", ".appex", ".xpc"} {
		if strings.HasSuffix(helperPath, ext) {
			t.Fatalf("%s ends in %s", helperPath, ext)
		}
	}
	if !strings.Contains(plist(), "<string>"+helperPath+"</string>") {
		t.Fatal("the plist does not start helperPath")
	}
}

// The kernel names the other end of the socket; a program that is not the
// signed window (this test is not) gets nothing.
func TestPeerIsCheckedBySignature(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "fvpeer") // a socket path has to be short
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	l, err := net.Listen("unix", filepath.Join(dir, "s"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		if c, err := net.Dial("unix", filepath.Join(dir, "s")); err == nil {
			time.Sleep(2 * time.Second)
			c.Close()
		}
	}()
	c, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p, err := peerOf(c)
	if err != nil {
		t.Fatal(err)
	}
	if int(p.pid) != os.Getpid() || int(p.uid) != os.Geteuid() {
		t.Fatalf("peer pid %d uid %d, want %d %d", p.pid, p.uid, os.Getpid(), os.Geteuid())
	}
	if st := p.signedAs(windowReq); st == 0 {
		t.Fatal("the test binary passed for the window")
	}
	if st := p.signedAs("never"); st == 0 {
		t.Fatal("never passed")
	}
	var lines []string
	ps := newPeers(func(f string, a ...any) { lines = append(lines, fmt.Sprintf(f, a...)) })
	if os.Geteuid() != 0 {
		if ps.admit(c) || ps.admit(c) {
			t.Fatal("a program that is not the window was let in")
		}
		if len(lines) != 1 || !strings.Contains(lines[0], "refused") {
			t.Fatalf("log: %q", lines)
		}
	}
	t.Logf("%s", pidPath(p.pid))
}

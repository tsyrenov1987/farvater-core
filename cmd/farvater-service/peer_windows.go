//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// peers lets in the window, Farvater.exe from the folder this service was
// installed to, and administrators. The folder is in Program Files, where
// only administrators write, so no other program can be put there under that
// name; installed anywhere else, only administrators get answers.
type peers struct {
	window string // "" outside Program Files
	logf   func(string, ...any)
	mu     sync.Mutex
	said   map[uint32]string // what the log already has, by process
}

func newPeers(logf func(string, ...any)) *peers {
	p := &peers{logf: logf, said: map[uint32]string{}}
	exe, err := os.Executable()
	if err != nil {
		logf("own path: %v: only administrators get answers", err)
		return p
	}
	dir := filepath.Dir(exe)
	if !protectedDir(dir) {
		logf("installed in %s, outside Program Files: only administrators get answers", dir)
		return p
	}
	p.window = filepath.Join(dir, "Farvater.exe")
	return p
}

func protectedDir(dir string) bool {
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		if root, err := windows.KnownFolderPath(id, 0); err == nil && root != "" && within(dir, root) {
			return true
		}
	}
	return false
}

// within: dir is root or a folder inside it.
func within(dir, root string) bool {
	d, r := strings.ToLower(filepath.Clean(dir)), strings.ToLower(filepath.Clean(root))
	return d == r || strings.HasPrefix(d, strings.TrimSuffix(r, `\`)+`\`)
}

// judge decides by the program's path and its rights.
func judge(window, image string, admin bool) (string, bool) {
	if window != "" && strings.EqualFold(filepath.Clean(image), window) {
		return "the window", true
	}
	if admin {
		return "an administrator", true
	}
	return "refused", false
}

// client: the process on the other end of the pipe, its program and whether it
// runs with administrator rights.
func client(c net.Conn) (pid uint32, image string, admin bool, err error) {
	h, ok := c.(interface{ Handle() windows.Handle })
	if !ok {
		return 0, "", false, fmt.Errorf("%T is not a pipe", c)
	}
	if err := windows.GetNamedPipeClientProcessId(h.Handle(), &pid); err != nil {
		return 0, "", false, err
	}
	p, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return pid, "", false, err
	}
	defer windows.CloseHandle(p)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(p, 0, &buf[0], &n); err != nil {
		return pid, "", false, err
	}
	image = windows.UTF16ToString(buf[:n])
	var t windows.Token
	if windows.OpenProcessToken(p, windows.TOKEN_QUERY, &t) == nil {
		admin = t.IsElevated()
		t.Close()
	}
	return pid, image, admin, nil
}

func (ps *peers) admit(c net.Conn) bool {
	pid, image, admin, err := client(c)
	who, ok := "refused", false
	if err == nil {
		who, ok = judge(ps.window, image, admin)
	} else {
		image = err.Error()
	}
	line := who + ", " + image
	ps.mu.Lock()
	if ps.said[pid] != line {
		if len(ps.said) > 256 {
			clear(ps.said)
		}
		ps.said[pid] = line
		ps.logf("pid %d: %s", pid, line)
	}
	ps.mu.Unlock()
	return ok
}

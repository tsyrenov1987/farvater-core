//go:build darwin

package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <Security/Security.h>

// fv_peer: who is on the other end of a local socket, as the kernel knows it.
static int fv_peer(int fd, audit_token_t *tok, int *pid, int *ver, unsigned *uid) {
	socklen_t n = sizeof *tok;
	if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, tok, &n) != 0 || n != sizeof *tok) return -1;
	*pid = audit_token_to_pid(*tok);
	*ver = audit_token_to_pidversion(*tok);
	*uid = audit_token_to_euid(*tok);
	return 0;
}

// fv_signed: the process is the code the requirement names, running as
// signed, and the files of its bundle on disk are the signed ones too.
static OSStatus fv_signed(audit_token_t *tok, const char *text) {
	SecRequirementRef req = NULL;
	SecCodeRef code = NULL;
	SecStaticCodeRef disk = NULL;
	CFStringRef rs = CFStringCreateWithCString(NULL, text, kCFStringEncodingUTF8);
	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)tok, sizeof *tok);
	const void *k[] = {kSecGuestAttributeAudit};
	const void *v[] = {data};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus s = SecRequirementCreateWithString(rs, kSecCSDefaultFlags, &req);
	if (s == errSecSuccess) s = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	if (s == errSecSuccess) s = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
	if (s == errSecSuccess) s = SecCodeCopyStaticCode(code, kSecCSDefaultFlags, &disk);
	if (s == errSecSuccess) s = SecStaticCodeCheckValidity(disk, kSecCSCheckNestedCode | kSecCSStrictValidate, req);
	if (disk) CFRelease(disk);
	if (code) CFRelease(code);
	if (req) CFRelease(req);
	CFRelease(attrs);
	CFRelease(data);
	CFRelease(rs);
	return s;
}

static int fv_path(int pid, char *buf, unsigned n) {
	return proc_pidpath(pid, buf, n);
}
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unsafe"

	"github.com/tsyrenov1987/farvater-core/desktop"
)

// windowReq names the window: Farvater as its developer signed it. The
// app in /Applications is the person's to change, so the check is of the
// signature, not of where the program lies.
const windowReq = `anchor apple generic and certificate leaf[subject.OU] = "643UT34CF8" and identifier "app.farvater.desktop"`

// reqFile, when there is one, names the window instead. Only root can
// write it (lockDir keeps the folder to root); the tests of unsigned builds
// put one there.
var reqFile = filepath.Join(desktop.StateDir, "window-requirement")

type peer struct {
	tok      C.audit_token_t
	pid, ver int32
	uid      uint32
}

// peerOf reads the other end of c from the kernel; a process that has gone
// since it connected is not one.
func peerOf(c net.Conn) (peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peer{}, fmt.Errorf("%T is not a local socket", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer{}, err
	}
	var (
		p        peer
		pid, ver C.int
		uid      C.uint
		rc       C.int = -1
	)
	if err := raw.Control(func(fd uintptr) { rc = C.fv_peer(C.int(fd), &p.tok, &pid, &ver, &uid) }); err != nil {
		return peer{}, err
	}
	if rc != 0 {
		return peer{}, fmt.Errorf("no peer token")
	}
	p.pid, p.ver, p.uid = int32(pid), int32(ver), uint32(uid)
	return p, nil
}

// signedAs is 0 when p is the code req names, else the Security framework's status.
func (p *peer) signedAs(req string) int {
	cs := C.CString(req)
	defer C.free(unsafe.Pointer(cs))
	return int(C.fv_signed(&p.tok, cs))
}

func pidPath(pid int32) string {
	buf := make([]byte, 4096)
	n := C.fv_path(C.int(pid), (*C.char)(unsafe.Pointer(&buf[0])), C.uint(len(buf)))
	if n <= 0 {
		return "?"
	}
	return string(buf[:n])
}

// peers decides once per process (pid and its version, which the kernel
// never gives twice) and says in the log whom it let in and whom not.
type peers struct {
	logf func(string, ...any)
	mu   sync.Mutex
	seen map[[2]int32]bool
}

func newPeers(logf func(string, ...any)) *peers {
	return &peers{logf: logf, seen: map[[2]int32]bool{}}
}

func (ps *peers) admit(c net.Conn) bool {
	p, err := peerOf(c)
	if err != nil {
		return false
	}
	if p.uid == 0 {
		return true // root reads the state folder anyway
	}
	key := [2]int32{p.pid, p.ver}
	ps.mu.Lock()
	ok, known := ps.seen[key]
	ps.mu.Unlock()
	if known {
		return ok
	}
	req := windowReq
	if b, err := os.ReadFile(reqFile); err == nil && strings.TrimSpace(string(b)) != "" {
		req = strings.TrimSpace(string(b))
	}
	st := 0
	if !allowedUID(p.uid) {
		st = -1
	} else {
		st = p.signedAs(req)
	}
	ok = st == 0
	if ok {
		ps.logf("pid %d (uid %d): the window, %s", p.pid, p.uid, pidPath(p.pid))
	} else {
		ps.logf("pid %d (uid %d): refused (%d), %s", p.pid, p.uid, st, pidPath(p.pid))
	}
	ps.mu.Lock()
	if len(ps.seen) > 256 {
		clear(ps.seen)
	}
	ps.seen[key] = ok
	ps.mu.Unlock()
	return ok
}

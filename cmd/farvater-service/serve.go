//go:build windows || darwin

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/service"
)

const (
	maxRequest = 1 << 20
	logLimit   = 2 << 20
)

func serve(l net.Listener, s *service.Session, logf func(string, ...any)) {
	for {
		c, err := l.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			logf("accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go answer(c, s)
	}
}

// answer takes one request and gives one reply. The window closes first: a
// pipe closed on this side can lose what the window has not read yet.
func answer(c net.Conn, s *service.Session) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(io.LimitReader(c, maxRequest)).ReadBytes('\n')
	if err != nil {
		return
	}
	_ = c.SetDeadline(time.Time{}) // import takes as long as a fetch does
	reply := append(s.Handle(line), '\n')
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(reply); err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, c)
}

// openLog keeps what happened next to the state, in a bounded size.
func openLog() func(string, ...any) {
	path := filepath.Join(desktop.StateDir, "service.log")
	_ = os.MkdirAll(desktop.StateDir, 0o700)
	var (
		mu sync.Mutex
		f  *os.File
		n  int64
	)
	open := func() {
		if f != nil {
			f.Close()
		}
		f, _ = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		n = 0
		if f != nil {
			if fi, err := f.Stat(); err == nil {
				n = fi.Size()
			}
		}
	}
	open()
	return func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		if n > logLimit {
			if f != nil {
				f.Close()
				f = nil
			}
			_ = os.Rename(path, path+".old")
			open()
		}
		if f == nil {
			return
		}
		line := time.Now().Format("2006-01-02 15:04:05 ") + fmt.Sprintf(format, a...) + "\n"
		w, _ := f.WriteString(line)
		n += int64(w)
	}
}

// Command farvater-service is the part of Farvater for Windows that has the
// machine's rights. The installer registers it once, with the one UAC prompt
// there is; from then on the window starts like any program and asks this
// service over a named pipe.
//
//	farvater-service install     (register and start; updates an existing one)
//	farvater-service uninstall
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.zx2c4.com/wireguard/ipc/namedpipe"

	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/service"
)

const (
	serviceName = "Farvater"
	description = "Держит соединение Farvater, чтобы приложению не нужны были права администратора."
	pipePath    = `\\.\pipe\farvater`

	// The machine owns the pipe; whoever sits at this computer, on its screen
	// or over Remote Desktop, may talk to it. Other computers cannot
	// (namedpipe refuses remote clients), nor can programs of other sessions'
	// services or the network account.
	pipeSDDL = "O:SYG:SYD:(A;;GA;;;SY)(A;;GRGW;;;IU)"

	// The folder holds the access code: the machine and administrators only.
	dirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	maxRequest = 1 << 20
	logLimit   = 2 << 20
)

func main() {
	isService, err := svc.IsWindowsService()
	if err != nil {
		log.Fatal(err)
	}
	if isService {
		if err := svc.Run(serviceName, handler{}); err != nil {
			os.Exit(1)
		}
		return
	}
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	switch cmd {
	case "install":
		err = install()
	case "uninstall":
		err = uninstall()
	case "version":
		fmt.Println(service.Version)
	default:
		fmt.Fprintln(os.Stderr, "usage: farvater-service install | uninstall | version")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func install() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err == nil {
		defer s.Close()
		if err := stop(s); err != nil {
			return err
		}
		c, err := s.Config()
		if err != nil {
			return err
		}
		c.BinaryPathName = `"` + exe + `"`
		c.StartType = mgr.StartAutomatic
		c.DisplayName, c.Description = serviceName, description
		if err := s.UpdateConfig(c); err != nil {
			return err
		}
	} else {
		s, err = m.CreateService(serviceName, exe, mgr.Config{
			DisplayName: serviceName,
			Description: description,
			StartType:   mgr.StartAutomatic,
		})
		if err != nil {
			return err
		}
		defer s.Close()
	}
	// A crash leaves the person's internet alone (nothing is cut off without
	// the tunnel's DNS rule, which the next start removes); come back quickly.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 2 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 3600); err != nil {
		return err
	}
	return s.Start()
}

func uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // nothing to remove
	}
	defer s.Close()
	if err := stop(s); err != nil {
		return err
	}
	if err := s.Delete(); err != nil {
		return err
	}
	return desktop.Off()
}

// stop waits for the service to end; the installer replaces its files next.
func stop(s *mgr.Service) error {
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if st.State != svc.StopPending {
		if _, err := s.Control(svc.Stop); err != nil {
			return err
		}
	}
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if st, err := s.Query(); err != nil || st.State == svc.Stopped {
			return err
		}
	}
	return errors.New("the service did not stop in 30 s")
}

type handler struct{}

func (handler) Execute(_ []string, r <-chan svc.ChangeRequest, st chan<- svc.Status) (bool, uint32) {
	st <- svc.Status{State: svc.StartPending}
	logf := openLog()
	if err := lockDir(); err != nil {
		logf("state folder: %v", err) // the folder is the access code's only guard
		return true, 1
	}
	if err := desktop.Off(); err != nil && !os.IsNotExist(err) {
		logf("clean up after the last run: %v", err)
	}
	s := service.New(desktop.StateDir, service.RealHooks(), logf)
	l, err := listen()
	if err != nil {
		logf("pipe: %v", err)
		return true, 2
	}
	go serve(l, s, logf)
	logf("started, version %s", service.Version)
	s.Resume()
	st <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			st <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			st <- svc.Status{State: svc.StopPending}
			_ = l.Close()
			s.Close(c.Cmd == svc.Shutdown)
			logf("stopped")
			return false, 0
		}
	}
	return false, 0
}

func lockDir() error {
	if err := os.MkdirAll(desktop.StateDir, 0o700); err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString(dirSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(desktop.StateDir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

func listen() (net.Listener, error) {
	sd, err := windows.SecurityDescriptorFromString(pipeSDDL)
	if err != nil {
		return nil, err
	}
	return (&namedpipe.ListenConfig{SecurityDescriptor: sd}).Listen(pipePath)
}

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

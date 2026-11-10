// Command farvater-service is the part of Farvater for macOS that has the
// machine's rights: a launchd daemon. The app installs it once, with the one
// password prompt there is; from then on the window starts like any program
// and asks this service over a socket.
//
//	farvater-service install     (as root: copy itself out of the app, register, start; updates an existing one)
//	farvater-service uninstall   (as root)
//	farvater-service run         (what launchd starts)
//	farvater-service version
package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tsyrenov1987/farvater-core/desktop"
	"github.com/tsyrenov1987/farvater-core/service"
)

const (
	label    = "app.farvater.service"
	bundleID = "app.farvater.desktop"
	// helperPath must not end in ".service": macOS 27 takes such a path for
	// a Services bundle and Gatekeeper kills every start of the plain
	// program there (OS_REASON_EXEC, "Failed to register app bundle for
	// protection: 45"). The first macOS builds put it at oldHelperPath.
	helperPath    = "/Library/PrivilegedHelperTools/app.farvater.daemon"
	oldHelperPath = "/Library/PrivilegedHelperTools/" + label
	plistPath     = "/Library/LaunchDaemons/" + label + ".plist"
	sockPath      = "/var/run/farvater.sock"
)

var (
	// appFile holds where the app was installed from; when it is gone (the
	// app went to the Trash), so is the service.
	appFile = filepath.Join(desktop.StateDir, "app")
	// restartMark tells the stopping service it is being replaced, not the
	// machine shut down: the connection the person had stays wanted.
	restartMark = filepath.Join(desktop.StateDir, "restarting")
)

func main() {
	cmd := ""
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "run":
		err = runDaemon()
	case "install":
		err = install()
	case "uninstall":
		err = uninstall()
	case "version":
		fmt.Println(service.Version)
	default:
		fmt.Fprintln(os.Stderr, "usage: farvater-service install | uninstall | run | version")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDaemon() error {
	logf := openLog()
	if err := lockDir(); err != nil {
		logf("state folder: %v", err) // the folder is the access code's only guard
		return err
	}
	if err := desktop.Off(); err != nil {
		logf("clean up after the last run: %v", err)
	}
	s := service.New(desktop.StateDir, service.RealHooks(), logf)
	l, err := listen()
	if err != nil {
		logf("socket: %v", err)
		return err
	}
	go serve(l, s, newPeers(logf).admit, logf)
	logf("started, version %s", service.Version)
	s.Resume()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	gone := make(chan struct{})
	go watchApp(gone)
	select {
	case <-sig:
		replaced := os.Remove(restartMark) == nil
		_ = l.Close()
		s.Close(!replaced)
		logf("stopped")
	case <-gone:
		logf("the app is gone: removing the service")
		_ = l.Close()
		s.Close(true)
		removeAll()
		// launchd would start the program again (KeepAlive); bootout stops
		// it for good, with a SIGTERM to this process.
		_ = exec.Command("/bin/launchctl", "bootout", "system/"+label).Start()
		select {
		case <-sig:
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

// lockDir keeps the state, the access code among it, to root.
func lockDir() error {
	if err := os.MkdirAll(desktop.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(desktop.StateDir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(desktop.StateDir, 0o700)
}

func listen() (net.Listener, error) {
	_ = os.Remove(sockPath)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sockPath, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	return l, nil
}

// allowedUID: the people of this Mac, root and the user accounts, not the
// accounts the system's own daemons run as (uid 1-500, nobody).
func allowedUID(uid uint32) bool {
	return uid == 0 || (uid >= 501 && uid < 1<<31)
}

// watchApp closes gone when the app the service came from has been missing
// for two checks in a row (a Finder copy over an old version is not that).
func watchApp(gone chan<- struct{}) {
	b, err := os.ReadFile(appFile)
	app := strings.TrimSpace(string(b))
	if err != nil || app == "" {
		return
	}
	missing := 0
	for range time.Tick(time.Minute) {
		if _, err := os.Stat(app); err == nil {
			missing = 0
			continue
		}
		if missing++; missing >= 2 {
			close(gone)
			return
		}
	}
}

func install() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := lockDir(); err != nil {
		return err
	}
	if loaded() {
		_ = os.WriteFile(restartMark, nil, 0o600)
		if err := stop(); err != nil {
			return err
		}
	}
	_ = os.Remove(restartMark) // the old service did not take it: nobody is to
	if exe != helperPath {
		if err := copyFile(exe, helperPath); err != nil {
			return err
		}
	}
	_ = os.Remove(oldHelperPath)
	if app := appBundle(exe); installedApp(app) {
		if err := os.WriteFile(appFile, []byte(app+"\n"), 0o600); err != nil {
			return err
		}
	} else {
		// From the disk image or Downloads: nothing to watch that would not
		// vanish on its own.
		_ = os.Remove(appFile)
	}
	if err := os.WriteFile(plistPath, []byte(plist()), 0o644); err != nil {
		return err
	}
	if out, err := exec.Command("/bin/launchctl", "bootstrap", "system", plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap: %v %s", err, strings.TrimSpace(string(out)))
	}
	for end := time.Now().Add(15 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if c, err := net.Dial("unix", sockPath); err == nil {
			c.Close()
			return nil
		}
	}
	return errors.New("the service did not start in 15 s")
}

func uninstall() error {
	if os.Geteuid() != 0 {
		return errors.New("run as root")
	}
	if loaded() {
		if err := stop(); err != nil {
			return err
		}
	}
	removeAll()
	return nil
}

// removeAll takes away everything the service put on the machine.
func removeAll() {
	_ = desktop.Off()
	_ = os.Remove(plistPath)
	_ = os.Remove(helperPath)
	_ = os.Remove(oldHelperPath)
	_ = os.Remove(sockPath)
	_ = os.RemoveAll(desktop.StateDir)
}

func loaded() bool {
	return exec.Command("/bin/launchctl", "print", "system/"+label).Run() == nil
}

// stop takes the service out of launchd and waits for it to end: it puts
// the machine's network back as it goes.
func stop() error {
	out, err := exec.Command("/bin/launchctl", "bootout", "system/"+label).CombinedOutput()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
		if !loaded() {
			return nil
		}
	}
	return fmt.Errorf("the service did not stop in 30 s: %v %s", err, strings.TrimSpace(string(out)))
}

// copyFile puts the program where launchd runs it from, whole: a new file
// renamed over the old, which a running copy keeps until it ends.
func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		return err
	}
	tmp := to + ".new"
	if err := os.WriteFile(tmp, b, 0o755); err != nil {
		return err
	}
	if err := os.Chown(tmp, 0, 0); err != nil {
		return err
	}
	return os.Rename(tmp, to)
}

// appBundle is the .app the program sits in, "" when it is not in one.
func appBundle(exe string) string {
	i := strings.Index(exe, ".app/Contents/")
	if i < 0 {
		return ""
	}
	return exe[:i+len(".app")]
}

// installedApp: an app in /Applications or a user's ~/Applications. Run
// from the disk image or a translocated copy, its path does not last.
func installedApp(app string) bool {
	if app == "" || strings.Contains(app, "/AppTranslocation/") {
		return false
	}
	if strings.HasPrefix(app, "/Applications/") {
		return true
	}
	parts := strings.Split(app, "/")
	return len(parts) > 4 && parts[1] == "Users" && parts[3] == "Applications"
}

func plist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + label + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + helperPath + `</string>
		<string>run</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>ExitTimeOut</key>
	<integer>30</integer>
	<key>StandardErrorPath</key>
	<string>` + filepath.Join(desktop.StateDir, "service.err") + `</string>
	<key>AssociatedBundleIdentifiers</key>
	<array>
		<string>` + bundleID + `</string>
	</array>
</dict>
</plist>
`
}

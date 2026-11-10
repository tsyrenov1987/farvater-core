//go:build darwin

package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestAppBundle(t *testing.T) {
	for exe, want := range map[string]string{
		"/Applications/Farvater.app/Contents/MacOS/farvater-service":     "/Applications/Farvater.app",
		"/Volumes/Farvater/Farvater.app/Contents/MacOS/farvater-service": "/Volumes/Farvater/Farvater.app",
		"/Library/PrivilegedHelperTools/app.farvater.service":            "",
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

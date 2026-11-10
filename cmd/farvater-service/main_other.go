//go:build !windows && !darwin

// Command farvater-service holds the tunnel on Windows and macOS; elsewhere there is
// nothing for it to do.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "farvater-service runs on Windows and macOS only")
	os.Exit(1)
}

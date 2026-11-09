//go:build !windows

// Command farvater-service holds the tunnel on Windows; elsewhere there is
// nothing for it to do.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "farvater-service runs on Windows only")
	os.Exit(1)
}

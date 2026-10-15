//go:build chaos

package wire

import "crypto/x509"

// SetLabRoots makes paths verify their certificates against roots instead of
// the system's: the chaos lab's self-signed paths, kilvater among them, which
// takes no insecure certificate. Only the lab's build has it.
func SetLabRoots(roots *x509.CertPool) { labRoots = roots }

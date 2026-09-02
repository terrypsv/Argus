//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/terrypsv/Argus/internal/engine"
	"github.com/terrypsv/Argus/internal/model"
)

// Debian and Red Hat both reserve a directory for administrator-added anchors,
// which gives a clean separation the check can rely on: anything found there was
// put there deliberately by someone on this machine.
var (
	vendorBundles = []string{
		"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Kali, Arch
		"/etc/pki/tls/certs/ca-bundle.crt",   // Red Hat, Fedora
		"/etc/ssl/cert.pem",                  // Alpine
	}
	localAnchorDirs = []string{
		"/usr/local/share/ca-certificates", // Debian family
		"/etc/pki/ca-trust/source/anchors", // Red Hat family
	}
)

func certStoreCheck(ctx *engine.Context) []model.Finding {
	var all []certInfo

	for _, bundle := range vendorBundles {
		if !fileExists(bundle) {
			continue
		}
		all = append(all, parsePEMCerts(readFile(bundle), false)...)
		break // the first bundle found is this distribution's store
	}

	for _, dir := range localAnchorDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			if !strings.HasSuffix(name, ".crt") && !strings.HasSuffix(name, ".pem") {
				continue
			}
			all = append(all, parsePEMCerts(readFile(filepath.Join(dir, e.Name())), true)...)
		}
	}

	return rootStoreFindings(all, "distribution bundle plus local anchors")
}

//go:build !windows && !darwin

package checks

// canVerifySignatures reports false. A Linux binary carries no per-file
// signature the system can verify on its own: it is the distribution's
// published digests that play this role, through --verify-packages.
//
// That option is not triggered automatically here. It walks every installed
// package, which turns a quick scan into a multi-minute one; doing so without
// being asked would surprise whoever launched the scan. The remediation names
// it instead.
func canVerifySignatures() bool { return false }

func verifySignatures(paths []string) (map[string]string, bool) { return nil, false }

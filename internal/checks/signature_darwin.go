//go:build darwin

package checks

import "strings"

// canVerifySignatures reports whether codesign is available to answer for a
// file's publisher.
func canVerifySignatures() bool { return cmdAvailable("codesign") }

// verifySignatures checks one file at a time, codesign taking a single path and
// offering no batch form. The integrity baseline holds about a dozen files, so
// the cost stays negligible; it would not on an arbitrary list.
//
// The second return value says whether the verification ran at all. Here it
// follows the availability of codesign, checked before any call.
func verifySignatures(paths []string) (map[string]string, bool) {
	if !cmdAvailable("codesign") {
		return nil, false
	}
	res := map[string]string{}
	for _, p := range paths {
		if authority, valid := signedBy(p); valid {
			res[strings.ToLower(p)] = authority
		}
	}
	return res, true
}

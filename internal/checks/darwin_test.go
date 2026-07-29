//go:build darwin

package checks

import (
	"strings"
	"testing"
)

const vmwarePlist = `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>com.vmware.launchd.tools</string>
	<key>ProgramArguments</key>
	<array>
		<string>/Library/Application Support/VMware Tools/vmware-tools-daemon</string>
		<string>--kvp</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
</dict>
</plist>`

func TestProgramOf(t *testing.T) {
	if got := programOf(vmwarePlist); got != "/Library/Application Support/VMware Tools/vmware-tools-daemon" {
		t.Errorf("programOf = %q, want the first ProgramArguments entry", got)
	}

	withProgram := `<dict>
	<key>Program</key>
	<string>/usr/local/bin/agent</string>
	<key>ProgramArguments</key>
	<array><string>/autre/chemin</string></array>
</dict>`
	if got := programOf(withProgram); got != "/usr/local/bin/agent" {
		t.Errorf("programOf = %q, want the Program key to win", got)
	}

	if got := programOf("<dict><key>Label</key><string>x</string></dict>"); got != "" {
		t.Errorf("programOf = %q, want empty when no program is declared", got)
	}
}

// A pattern match must name itself in the report. Without this, diagnosing a
// false positive means reading the source.
func TestMatchedTokenNamesThePattern(t *testing.T) {
	if got := matchedToken("<string>/tmp/payload</string>"); got != "/tmp/" {
		t.Errorf("matchedToken = %q, want %q", got, "/tmp/")
	}
	if got := matchedToken("<string>curl http://exemple</string>"); got != "curl " {
		t.Errorf("matchedToken = %q, want %q", got, "curl ")
	}
	if got := matchedToken("<string>/usr/bin/true</string>"); got != "" {
		t.Errorf("matchedToken = %q, want empty for a benign item", got)
	}
}

// An absent or unreadable program cannot be vouched for, so it must never be
// reported as validly signed.
func TestSignedByRejectsMissingProgram(t *testing.T) {
	if _, valid := signedBy(""); valid {
		t.Error("an empty program path must not be reported as signed")
	}
	if _, valid := signedBy("/chemin/qui/nexiste/pas"); valid {
		t.Error("a missing program must not be reported as signed")
	}
}

// Sanity check against the real system: Apple's own binaries verify.
func TestSignedByAcceptsASystemBinary(t *testing.T) {
	if !cmdAvailable("codesign") {
		t.Skip("codesign unavailable")
	}
	authority, valid := signedBy("/bin/ls")
	if !valid {
		t.Error("/bin/ls should carry a valid signature on macOS")
	}
	if authority == "" {
		t.Error("a valid signature should report an authority")
	}
	// Locks the bug this test failed to catch: codesign only prints the
	// certificate chain at verbosity 2, so a single -v silently produced the
	// placeholder instead of the real signer.
	if strings.Contains(authority, "not reported") {
		t.Errorf("the signing authority was not extracted, got %q", authority)
	}
}

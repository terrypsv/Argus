//go:build darwin

package checks

import "testing"

// The format here is the one macOS actually prints. Two traits break naive
// parsing: paths contain spaces, and some processes are reported by bare name.
func TestParsePSLine(t *testing.T) {
	cases := []struct {
		name           string
		line           string
		ok             bool
		pid, user, cmd string
	}{
		{
			name: "ordinary system daemon",
			line: "   96 root             /usr/libexec/logd",
			ok:   true, pid: "96", user: "root", cmd: "/usr/libexec/logd",
		},
		{
			// The case field splitting gets wrong.
			name: "path containing spaces",
			line: "  512 root             /Library/Application Support/VMware Tools/vmware-tools-daemon",
			ok:   true, pid: "512", user: "root",
			cmd: "/Library/Application Support/VMware Tools/vmware-tools-daemon",
		},
		{
			name: "bare name, no path to inspect",
			line: " 1204 zyrow            aslmanager",
			ok:   true, pid: "1204", user: "zyrow", cmd: "aslmanager",
		},
		{
			name: "login shell reported with a leading dash",
			line: " 1301 zyrow            -zsh",
			ok:   true, pid: "1301", user: "zyrow", cmd: "-zsh",
		},
		{name: "empty line", line: "", ok: false},
		{name: "too few columns", line: "  96 root", ok: false},
		{name: "non-numeric first column is a header", line: "PID USER COMMAND", ok: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pid, user, cmd, ok := parsePSLine(c.line)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if pid != c.pid || user != c.user || cmd != c.cmd {
				t.Errorf("got (%q, %q, %q), want (%q, %q, %q)", pid, user, cmd, c.pid, c.user, c.cmd)
			}
		})
	}
}

// A bare name must never be mistaken for a path, or the check would try to
// verify "/aslmanager" and report a vanished executable.
func TestBareNamesAreNotTreatedAsPaths(t *testing.T) {
	for _, name := range []string{"aslmanager", "-zsh", "login", "endpointsecurityd"} {
		if len(name) > 0 && name[0] == '/' {
			t.Fatalf("%q is a path, the test premise is wrong", name)
		}
	}
}

func TestWorldWritableExecPrefixes(t *testing.T) {
	shouldMatch := []string{
		"/tmp/payload", "/private/tmp/x", "/var/tmp/y",
		"/Users/Shared/agent", "/private/var/folders/ab/cd/T/thing",
	}
	for _, p := range shouldMatch {
		if !hasAnyPrefix(p, worldWritableExec...) {
			t.Errorf("%q should be treated as a world-writable location", p)
		}
	}
	shouldNot := []string{
		"/usr/libexec/logd", "/System/Library/CoreServices/x",
		"/Applications/Safari.app/Contents/MacOS/Safari",
		"/Library/Application Support/VMware Tools/vmware-tools-daemon",
	}
	for _, p := range shouldNot {
		if hasAnyPrefix(p, worldWritableExec...) {
			t.Errorf("%q is a normal location and must not match", p)
		}
	}
}

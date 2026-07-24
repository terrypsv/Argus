//go:build linux

package checks

import "testing"

func TestParseVerifyLine(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		ok      bool
		path    string
		config  bool
		missing bool
		altered bool
	}{
		{
			name:    "dpkg digest mismatch",
			line:    "??5??????   /usr/bin/foo",
			ok:      true,
			path:    "/usr/bin/foo",
			altered: true,
		},
		{
			name:   "rpm modified config file",
			line:   "S.5....T.  c /etc/ssh/sshd_config",
			ok:     true,
			path:   "/etc/ssh/sshd_config",
			config: true, altered: true,
		},
		{
			name:    "missing file",
			line:    "missing     /usr/share/doc/foo/README",
			ok:      true,
			path:    "/usr/share/doc/foo/README",
			missing: true,
		},
		{
			name: "mtime only, contents intact",
			line: ".......T.   /usr/bin/bar",
			ok:   true,
			path: "/usr/bin/bar",
		},
		{name: "empty line", line: "", ok: false},
		{name: "noise without a path", line: "quelque chose", ok: false},
		{name: "relative path is not a packaged file", line: "??5?????? usr/bin/foo", ok: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := parseVerifyLine(c.line)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if a.path != c.path {
				t.Errorf("path = %q, want %q", a.path, c.path)
			}
			if a.config != c.config {
				t.Errorf("config = %v, want %v", a.config, c.config)
			}
			if a.missing != c.missing {
				t.Errorf("missing = %v, want %v", a.missing, c.missing)
			}
			if got := contentAltered(a.flags); got != c.altered {
				t.Errorf("contentAltered(%q) = %v, want %v", a.flags, got, c.altered)
			}
		})
	}
}

// Only the digest flag proves the contents changed. Treating ownership or
// timestamp drift as tampering would drown the real signal.
func TestContentAlteredOnlyOnDigest(t *testing.T) {
	altered := []string{"??5??????", "S.5....T.", ".M5......", "5"}
	for _, f := range altered {
		if !contentAltered(f) {
			t.Errorf("contentAltered(%q) = false, want true", f)
		}
	}
	intact := []string{".........", ".M.......", "S..DLUGTP", ".......T."}
	for _, f := range intact {
		if contentAltered(f) {
			t.Errorf("contentAltered(%q) = true, want false", f)
		}
	}
}

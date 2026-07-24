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
		doc     bool
		missing bool
		altered bool
	}{
		{
			name:    "dpkg digest mismatch on a binary",
			line:    "??5??????   /usr/bin/foo",
			ok:      true,
			path:    "/usr/bin/foo",
			altered: true,
		},
		{
			name:   "rpm modified config, marker and path agree",
			line:   "S.5....T.  c /etc/ssh/sshd_config",
			ok:     true,
			path:   "/etc/ssh/sshd_config",
			config: true, altered: true,
		},
		{
			// dpkg emits no attribute marker, so the path has to carry it.
			name:   "dpkg modified config, path only",
			line:   "??5??????   /etc/ssh/sshd_config",
			ok:     true,
			path:   "/etc/ssh/sshd_config",
			config: true, altered: true,
		},
		{
			// The real case from a Kali scan: a compressed changelog whose
			// digest moves whenever the package is rebuilt.
			name: "compressed changelog is documentation",
			line: "??5??????   /usr/share/doc/libwinpr3-3/changelog.Debian.gz",
			ok:   true,
			path: "/usr/share/doc/libwinpr3-3/changelog.Debian.gz",
			doc:  true, altered: true,
		},
		{
			name: "manual page is documentation",
			line: "??5??????   /usr/share/man/man1/foo.1.gz",
			ok:   true,
			path: "/usr/share/man/man1/foo.1.gz",
			doc:  true, altered: true,
		},
		{
			// Also from the Kali scan: shipped defaults consumed at setup.
			name:   "missing config default",
			line:   "missing     /etc/zsh/zprofile.original",
			ok:     true,
			path:   "/etc/zsh/zprofile.original",
			config: true, missing: true,
		},
		{
			name:    "missing binary",
			line:    "missing     /usr/bin/bar",
			ok:      true,
			path:    "/usr/bin/bar",
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
			if a.doc != c.doc {
				t.Errorf("doc = %v, want %v", a.doc, c.doc)
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

// Nothing under a documentation prefix may ever reach the HIGH bucket.
func TestDocumentationNeverCountsAsTampering(t *testing.T) {
	for _, p := range docPrefixes {
		a, ok := parseVerifyLine("??5??????   " + p + "quelque/chose")
		if !ok {
			t.Fatalf("parsing failed for prefix %q", p)
		}
		if !a.doc {
			t.Errorf("%q was not classified as documentation", p)
		}
	}
}

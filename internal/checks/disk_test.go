package checks

import (
	"strings"
	"testing"
)

// The bug this guards: a VMware guest reported a filesystem called
// "/Volumes/VMware", which does not exist. The real mount point is
// "/Volumes/VMware Shared Folders" and strings.Fields had cut it at the space.
func TestMountPointOfHandlesSpaces(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{
			name: "mount point containing spaces",
			line: "//host/Shared  1024  1024  0  100%  /Volumes/VMware Shared Folders",
			want: "/Volumes/VMware Shared Folders",
		},
		{
			name: "ordinary mount point",
			line: "/dev/disk1s1  489620264  387062080  99558184  80%  /",
			want: "/",
		},
		{
			name: "macOS devfs",
			line: "devfs  205  205  0  100%  /dev",
			want: "/dev",
		},
		{
			name: "nested path with one space",
			line: "/dev/disk2s1  100  100  0  100%  /Volumes/Install macOS",
			want: "/Volumes/Install macOS",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := strings.Fields(c.line)
			if got := mountPointOf(c.line, f); got != c.want {
				t.Errorf("mountPointOf = %q, want %q", got, c.want)
			}
		})
	}
}

func TestIsReadOnlyOpts(t *testing.T) {
	readOnly := []string{
		"apfs, local, read-only, journaled", // macOS
		"ro,relatime",                       // Linux
		"ext4, ro",
	}
	for _, o := range readOnly {
		if !isReadOnlyOpts(o) {
			t.Errorf("isReadOnlyOpts(%q) = false, want true", o)
		}
	}

	writable := []string{
		"apfs, local, journaled, nobrowse",
		"rw,relatime",
		"ext4, rw, errors=remount-ro", // must not match on the substring
		"",
	}
	for _, o := range writable {
		if isReadOnlyOpts(o) {
			t.Errorf("isReadOnlyOpts(%q) = true, want false", o)
		}
	}
}

// A read-only or synthetic filesystem at 100% is normal by construction, so it
// must never be treated as disk pressure.
func TestPseudoFilesystemsAreRecognised(t *testing.T) {
	for _, name := range []string{"devfs", "tmpfs", "map auto_home", "vmhgfs", "autofs"} {
		if !containsAny(strings.ToLower(name), pseudoFilesystems...) {
			t.Errorf("%q should be treated as a pseudo filesystem", name)
		}
	}
	for _, name := range []string{"/dev/disk1s1", "/dev/sda1", "/dev/nvme0n1p2"} {
		if containsAny(strings.ToLower(name), pseudoFilesystems...) {
			t.Errorf("%q is real storage and must not be skipped", name)
		}
	}
}

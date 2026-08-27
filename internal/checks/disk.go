package checks

import (
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
)

type volume struct {
	name     string
	pctUsed  int
	readOnly bool
}

// readVolumes lit les volumes du systeme. C'est une variable pour que les
// regles au-dessus soient verifiables sans disque: les seuils, l'exclusion
// des volumes en lecture seule et le cas sans donnee sont des decisions, et
// une decision non testee est une valeur que l'on peut changer sans que rien
// ne proteste.
var readVolumes = func() []volume {
	if runtime.GOOS == "windows" {
		return windowsVolumes()
	}
	return unixVolumes()
}

func diskUsageCheck(ctx *engine.Context) []model.Finding {
	vols := readVolumes()
	if len(vols) == 0 {
		return []model.Finding{info("DISK-NONE", "disk", "No disk usage data available", "")}
	}

	var out []model.Finding
	var inventory []string
	for _, v := range vols {
		if v.readOnly {
			// Kept in the inventory for visibility, but never alerted on: a
			// read-only volume at 100% is normal by construction, and macOS
			// seals "/" that way on every install.
			inventory = append(inventory, fmt.Sprintf("%s - %d%% used (read-only)", v.name, v.pctUsed))
			continue
		}
		inventory = append(inventory, fmt.Sprintf("%s - %d%% used", v.name, v.pctUsed))
		switch {
		case v.pctUsed >= 98:
			out = append(out, fail("DISK-FULL-"+sanitize(v.name), "disk",
				fmt.Sprintf("Filesystem %s is critically full (%d%%)", v.name, v.pctUsed),
				model.SevMedium,
				"A full disk can stop security logging and updates, and is exploited to blind defenders.",
				"Free space or extend the volume."))
		case v.pctUsed >= 90:
			out = append(out, fail("DISK-LOW-"+sanitize(v.name), "disk",
				fmt.Sprintf("Filesystem %s is nearly full (%d%%)", v.name, v.pctUsed),
				model.SevLow, "", "Free space to keep logging and updates working."))
		}
	}
	sort.Strings(inventory)
	out = append(out, info("DISK-INV", "disk",
		fmt.Sprintf("%d filesystem(s) inspected", len(vols)), "", inventory...))
	return out
}

// pseudoFilesystems never reflect real storage pressure. devfs and the autofs
// maps report 100% by construction, and a VM shared folder reports the host's
// disk, not this machine's.
var pseudoFilesystems = []string{
	"tmpfs", "devtmpfs", "devfs", "udev", "overlay", "squashfs",
	"autofs", "map", "vmhgfs", "fuse.gvfsd", "none",
}

// readOnlyMounts lists mount points that cannot be written to. A read-only
// filesystem sitting at 100% is normal by definition, not a warning: an
// installer image or a sealed system volume is *supposed* to be full.
func readOnlyMounts() map[string]bool {
	ro := map[string]bool{}
	out, err := runCmd(10*time.Second, "mount")
	if err != nil {
		return ro
	}
	for _, l := range strings.Split(out, "\n") {
		i := strings.Index(l, " on ")
		if i < 0 {
			continue
		}
		rest := l[i+4:]
		// macOS: "/dev/disk1s1 on / (apfs, local, read-only)"
		// Linux: "/dev/sda1 on / type ext4 (ro,relatime)"
		mount := rest
		if j := strings.Index(rest, " ("); j >= 0 {
			mount = rest[:j]
		}
		if j := strings.Index(mount, " type "); j >= 0 {
			mount = mount[:j]
		}
		opts := ""
		if a := strings.LastIndex(l, "("); a >= 0 {
			if b := strings.LastIndex(l, ")"); b > a {
				opts = l[a+1 : b]
			}
		}
		if isReadOnlyOpts(opts) {
			ro[strings.TrimSpace(mount)] = true
		}
	}
	return ro
}

func isReadOnlyOpts(opts string) bool {
	if strings.Contains(opts, "read-only") {
		return true // macOS spelling
	}
	for _, o := range strings.Split(opts, ",") {
		if strings.TrimSpace(o) == "ro" {
			return true // Linux spelling
		}
	}
	return false
}

// mountPointOf recovers the "Mounted on" column from a df line. It cannot be
// read with strings.Fields because mount points contain spaces: on a VMware
// guest, "/Volumes/VMware Shared Folders" was being reported as a filesystem
// called "/Volumes/VMware", which does not exist.
func mountPointOf(line string, fields []string) string {
	idx := 0
	for k := 0; k < 5 && k < len(fields); k++ {
		j := strings.Index(line[idx:], fields[k])
		if j < 0 {
			return fields[len(fields)-1]
		}
		idx += j + len(fields[k])
	}
	return strings.TrimSpace(line[idx:])
}

func unixVolumes() []volume {
	out, err := runCmd(10*time.Second, "df", "-kP")
	if err != nil {
		return nil
	}
	ro := readOnlyMounts()

	var vols []volume
	for i, l := range strings.Split(out, "\n") {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		if containsAny(strings.ToLower(f[0]), pseudoFilesystems...) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
		if err != nil {
			continue
		}
		mount := mountPointOf(l, f)
		vols = append(vols, volume{name: mount, pctUsed: n, readOnly: ro[mount]})
	}
	return vols
}

func windowsVolumes() []volume {
	script := `Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | ForEach-Object { "$($_.DeviceID)|$($_.Size)|$($_.FreeSpace)" }`
	out, err := runCmd(15*time.Second, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if err != nil {
		return nil
	}
	var vols []volume
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimSpace(l), "|")
		if len(f) != 3 {
			continue
		}
		size, err1 := strconv.ParseFloat(f[1], 64)
		free, err2 := strconv.ParseFloat(f[2], 64)
		if err1 != nil || err2 != nil || size <= 0 {
			continue
		}
		pct := int((size - free) / size * 100.0)
		vols = append(vols, volume{name: f[0], pctUsed: pct})
	}
	return vols
}

func sanitize(s string) string {
	r := strings.NewReplacer("/", "-", "\\", "-", ":", "", " ", "-")
	return strings.Trim(r.Replace(s), "-")
}

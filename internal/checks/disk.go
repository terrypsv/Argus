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
	name    string
	pctUsed int
}

func diskUsageCheck(ctx *engine.Context) []model.Finding {
	var vols []volume
	if runtime.GOOS == "windows" {
		vols = windowsVolumes()
	} else {
		vols = unixVolumes()
	}
	if len(vols) == 0 {
		return []model.Finding{info("DISK-NONE", "disk", "No disk usage data available", "")}
	}

	var out []model.Finding
	var inventory []string
	for _, v := range vols {
		inventory = append(inventory, fmt.Sprintf("%s — %d%% used", v.name, v.pctUsed))
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

func unixVolumes() []volume {
	out, err := runCmd(10*time.Second, "df", "-kP")
	if err != nil {
		return nil
	}
	var vols []volume
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		fsName := f[0]
		if containsAny(fsName, "tmpfs", "devtmpfs", "udev", "overlay", "squashfs") || fsName == "none" {
			continue
		}
		pct := strings.TrimSuffix(f[4], "%")
		n, err := strconv.Atoi(pct)
		if err != nil {
			continue
		}
		mount := f[5]
		vols = append(vols, volume{name: mount, pctUsed: n})
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

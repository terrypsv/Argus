//go:build windows

package engine

import (
	"os/exec"
	"strings"
)

func platformString() string {
	out, err := exec.Command("cmd", "/c", "ver").Output()
	if err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return s
		}
	}
	// Fallback via PowerShell CIM.
	ps, err := exec.Command("powershell", "-NoProfile", "-Command",
		"(Get-CimInstance Win32_OperatingSystem).Caption").Output()
	if err == nil {
		if s := strings.TrimSpace(string(ps)); s != "" {
			return s
		}
	}
	return "Windows"
}

func kernelString() string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		"[System.Environment]::OSVersion.Version.ToString()").Output()
	if err == nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			return "Windows NT " + s
		}
	}
	return "Windows NT"
}

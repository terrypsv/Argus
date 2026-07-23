//go:build linux

package engine

import (
	"os"
	"strings"
)

func kernelString() string {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		return "Linux " + strings.TrimSpace(string(b))
	}
	if b, err := os.ReadFile("/proc/version"); err == nil {
		return strings.TrimSpace(string(b))
	}
	return "Linux (unknown)"
}

func platformString() string {
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				v := strings.TrimPrefix(line, "PRETTY_NAME=")
				return strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
	}
	return "Linux"
}

//go:build darwin

package engine

import (
	"os/exec"
	"strings"
)

func run(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func kernelString() string {
	v := run("uname", "-sr")
	if v == "" {
		return "Darwin (unknown)"
	}
	return v
}

func platformString() string {
	name := run("sw_vers", "-productName")
	ver := run("sw_vers", "-productVersion")
	build := run("sw_vers", "-buildVersion")
	p := strings.TrimSpace(name + " " + ver)
	if build != "" {
		p += " (" + build + ")"
	}
	if strings.TrimSpace(p) == "" {
		return "macOS"
	}
	return p
}

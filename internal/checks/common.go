package checks

import (
	"fmt"

	"argus/internal/engine"
	"argus/internal/model"
)

// systemInfoCheck records the environment as an informational finding.
func systemInfoCheck(ctx *engine.Context) []model.Finding {
	return []model.Finding{info("SYS-INFO", "system",
		"Host information collected",
		fmt.Sprintf("%s on %s/%s, %d CPU(s), kernel: %s",
			ctx.Host.Platform, ctx.Host.OS, ctx.Host.Arch, ctx.Host.NumCPU, ctx.Host.Kernel))}
}

// commonChecks run on every operating system.
func commonChecks() []check {
	return []check{
		{Name: "system-info", Category: "system", Fn: systemInfoCheck},
		{Name: "file-integrity", Category: "integrity", Fn: integrityCheck},
	}
}

// All returns the complete, ordered list of checks for the current OS.
// osChecks() is provided by the platform-specific file (linux/windows/darwin).
func All() []check {
	out := commonChecks()
	out = append(out, osChecks()...)
	return out
}

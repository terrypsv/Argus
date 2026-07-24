package checks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"argus/internal/engine"
	"argus/internal/model"
)

// baseline is the on-disk integrity snapshot.
type baseline struct {
	CreatedAt time.Time         `json:"created_at"`
	Algorithm string            `json:"algorithm"`
	Files     map[string]string `json:"files"` // absolute path -> hex sha256
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// WriteBaseline hashes each existing file in paths and stores the snapshot.
// Returns the number of files recorded.
func WriteBaseline(path string, paths []string) (int, error) {
	b := baseline{
		CreatedAt: time.Now(),
		Algorithm: "sha256",
		Files:     map[string]string{},
	}
	for _, p := range paths {
		if !fileExists(p) {
			continue
		}
		sum, err := hashFile(p)
		if err != nil {
			continue // unreadable (permissions) - skip rather than abort
		}
		b.Files[p] = sum
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return 0, err
	}
	return len(b.Files), nil
}

// integrityCheck compares current hashes against the stored baseline.
func integrityCheck(ctx *engine.Context) []model.Finding {
	const cat = "integrity"
	path := ctx.Config.BaselinePath
	data, err := os.ReadFile(path)
	if err != nil {
		return []model.Finding{info("INTEG-NOBASE", cat,
			"No integrity baseline found",
			fmt.Sprintf("Run `argus baseline` first to record trusted hashes of critical files (looked for %s).", path))}
	}
	var b baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return []model.Finding{errFinding("INTEG-BADBASE", cat,
			"Integrity baseline is corrupt", err.Error())}
	}

	var findings []model.Finding
	var changed, missing []string
	paths := make([]string, 0, len(b.Files))
	for p := range b.Files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		want := b.Files[p]
		if !fileExists(p) {
			missing = append(missing, p)
			continue
		}
		got, err := hashFile(p)
		if err != nil {
			continue
		}
		if got != want {
			changed = append(changed, p)
		}
	}

	if len(changed) > 0 {
		findings = append(findings, fail("INTEG-CHANGED", cat,
			fmt.Sprintf("%d critical file(s) changed since baseline", len(changed)),
			model.SevHigh,
			"A monitored system binary or config differs from the trusted baseline. This is expected after an update, but also a classic sign of tampering or a trojaned binary.",
			"Confirm the change matches a legitimate package update (compare with the distro package hashes); if not, treat the host as compromised.",
			changed...))
	}
	if len(missing) > 0 {
		findings = append(findings, fail("INTEG-MISSING", cat,
			fmt.Sprintf("%d baselined file(s) missing", len(missing)),
			model.SevMedium,
			"Files present when the baseline was taken are now gone.",
			"Verify whether the removal was intentional.",
			missing...))
	}
	if len(findings) == 0 {
		findings = append(findings, pass("INTEG-OK", cat,
			fmt.Sprintf("All %d baselined files match", len(b.Files))))
	}
	return findings
}

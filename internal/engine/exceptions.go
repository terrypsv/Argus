package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"argus/internal/model"
)

// DateLayout is the date format used in the exception file.
const DateLayout = "2006-01-02"

// Exception records a finding the operator has reviewed and knowingly accepted.
//
// Silently suppressing findings is how audit tools rot into decoration, so an
// exception is deliberately expensive: it must carry a reason and an author,
// it is dated, and it can be given an expiry so that "temporary" acceptances
// do not quietly become permanent.
type Exception struct {
	ID         string `json:"id"`
	Reason     string `json:"reason"`
	AcceptedBy string `json:"accepted_by,omitempty"`
	AcceptedAt string `json:"accepted_at,omitempty"`
	Expires    string `json:"expires,omitempty"` // YYYY-MM-DD; empty means never
}

// ExceptionFile is the on-disk format.
type ExceptionFile struct {
	Exceptions []Exception `json:"exceptions"`
}

// expired reports whether the exception is past its expiry date. An unparsable
// date is treated as never expiring rather than silently dropped, so a typo
// cannot make an acceptance vanish without a word.
func (e Exception) expired(now time.Time) bool {
	if e.Expires == "" {
		return false
	}
	t, err := time.Parse(DateLayout, e.Expires)
	if err != nil {
		return false
	}
	return now.After(t.AddDate(0, 0, 1))
}

// LoadExceptions reads the exception file. A missing file is not an error.
func LoadExceptions(path string) (ExceptionFile, error) {
	var ef ExceptionFile
	if path == "" {
		return ef, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ef, nil
		}
		return ef, err
	}
	if err := json.Unmarshal(raw, &ef); err != nil {
		return ef, fmt.Errorf("%s: %w", path, err)
	}
	return ef, nil
}

// SaveExceptions writes the file back, pretty-printed so it stays reviewable
// in a pull request.
func SaveExceptions(path string, ef ExceptionFile) error {
	raw, err := json.MarshalIndent(ef, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}

// AddException inserts an exception, replacing any existing one with the same ID.
func AddException(path string, e Exception) error {
	ef, err := LoadExceptions(path)
	if err != nil {
		return err
	}
	for i := range ef.Exceptions {
		if strings.EqualFold(ef.Exceptions[i].ID, e.ID) {
			ef.Exceptions[i] = e
			return SaveExceptions(path, ef)
		}
	}
	ef.Exceptions = append(ef.Exceptions, e)
	return SaveExceptions(path, ef)
}

// applyExceptions neutralises accepted findings in place. The finding stays in
// the report, tagged with the reason it was accepted, so nothing is ever
// hidden — only acknowledged. Returns the number neutralised and the IDs of
// exceptions that have expired and therefore no longer apply.
func applyExceptions(findings []model.Finding, ef ExceptionFile, now time.Time) (suppressed int, expired []string) {
	if len(ef.Exceptions) == 0 {
		return 0, nil
	}
	active := map[string]Exception{}
	for _, e := range ef.Exceptions {
		if strings.TrimSpace(e.ID) == "" {
			continue
		}
		if e.expired(now) {
			expired = append(expired, e.ID)
			continue
		}
		active[strings.ToUpper(strings.TrimSpace(e.ID))] = e
	}
	for i := range findings {
		f := &findings[i]
		if f.Passed || f.Severity == model.SevInfo {
			continue
		}
		e, ok := active[strings.ToUpper(f.ID)]
		if !ok {
			continue
		}
		f.Passed = true
		f.Severity = model.SevInfo
		f.Accepted = e.Reason
		suppressed++
	}
	return suppressed, expired
}

//go:build !windows

package report

// enableANSI is a no-op outside Windows: Unix terminals interpret ANSI escape
// sequences without being asked.
func enableANSI() {}

// EnableUTF8 is a no-op outside Windows, where UTF-8 is the norm.
func EnableUTF8() {}

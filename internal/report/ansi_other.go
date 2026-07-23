//go:build !windows

package report

// enableANSI is a no-op outside Windows: Unix terminals interpret ANSI escape
// sequences without being asked.
func enableANSI() {}

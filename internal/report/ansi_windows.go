//go:build windows

package report

import (
	"syscall"
	"unsafe"
)

// enableVirtualTerminalProcessing is the console mode flag that makes a Windows
// console interpret ANSI escape sequences instead of printing them literally.
const enableVirtualTerminalProcessing = 0x0004

// codePageUTF8 is the Windows identifier for UTF-8.
const codePageUTF8 = 65001

var (
	kernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode    = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode    = kernel32.NewProc("SetConsoleMode")
	procSetConsoleOutputC = kernel32.NewProc("SetConsoleOutputCP")
)

// EnableUTF8 switches the console to UTF-8. It must be called explicitly, first
// thing in main, and not from a package init.
//
// The distinction matters and cost an afternoon to find: the same call made
// from an init did nothing, while the identical call made from main worked. So
// this is exported and called deliberately, where the order of execution is
// visible in the code rather than left to package initialisation.
//
// It is not folded into enableANSI on purpose. The rules, bullets, arrows and
// blocks in this report are not decoration, they carry its structure, and a
// legacy code page mangles them whether or not colour is enabled. A report
// whose own separators read as garbage is a report nobody trusts the contents
// of.
//
// The return value is ignored: a scanner must never abort over the encoding of
// its own output.
func EnableUTF8() {
	procSetConsoleOutputC.Call(uintptr(codePageUTF8))
}

// enableANSI switches the console attached to stdout into virtual-terminal
// mode. Unlike Unix terminals, a Windows console does not interpret escape
// sequences until asked, and Go does not ask on our behalf - so emitting colour
// without this call is a bet on whichever program ran before us.
//
// Every failure is ignored on purpose: a scanner must never abort over the
// colour of its own output.
func enableANSI() {
	handle, err := syscall.GetStdHandle(syscall.STD_OUTPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return
	}
	if mode&enableVirtualTerminalProcessing != 0 {
		return // already on
	}
	procSetConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
}

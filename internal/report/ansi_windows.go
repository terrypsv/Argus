//go:build windows

package report

import (
	"syscall"
	"unsafe"
)

// enableVirtualTerminalProcessing is the console mode flag that makes a Windows
// console interpret ANSI escape sequences instead of printing them literally.
const enableVirtualTerminalProcessing = 0x0004

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

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

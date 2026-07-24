//go:build windows

package main

import (
	"bufio"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// ownsConsole reports whether this process is the only one attached to its
// console. That is exactly what happens when Windows creates a console for a
// double-clicked executable: nothing else is using it, so it disappears the
// instant we return, taking the report with it.
//
// Launched from an existing PowerShell or cmd window, the shell is attached too
// and the count is at least two, so we must not pause.
func ownsConsole() bool {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := kernel32.NewProc("GetConsoleProcessList")

	var pids [8]uint32
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	return r == 1
}

// pauseIfLaunchedFromExplorer keeps the window open long enough to read the
// report. It is deliberately silent when a terminal or a CI job is driving us:
// a scanner that blocks waiting for a keypress inside a pipeline is broken.
func pauseIfLaunchedFromExplorer() {
	if !ownsConsole() {
		return
	}
	fmt.Fprint(os.Stderr, "\nAppuyez sur Entree pour fermer cette fenetre...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

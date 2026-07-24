//go:build !windows

package main

// pauseIfLaunchedFromExplorer is a no-op outside Windows. Unix desktops do not
// spawn a throwaway console for a double-clicked binary, so there is no window
// to hold open.
func pauseIfLaunchedFromExplorer() {}

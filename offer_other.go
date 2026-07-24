//go:build !windows

package main

// offerBrowserReport is a no-op outside Windows: Unix desktops do not launch a
// binary into a throwaway console, so there is no double-click case to serve.
func offerBrowserReport() {}

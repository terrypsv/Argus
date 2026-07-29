//go:build darwin

package checks

import "testing"

// Screen Sharing was listening on port 5900 while this parser reported it off,
// because current macOS prints "=> enabled" where older releases printed
// "=> false". Both spellings are now accepted, and both are locked here.
func TestLaunchdEnabled(t *testing.T) {
	cases := []struct {
		name    string
		out     string
		label   string
		enabled bool
		known   bool
	}{
		{
			name:  "current macOS spelling, enabled",
			out:   "\t\t\"com.apple.screensharing\" => enabled\n",
			label: "com.apple.screensharing", enabled: true, known: true,
		},
		{
			name:  "current macOS spelling, disabled",
			out:   "\t\t\"com.apple.screensharing\" => disabled\n",
			label: "com.apple.screensharing", enabled: false, known: true,
		},
		{
			// The legacy list answered the question "is it disabled?", so false
			// means the service is running.
			name:  "legacy spelling, not disabled",
			out:   "\t\t\"com.apple.screensharing\" => false\n",
			label: "com.apple.screensharing", enabled: true, known: true,
		},
		{
			name:  "legacy spelling, disabled",
			out:   "\t\t\"com.apple.screensharing\" => true\n",
			label: "com.apple.screensharing", enabled: false, known: true,
		},
		{
			name:  "label absent from the list",
			out:   "\t\t\"com.apple.other\" => enabled\n",
			label: "com.apple.screensharing", enabled: false, known: false,
		},
		{
			name:  "unrecognised state is not a conclusion",
			out:   "\t\t\"com.apple.screensharing\" => quelque-chose\n",
			label: "com.apple.screensharing", enabled: false, known: false,
		},
		{
			name:  "picks the right line among several",
			out:   "\t\t\"com.apple.screensharing\" => disabled\n\t\t\"com.apple.RemoteDesktop.agent\" => enabled\n",
			label: "com.apple.RemoteDesktop.agent", enabled: true, known: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enabled, known := launchdEnabled(c.out, c.label)
			if known != c.known {
				t.Fatalf("known = %v, want %v", known, c.known)
			}
			if enabled != c.enabled {
				t.Errorf("enabled = %v, want %v", enabled, c.enabled)
			}
		})
	}
}

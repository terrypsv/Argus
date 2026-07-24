//go:build linux

package checks

import (
	"os"
	"path/filepath"
	"testing"
)

// procTable writes a fake /proc/net table and returns its path.
func procTable(t *testing.T, rows ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "table")
	body := "  sl  local_address rem_address   st tx_queue rx_queue\n"
	for _, r := range rows {
		body += r + "\n"
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("écriture de la table: %v", err)
	}
	return p
}

// A missing table must not read as "no open ports": that is a false all-clear.
func TestParseProcNetReportsUnreadableTable(t *testing.T) {
	_, ok := parseProcNet(filepath.Join(t.TempDir(), "absent"), "tcp", tcpListenState)
	if ok {
		t.Error("a missing table must report failure, not an empty result")
	}
}

func TestParseProcNetEmptyTableIsReadable(t *testing.T) {
	ls, ok := parseProcNet(procTable(t), "tcp", tcpListenState)
	if !ok {
		t.Fatal("a table holding only a header is readable")
	}
	if len(ls) != 0 {
		t.Errorf("got %d socket(s), want 0", len(ls))
	}
}

func TestParseProcNetKeepsOnlyListeningTCP(t *testing.T) {
	ls, ok := parseProcNet(procTable(t,
		// 0.0.0.0:22 in LISTEN -> kept, all interfaces
		"   0: 00000000:0016 00000000:0000 0A 00000000:00000000",
		// 127.0.0.1:631 in LISTEN -> kept, loopback
		"   1: 0100007F:0277 00000000:0000 0A 00000000:00000000",
		// an established connection -> dropped
		"   2: 0100007F:1F90 0100007F:D431 01 00000000:00000000",
	), "tcp", tcpListenState)
	if !ok {
		t.Fatal("table should be readable")
	}
	if len(ls) != 2 {
		t.Fatalf("got %d socket(s), want 2", len(ls))
	}
	if ls[0].port != 22 || !ls[0].allIf {
		t.Errorf("first = port %d allIf %v, want 22 and true", ls[0].port, ls[0].allIf)
	}
	if ls[1].port != 631 || ls[1].allIf {
		t.Errorf("second = port %d allIf %v, want 631 and false", ls[1].port, ls[1].allIf)
	}
}

// UDP has no listening state, so every bound socket counts - except the
// ephemeral ones, which are a client's source port rather than a service.
func TestParseProcNetUDPDropsEphemeralPorts(t *testing.T) {
	ls, ok := parseProcNet(procTable(t,
		"   0: 00000000:00A1 00000000:0000 07 00000000:00000000", // 161, snmp
		"   1: 00000000:E2C4 00000000:0000 07 00000000:00000000", // 58052, ephemeral
	), "udp", "")
	if !ok {
		t.Fatal("table should be readable")
	}
	if len(ls) != 1 {
		t.Fatalf("got %d socket(s), want 1", len(ls))
	}
	if ls[0].port != 161 {
		t.Errorf("port = %d, want 161", ls[0].port)
	}
}

func TestFamily(t *testing.T) {
	cases := map[string]string{
		"tcp": "tcp", "tcp6": "tcp", "udp": "udp", "udp6": "udp",
	}
	for in, want := range cases {
		if got := family(in); got != want {
			t.Errorf("family(%q) = %q, want %q", in, got, want)
		}
	}
}

// Package webui serves a scan report as an interactive page in the local
// browser.
//
// The design constraints come from what Argus is. A security report must not be
// reachable from the network, not even for a second, so the listener binds to
// the loopback interface on a port the kernel picks. Any other local process
// could still reach that port, so a single-use token is required on every
// request. And because a scanner has no business outliving its own report, the
// server shuts itself down once the page stops answering.
package webui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"argus/internal/model"
)

//go:embed index.html
var assets embed.FS

// idleTimeout is how long the server waits without a heartbeat before closing.
// The page pings while it is open, so closing the tab ends the process.
const idleTimeout = 45 * time.Second

type server struct {
	report model.Report
	token  string

	mu       sync.Mutex
	lastSeen time.Time
	done     chan struct{}
	closeOne sync.Once
}

// Serve renders the report in the browser and blocks until the page is closed.
func Serve(rep model.Report, out io.Writer, openBrowser bool) error {
	token, err := randomToken()
	if err != nil {
		return fmt.Errorf("cannot generate an access token: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("cannot open a local listener: %w", err)
	}

	s := &server{
		report:   rep,
		token:    token,
		lastSeen: time.Now(),
		done:     make(chan struct{}),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.guard(s.handleIndex))
	mux.HandleFunc("/report.json", s.guard(s.handleReport))
	mux.HandleFunc("/ping", s.guard(s.handlePing))
	mux.HandleFunc("/quit", s.guard(s.handleQuit))

	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	url := fmt.Sprintf("http://%s/?t=%s", ln.Addr().String(), token)
	fmt.Fprintf(out, "\nRapport interactif : %s\n", url)
	fmt.Fprintf(out, "La fenetre se ferme toute seule quand vous quittez la page.\n")

	if openBrowser {
		_ = open(url)
	}

	go s.watchIdle()
	go func() {
		<-s.done
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(ctx)
	}()

	if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// guard rejects any request that does not carry the token, and refreshes the
// idle deadline for the ones that do.
func (s *server) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.URL.Query().Get("t")
		if subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1 {
			http.Error(w, "invalid or missing token", http.StatusForbidden)
			return
		}
		s.touch()
		next(w, r)
	}
}

func (s *server) touch() {
	s.mu.Lock()
	s.lastSeen = time.Now()
	s.mu.Unlock()
}

func (s *server) watchIdle() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
			s.mu.Lock()
			idle := time.Since(s.lastSeen)
			s.mu.Unlock()
			if idle > idleTimeout {
				s.shutdown()
				return
			}
		}
	}
}

func (s *server) shutdown() {
	s.closeOne.Do(func() { close(s.done) })
}

func (s *server) handleIndex(w http.ResponseWriter, r *http.Request) {
	page, err := assets.ReadFile("index.html")
	if err != nil {
		http.Error(w, "page introuvable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The page loads nothing from anywhere: say so, and let the browser enforce it.
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(page)
}

func (s *server) handleReport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(s.report)
}

func (s *server) handlePing(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleQuit(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
	go func() {
		time.Sleep(200 * time.Millisecond)
		s.shutdown()
	}()
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// open asks the desktop to show the URL. Failure is not fatal: the address has
// already been printed, so the person can paste it themselves.
func open(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}

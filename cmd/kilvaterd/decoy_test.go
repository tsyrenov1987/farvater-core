package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decoyFS is a file handler over a temp dir holding one real file, like a real
// decoy site, so the wrapper is tested against actual FileServer behaviour.
func decoyFS(t *testing.T) http.Handler {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>hello</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	return newNginxDecoy(http.FileServer(http.Dir(dir)))
}

func do(t *testing.T, h http.Handler, method, path string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Result()
}

func TestDecoyServerHeader(t *testing.T) {
	h := decoyFS(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/"}, {"GET", "/nope"}, {"POST", "/"},
	} {
		resp := do(t, h, tc.method, tc.path)
		if got := resp.Header.Get("Server"); got != "nginx" {
			t.Errorf("%s %s: Server = %q, want nginx", tc.method, tc.path, got)
		}
	}
}

func TestDecoyNotFoundLooksLikeNginx(t *testing.T) {
	resp := do(t, decoyFS(t), "GET", "/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html (Go FileServer sends text/plain)", ct)
	}
	if resp.Header.Get("X-Content-Type-Options") != "" {
		t.Error("X-Content-Type-Options present; nginx does not send it")
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "404 Not Found") || !strings.Contains(string(body), "nginx") {
		t.Errorf("body is not nginx's 404 page: %q", body)
	}
	if strings.Contains(string(body), "page not found") {
		t.Error("body still carries Go's '404 page not found' text")
	}
}

func TestDecoyPostIs405(t *testing.T) {
	resp := do(t, decoyFS(t), "POST", "/")
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405 (Go FileServer answers 200)", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "405 Not Allowed") {
		t.Errorf("body is not nginx's 405 page: %q", body)
	}
}

func TestDecoyGetServesRealFile(t *testing.T) {
	resp := do(t, decoyFS(t), "GET", "/")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "hello") {
		t.Errorf("real file not served: %q", body)
	}
}

func TestDecoyHeadNoBody(t *testing.T) {
	resp := do(t, decoyFS(t), "HEAD", "/does-not-exist")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(body) != 0 {
		t.Errorf("HEAD returned a body of %d bytes", len(body))
	}
}

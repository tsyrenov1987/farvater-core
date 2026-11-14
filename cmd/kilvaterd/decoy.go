package main

import (
	"io"
	"net/http"
	"strconv"
)

// The HTTP-layer half of the server fingerprint, the counterpart of the TLS and
// HTTP/2 shaping (h2server.go). On the h2c path the TLS is the front proxy's
// OpenSSL and the HTTP/2 is kilvaterd's, shaped to a stock nginx's. But the
// static handler under it is Go's http.FileServer, whose HTTP responses are
// plainly Go, not nginx: no Server header, a text/plain "404 page not found"
// body for a miss, and 200 to a POST that nginx refuses on a static location.
// A request to a non-tunnel path reaches the decoy before any key is checked, so
// those responses are readable without a key and contradict the nginx below.
//
// nginxDecoy wraps the file handler so its responses match a stock nginx's: a
// bare "Server: nginx" header, nginx's HTML error pages, and 405 for methods
// other than GET and HEAD. It is applied only on the h2c path, where the rest of
// the stack is nginx; the direct-TLS path keeps the plain Go handler, since there
// the whole stack is Go and an nginx HTTP layer would be a fresh mismatch.

// nginx's stock error-page bodies (modern nginx, server_tokens off: a bare
// "nginx" footer, matching the bare Server header). CRLF line endings as nginx
// emits them.
const (
	nginx404Body = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	nginx403Body = "<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
	nginx405Body = "<html>\r\n<head><title>405 Not Allowed</title></head>\r\n<body>\r\n<center><h1>405 Not Allowed</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"
)

// newNginxDecoy wraps a static file handler so its HTTP responses look like a
// stock nginx's.
func newNginxDecoy(files http.Handler) http.Handler {
	return &nginxDecoy{files: files}
}

type nginxDecoy struct{ files http.Handler }

func (d *nginxDecoy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Server", "nginx")
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		// Serve the file, but rewrite the Go handler's own error responses
		// (notably its text/plain 404) into nginx's HTML pages.
		d.files.ServeHTTP(&nginxErrorWriter{ResponseWriter: w, head: r.Method == http.MethodHead}, r)
	default:
		// nginx answers a static location only for GET and HEAD; anything else
		// is 405 Not Allowed.
		writeNginxError(w, http.StatusMethodNotAllowed, nginx405Body, r.Method == http.MethodHead)
	}
}

// writeNginxError sends one of nginx's stock error pages with its headers.
func writeNginxError(w http.ResponseWriter, code int, body string, head bool) {
	h := w.Header()
	h.Del("X-Content-Type-Options") // nginx does not send it; Go's http.Error does
	h.Set("Content-Type", "text/html")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(code)
	if !head {
		io.WriteString(w, body)
	}
}

// nginxErrorWriter intercepts the status the file handler writes: for the error
// statuses http.FileServer produces (404, 403) it substitutes nginx's HTML page
// and swallows the handler's own body; every other status (200 for a real file,
// 301 for a directory redirect, 304) passes straight through.
type nginxErrorWriter struct {
	http.ResponseWriter
	head        bool
	wroteHeader bool
	suppress    bool // an error body is being swallowed in favour of nginx's
}

func (w *nginxErrorWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	switch code {
	case http.StatusNotFound, http.StatusForbidden:
		body := nginx404Body
		if code == http.StatusForbidden {
			body = nginx403Body
		}
		h := w.Header()
		h.Del("X-Content-Type-Options")
		h.Set("Content-Type", "text/html")
		h.Set("Content-Length", strconv.Itoa(len(body)))
		w.ResponseWriter.WriteHeader(code)
		if !w.head {
			io.WriteString(w.ResponseWriter, body)
		}
		w.suppress = true
	default:
		w.ResponseWriter.WriteHeader(code)
	}
}

func (w *nginxErrorWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if w.suppress {
		return len(p), nil // the handler's own error body, dropped
	}
	return w.ResponseWriter.Write(p)
}

#!/usr/bin/env python3
# стенд этапа 3: источник (порт 18080: 8 МиБ, 18082: размер promo.mp4) и сток (18081)
import socket, threading, os
def serve(port, fn):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(16)
    while True:
        c, _ = s.accept(); threading.Thread(target=fn, args=(c,), daemon=True).start()
def src(n):
    def f(c):
        try:
            c.recv(1); buf = os.urandom(65536); left = n
            while left > 0:
                c.sendall(buf[:min(left, 65536)]); left -= 65536
        finally: c.close()
    return f
def sink(c):
    try:
        while c.recv(65536): pass
    finally: c.close()
for p, f in ((18080, src(8 << 20)), (18082, src(1166826)), (18081, sink)):
    threading.Thread(target=serve, args=(p, f), daemon=True).start()
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        left = int(self.headers.get("Content-Length", 0))
        while left > 0:
            b = self.rfile.read(min(left, 65536))
            if not b: break
            left -= len(b)
        self.send_response(200); self.send_header("Content-Length", "2"); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
HTTPServer(("127.0.0.1", 18083), H).serve_forever()

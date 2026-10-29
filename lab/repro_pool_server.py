"""Repro 3, upstream: http.server HTTP/1.1 que cierra keepalive ociosas a 1 s."""
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 1  # inactividad de keepalive

    def do_GET(self):
        time.sleep(0.05)  # fuerza concurrencia: 10 conexiones distintas en el pool
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
print(srv.server_address[1], flush=True)
srv.serve_forever()

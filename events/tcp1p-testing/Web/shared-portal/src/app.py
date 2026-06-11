"""Shared Portal — a trivial static-flag web service.

StaticContainer with container.enableSharedContainer: true, so the platform runs
ONE container for the whole game and every team connects to it. The page prints
the container hostname (identical for all teams, since it's the same box) so the
sharing is visible. The flag is static and must match challenge.yml `flags:`.
"""
import http.server
import socket

FLAG = "TCP1P{shared_container_one_box_for_every_team}"
HOST = socket.gethostname()

PAGE = f"""<!doctype html>
<html>
  <head><title>Shared Portal</title></head>
  <body style="font-family: monospace; max-width: 40rem; margin: 3rem auto;">
    <h1>Shared Portal</h1>
    <p>This service runs as <b>one shared container</b> for the whole game &mdash;
       every team connects to this same instance.</p>
    <p>Container host: <b>{HOST}</b><br/>
       <small>(open this from another team &mdash; same hostname = same shared box)</small></p>
    <p>Flag: <code>{FLAG}</code></p>
  </body>
</html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(PAGE.encode())

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    http.server.HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()

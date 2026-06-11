"""Per-Team Portal — a trivial static-flag web service in the normal mode.

StaticContainer WITHOUT enableSharedContainer, so the platform runs one container
per team (the default). The page prints the container hostname (different for each
team's instance) to contrast with the sibling Shared Portal. The flag is static
and must match challenge.yml `flags:`.
"""
import http.server
import socket

FLAG = "TCP1P{per_team_container_one_box_each_team}"
HOST = socket.gethostname()

PAGE = f"""<!doctype html>
<html>
  <head><title>Per-Team Portal</title></head>
  <body style="font-family: monospace; max-width: 40rem; margin: 3rem auto;">
    <h1>Per-Team Portal</h1>
    <p>This service runs as <b>one container per team</b> (the default mode) &mdash;
       each team gets its own instance.</p>
    <p>Container host: <b>{HOST}</b><br/>
       <small>(each team sees a different hostname &mdash; its own box)</small></p>
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

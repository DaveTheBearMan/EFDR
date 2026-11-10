#!/usr/bin/python3
"""The scored service of the e2e-net test, on tcp/80.

GET / answers 200. GET /run starts a shell as a hijacked web server would;
the agent must kill the shell and leave the service alone.
"""
import http.server
import signal
import subprocess


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/run":
            # "; true" keeps dash from exec'ing straight into sleep.
            subprocess.Popen(["sh", "-c", "sleep 300; true"])
        elif self.path != "/":
            self.send_error(404)
            return
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


signal.signal(signal.SIGCHLD, signal.SIG_IGN)  # reap the shells
http.server.HTTPServer(("0.0.0.0", 80), Handler).serve_forever()

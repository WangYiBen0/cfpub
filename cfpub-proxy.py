#!/usr/bin/env python3
"""Prefix-stripping reverse proxy used by cfpub.

Cloudflare's ingress `path` matcher hands the *full* path to the origin, so a
request for /sxyz-79/web/foo arrives at the app as /sxyz-79/web/foo and 404s.
This proxy strips the prefix before forwarding, which is what makes one
hostname able to serve many services by path.

Routes are re-read from the state file on every request (cached by mtime), so
`cfpub pub` takes effect immediately without restarting the proxy.
"""

import http.client
import json
import os
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = os.environ.get("CFPUB_STATE", "")
PORT = int(os.environ.get("CFPUB_PROXY_PORT", "8080"))
BIND = os.environ.get("CFPUB_PROXY_BIND", "127.0.0.1")

_lock = threading.Lock()
_cache = {"mtime": None, "routes": {}}

HOP_BY_HOP = {
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "accept-encoding",  # let the origin send identity so we can relay verbatim
}


def routes():
    """Current prefix -> target map, refreshed only when the file changes."""
    try:
        mtime = os.stat(STATE).st_mtime
    except OSError:
        return {}
    with _lock:
        if _cache["mtime"] != mtime:
            try:
                with open(STATE) as fh:
                    _cache["routes"] = json.load(fh).get("http", {})
            except (OSError, ValueError):
                return _cache["routes"]
            _cache["mtime"] = mtime
        return _cache["routes"]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cfpub-proxy"

    def log_message(self, fmt, *args):
        sys.stderr.write("cfpub-proxy: " + (fmt % args) + "\n")

    def _pick(self):
        path = urllib.parse.urlsplit(self.path).path
        best = None
        for prefix, target in routes().items():
            if path == prefix or path.startswith(prefix + "/"):
                # Longest prefix wins, so /sxyz-79/web beats /sxyz-79.
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, target)
        return best

    def _simple(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self):
        picked = self._pick()
        if not picked:
            self._simple(404, "cfpub: no service published at this path\n")
            return

        prefix, target = picked
        url = urllib.parse.urlsplit(target)
        rest = self.path[len(prefix):] or "/"
        if not rest.startswith("/"):
            rest = "/" + rest

        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else None

        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP_BY_HOP}
        headers["X-Forwarded-Prefix"] = prefix

        conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=60)
        try:
            conn.request(self.command, rest, body=body, headers=headers)
            resp = conn.getresponse()
            payload = resp.read()
        except Exception as exc:  # noqa: BLE001 - report any upstream failure verbatim
            self._simple(502, "cfpub: upstream %s unreachable: %s\n" % (target, exc))
            return
        finally:
            conn.close()

        self.send_response(resp.status, resp.reason)
        for key, value in resp.getheaders():
            if key.lower() not in HOP_BY_HOP and key.lower() != "content-length":
                self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    do_GET = _proxy
    do_HEAD = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_PATCH = _proxy
    do_DELETE = _proxy
    do_OPTIONS = _proxy


def main():
    if not STATE:
        sys.exit("cfpub-proxy: CFPUB_STATE is not set")
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.daemon_threads = True
    sys.stderr.write("cfpub-proxy: listening on %s:%d (%d route(s))\n"
                     % (BIND, PORT, len(routes())))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Prefix-stripping reverse proxy used by cfpub.

Cloudflare's ingress `path` matcher hands the *full* path to the origin, so a
request for /sxyz-79/web/foo arrives at the app as /sxyz-79/web/foo and 404s.
This proxy strips the prefix before forwarding, which is what makes one
hostname able to serve many services by path.

Routes are re-read from the state file on every request (cached by mtime), so
`cfpub pub` takes effect immediately without restarting the proxy.

Everything this proxy can be reached by is untrusted: the tunnel is on the
public internet, and the listen port is on localhost where any local process or
page can reach it. So the framing is pinned down rather than negotiated --
no Transfer-Encoding in, no chunked framing out, one request per connection --
and the path handed upstream is proven to stay inside the published prefix.
"""

import http.client
import json
import os
import ssl
import sys
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STATE = os.environ.get("CFPUB_STATE", "")
PORT = int(os.environ.get("CFPUB_PROXY_PORT", "8080"))
BIND = os.environ.get("CFPUB_PROXY_BIND", "127.0.0.1")

# A request body is buffered in memory before forwarding, so it needs a ceiling.
MAX_BODY = int(os.environ.get("CFPUB_MAX_BODY", str(64 * 1024 * 1024)))
# One thread per connection: without a cap, opening sockets is enough to exhaust
# the process. Refusing the connection is cheaper than growing to match.
MAX_CONNECTIONS = int(os.environ.get("CFPUB_MAX_CONNECTIONS", "256"))
# Self-signed loopback origins are common; opt in explicitly rather than
# silently talking plaintext to an https:// target.
TLS_INSECURE = os.environ.get("CFPUB_TLS_INSECURE", "") not in ("", "0")

CHUNK = 64 * 1024

_lock = threading.Lock()
_cache = {"mtime": None, "routes": {}}
_slots = threading.BoundedSemaphore(MAX_CONNECTIONS)

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
    "expect",           # http.client does not do 100-continue
    "accept-encoding",  # let the origin send identity so we can relay verbatim
}

# Client-supplied identity headers are dropped and re-derived. Forwarding them
# verbatim would let anyone behind the tunnel claim to be 127.0.0.1, or claim a
# different prefix than the one actually stripped.
UNTRUSTED = {
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-prefix",
    "x-forwarded-proto",
    "x-real-ip",
    "forwarded",
    "cf-connecting-ip",
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


def unsafe_path(path):
    """True if `path` contains a segment a server or framework may resolve away.

    Forwarding `/prefix/../x` verbatim is not a sandbox: nginx `alias`, SPA
    fallbacks and SimpleHTTPRequestHandler all normalise dot segments, so the
    origin would serve something outside the directory the operator published.
    Percent-encoded forms are decoded first for the same reason, and `..;` is
    caught because Tomcat-style containers treat `;` as a path parameter but
    still resolve the parent.
    """
    decoded = urllib.parse.unquote(path)
    if "\x00" in decoded or "\\" in decoded:
        return True
    for segment in decoded.split("/"):
        if segment.split(";", 1)[0] in (".", ".."):
            return True
    return False


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cfpub-proxy"
    # Without this a client that stops mid-request pins a worker thread forever.
    timeout = 30

    def log_message(self, fmt, *args):
        sys.stderr.write("cfpub-proxy: " + (fmt % args) + "\n")

    # ------------------------------------------------------------- responses

    def _simple(self, code, text):
        body = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    # --------------------------------------------------------------- request

    def _pick(self, path):
        best = None
        for prefix, target in routes().items():
            if path == prefix or path.startswith(prefix + "/"):
                # Longest prefix wins, so /sxyz-79/web beats /sxyz-79.
                if best is None or len(prefix) > len(best[0]):
                    best = (prefix, target)
        return best

    def _read_body(self):
        """The request body, or None when a rejection has already been sent."""
        # Expect is stripped from the forwarded headers (http.client cannot do
        # 100-continue), so the interim response has to be produced here or the
        # client waits for it while we wait for a body that is never sent.
        if self.headers.get("Expect", "").lower() == "100-continue":
            self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            self.wfile.flush()
        if self.headers.get_all("Transfer-Encoding"):
            self._simple(400, "cfpub: Transfer-Encoding is not accepted\n")
            return None
        lengths = {v.strip() for v in (self.headers.get_all("Content-Length") or [])}
        if len(lengths) > 1:
            # Two different numbers are the classic request-smuggling setup; the
            # origin would frame the body differently than we did.
            self._simple(400, "cfpub: conflicting Content-Length\n")
            return None
        length = 0
        if lengths:
            raw = lengths.pop()
            if not raw.isdigit():
                self._simple(400, "cfpub: invalid Content-Length\n")
                return None
            length = int(raw)
            if length > MAX_BODY:
                self._simple(413, "cfpub: request body too large\n")
                return None
        if not length:
            return b""
        data = self.rfile.read(length)
        if len(data) != length:
            self._simple(400, "cfpub: truncated request body\n")
            return None
        return data

    def _forward_headers(self, prefix):
        headers = {}
        for key, value in self.headers.items():
            lowered = key.lower()
            if lowered in HOP_BY_HOP or lowered in UNTRUSTED:
                continue
            # An obs-folded continuation line arrives as a value containing CRLF
            # and http.client would re-emit it as a second header line upstream.
            if "\r" in value or "\n" in value:
                continue
            headers[key] = value
        headers["X-Forwarded-Prefix"] = prefix
        headers["X-Forwarded-For"] = self.client_address[0]
        host = self.headers.get("Host", "")
        if host and "\r" not in host and "\n" not in host:
            headers["X-Forwarded-Host"] = host
        return headers

    # -------------------------------------------------------------- proxying

    def _proxy(self):
        target_path = self.path
        split = urllib.parse.urlsplit(target_path)
        if split.scheme or split.netloc or not split.path.startswith("/"):
            # Absolute-form and //host forms would let the request line choose a
            # different authority; only origin-form paths are ours to serve.
            self._simple(400, "cfpub: only origin-form request paths are served\n")
            return
        if unsafe_path(split.path):
            self._simple(400, "cfpub: refusing a path with dot segments\n")
            return

        picked = self._pick(split.path)
        if not picked:
            self._simple(404, "cfpub: no service published at this path\n")
            return

        prefix, target = picked
        try:
            body = self._read_body()
        except TimeoutError:
            self._simple(408, "cfpub: request body timed out\n")
            return
        if body is None:
            return

        url = urllib.parse.urlsplit(target)
        base = url.path.rstrip("/")
        rest = split.path[len(prefix):] or "/"
        rest = base + rest
        if split.query:
            rest += "?" + split.query

        headers = self._forward_headers(prefix)

        if url.scheme == "https":
            context = ssl._create_unverified_context() if TLS_INSECURE else ssl.create_default_context()
            conn = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=60, context=context)
        elif url.scheme in ("http", ""):
            conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=60)
        else:
            sys.stderr.write("cfpub-proxy: unsupported target scheme %r\n" % url.scheme)
            self._simple(502, "cfpub: upstream unreachable\n")
            return

        try:
            try:
                conn.request(self.command, rest, body=body, headers=headers)
                resp = conn.getresponse()
            except Exception as exc:  # noqa: BLE001 - any upstream failure
                # The target URL may embed credentials; the client gets a fixed
                # string and the detail only reaches the operator's stderr.
                sys.stderr.write("cfpub-proxy: upstream %s unreachable: %s\n" % (target, exc))
                self._simple(502, "cfpub: upstream unreachable\n")
                return

            self.send_response(resp.status, resp.reason)
            for key, value in resp.getheaders():
                lowered = key.lower()
                if lowered in HOP_BY_HOP or lowered in ("content-length", "transfer-encoding"):
                    continue
                self.send_header(key, value)
            # http.client knows the upstream framing; re-state it rather than
            # letting the client guess. Unknown length (chunked upstream) is
            # delimited by the connection close below.
            # http.client sets length=0 for a HEAD response, which would tell
            # the client the entity is empty rather than merely unsent.
            declared = resp.length
            if self.command == "HEAD":
                raw = resp.getheader("Content-Length")
                if raw is not None and raw.strip().isdigit():
                    declared = int(raw.strip())
            if declared is not None:
                self.send_header("Content-Length", str(declared))
            self.send_header("Connection", "close")
            self.close_connection = True
            self.end_headers()

            if self.command == "HEAD" or resp.status in (204, 304):
                return

            # Stream instead of buffering: an origin that emits a large body
            # used to cost that much RAM in the proxy per concurrent request.
            remaining = resp.length
            while True:
                want = CHUNK if remaining is None else min(CHUNK, remaining)
                if want <= 0:
                    break
                chunk = resp.read(want)
                if not chunk:
                    break
                self.wfile.write(chunk)
                if remaining is not None:
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            return
        finally:
            conn.close()

    do_GET = _proxy
    do_HEAD = _proxy
    do_POST = _proxy
    do_PUT = _proxy
    do_PATCH = _proxy
    do_DELETE = _proxy
    do_OPTIONS = _proxy


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def process_request(self, request, client_address):
        # Refuse beyond the cap instead of spawning another thread: the point of
        # the cap is to bound threads, and a thread has to exist to wait for one.
        if not _slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            _slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            _slots.release()


def main():
    if not STATE:
        sys.exit("cfpub-proxy: CFPUB_STATE is not set")
    server = Server((BIND, PORT), Handler)
    sys.stderr.write("cfpub-proxy: listening on %s:%d (%d route(s))\n"
                     % (BIND, PORT, len(routes())))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

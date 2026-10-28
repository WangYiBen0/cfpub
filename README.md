# cfpub

Publish a local service to the internet with one command, under one Cloudflare
domain, addressed by path:

```
https://w1ngd1nga5ter.dpdns.org/sxyz-79/web/   ->  127.0.0.1:3000
https://w1ngd1nga5ter.dpdns.org/sxyz-79/ssh    ->  sshd on 127.0.0.1:22
```

No port forwarding, no public IP, no reverse proxy to configure by hand, and no
rebuild or restart when you add or remove a service.

```bash
./cfpub.sh pub web 3000        # done. the hostname is already live.
```

## Why

A wildcard DNS record plus a Cloudflare Tunnel already gets you from the edge to
your machine. What it does not give you is a way to *publish* something without
editing a config file and reloading the connector each time.

cfpub drives the Cloudflare API directly instead. The tunnel uses
`config_src=cloudflare`, so its ingress rules live in the API rather than in a
local YAML file — publishing is one HTTP call, effective within seconds. That
also makes it a plain shell script: nothing to install, nothing to rebuild.

## Requirements

| Dependency    | Why                                           |
| ------------- | --------------------------------------------- |
| `bash`        | the script itself                             |
| `curl`, `jq`  | Cloudflare API calls                          |
| `cloudflared` | the connector (`run`) and SSH access          |
| `python3`     | the prefix-stripping proxy for HTTP services  |

You also need a zone managed by Cloudflare and one named tunnel in that account.
Set both up once:

```bash
cloudflared tunnel login              # writes ~/.cloudflared/cert.pem
cloudflared tunnel create myhost      # prints the tunnel UUID
```

cfpub reads the account id, zone id and API token out of `cert.pem`, so there is
nothing else to configure and no secret in this repo.

## Usage

```bash
./cfpub.sh run                        # start proxy + connector (foreground)
./cfpub.sh pub web 3000               # -> /<machine>/web  -> 127.0.0.1:3000
./cfpub.sh pub ssh ssh://localhost:22 # -> /<machine>/ssh  -> sshd (raw TCP)
./cfpub.sh ls                         # what is published
./cfpub.sh rm web                     # unpublish
./cfpub.sh token                      # print the tunnel token (for debugging)
```

`run` serves everything you have published and blocks until interrupted. It
writes the tunnel token to a `0600` temporary file (so it never shows up in
`ps`) and removes it on exit.

### Running only one half

`run` starts two independent things: the **connector** (cloudflared, which joins
the tunnel) and the **proxy** (python, which serves HTTP routes). You can start
either on its own.

```bash
./cfpub.sh run --connector   # only cloudflared: enough for ssh://, tcp://, udp://
./cfpub.sh run --proxy       # only the HTTP proxy: connector runs elsewhere
./cfpub.sh run               # both (same as passing neither flag)
```

Pick `--connector` when you only publish raw TCP services: it needs neither
`python3` nor a route table, so it is the leanest thing to keep running, and it
is what you want in a startup unit. Pick `--proxy` when the connector already
runs as a service — for example a systemd unit that joins the tunnel at boot —
and you just want this shell to serve the HTTP paths.

The two halves are also useful side by side: a long-lived connector from systemd
(`run --connector` semantics) plus a foreground proxy to debug a route.

A second `run` refuses to start if the proxy port is already taken, so a stray
instance cannot silently shadow the one you think is serving traffic.

### HTTP services vs raw TCP

A bare port means **HTTP** and is sent through the local proxy, because
Cloudflare's ingress `path` matcher forwards the full path and an app would
otherwise see `/sxyz-79/web/foo` and 404:

```bash
./cfpub.sh pub web 3000          # http://127.0.0.1:3000, prefix stripped
```

An explicit scheme means the protocol is carried as-is, straight from the edge
to the port, with no proxy in between:

```bash
./cfpub.sh pub ssh ssh://localhost:22
./cfpub.sh pub db tcp://localhost:5432
```

Recognised as raw: `ssh://`, `rdp://`, `tcp://`, `udp://`, `smb://`. Anything
else with a scheme (`https://`, `http://`) goes through the proxy.

### Reaching a published SSH service

Cloudflare carries SSH over a WebSocket, so a plain `ssh host` will not work.
Use `cloudflared access` as the transport:

```bash
ssh -o ProxyCommand='cloudflared access ssh --hostname %h' \
    w1ngd1nga5ter@w1ngd1nga5ter.dpdns.org/sxyz-79/ssh
```

Or put it in `~/.ssh/config` once:

```
Host w1ngd1nga5ter.dpdns.org
  ProxyCommand cloudflared access ssh --hostname %h
  User w1ngd1nga5ter
```

## How it works

```
client
  |  https://<domain>/<machine>/<service>/...
  v
Cloudflare edge          ingress rule: path ^/<machine>/<service> -> 127.0.0.1:8080
  |                      (a real TLS-terminating proxy, so nothing listens publicly)
  v
cloudflared              the tunnel connector, dials out only
  |
  v
cfpub-proxy.py           :8080, strips /<machine>/<service>, forwards to the target
  |
  v
your service             :3000, :8000, whatever
```

Publishing rewrites the tunnel's ingress list so that:

1. path rules come first, longest path first (Cloudflare matches top-down),
2. then an apex catch-all pointing at the proxy,
3. then `http_status:404` — the API rejects any list that does not end with an
   unfiltered rule.

Rules for other hostnames are preserved verbatim, so cfpub coexists with
subdomains you wired up by hand.

The proxy reads its route table (`routes.json`) on demand, keyed by mtime, so
`pub` and `rm` take effect on the next request without restarting anything.

## Configuration

Every setting has a default; none are required.

| Variable                             | Default                        | Purpose                                     |
| ------------------------------------ | ------------------------------ | ------------------------------------------- |
| `CFPUB_HOST_NAME`                    | `hostname -s`, lowercased      | Path segment identifying this machine       |
| `CFPUB_TUNNEL_ID`                    | auto if the account has one    | Which tunnel to publish into                |
| `CFPUB_DOMAIN`                       | read from the zone id          | Domain to publish under                     |
| `CFPUB_CERT`                         | `~/.cloudflared/cert.pem`      | Where the ARGO credentials live             |
| `CFPUB_PROXY_PORT`                   | `8080`                         | Where the prefix-stripping proxy binds      |
| `CFPUB_STATE`                        | `$XDG_STATE_HOME/cfpub/routes.json` | Proxy route table                      |
| `CFPUB_RETRIES`                      | `4`                            | Attempts per API call on connection failure |
| `CFPUB_MAX_BODY`                      | `64m`                          | Largest request body the proxy buffers |
| `CFPUB_MAX_CONNECTIONS`               | `256`                          | Concurrent connections the proxy accepts |
| `CFPUB_TLS_INSECURE`                  | off                            | Accept self-signed certs from `https://` targets |
| `CFPUB_API_TOKEN`, `CFPUB_ACCOUNT_ID`, `CFPUB_ZONE_ID` | from `cert.pem` | Override the parsed credentials |

The route table falls back to `/tmp` and then to `./cfpub/` if the state
directory is not writable, and only errors out if none of those work.

If the account holds more than one tunnel, cfpub refuses to guess: it lists them
and asks for `CFPUB_TUNNEL_ID`.

## Limits

- **One machine per path segment.** Two machines need two `CFPUB_HOST_NAME`
  values; they can share the zone, the apex record *and* the tunnel. The
  ingress rules are keyed by the pair `(hostname, path)`, so machines sharing a
  tunnel never overwrite each other's `/<machine>/<service>` rules even when
  they publish the same service name — one path rule per machine, all pointing
  at port 8080. `ls` prints the hostname as its first column because, on a
  shared tunnel, the path alone does not identify a rule.
- **The proxy speaks HTTP/1.1 only.** It does not tunnel WebSocket upgrades —
  it strips `Upgrade`/`Connection`. Publish a WebSocket service over raw TCP
  instead, or put it behind a hostname of its own.
- **Request bodies are buffered, responses are streamed.** A body larger than
  `CFPUB_MAX_BODY` is refused with 413 rather than buffered, and one connection
  per request keeps framing predictable — at the cost of keep-alive reuse.
  `Transfer-Encoding: chunked` is rejected outright.
- **Apps must be prefix-aware.** The proxy sets `X-Forwarded-Prefix` and strips
  the prefix before forwarding, but an app that emits absolute URLs in its HTML
  or redirects will need to be told about the prefix.
- **The ingress `path` value is a regex**, and cfpub writes it unanchored, so
  `/x/sxyz-79/web` also matches the rule. The proxy then 404s it, since it only
  strips an exact prefix — harmless, but not tight. Because the path is a
  regex, the machine segment is restricted to letters, digits and inner dashes;
  a value like `.*` would otherwise match every machine's rules.
- **`run` must stay running.** Publishing only writes edge configuration; with
  no connector up, the edge answers `530` or `websocket: bad handshake`.

## Security

`pub ssh ssh://localhost:22` exposes sshd to the whole internet. Cloudflare
proxies the bytes but does not authenticate the user, so anyone can reach it and
try to log in. Before you do that:

- disable `PasswordAuthentication` and use keys only, and
- consider a Cloudflare Access policy on the path (`Self-hosted` application),
  so the edge rejects unauthenticated requests before they reach you.

The tunnel token is an account-wide credential. cfpub keeps it in a `0600`
temporary file for the connector's lifetime and never writes it anywhere else.
The API token is never put on a command line either — it reaches `curl` through
a config on a file descriptor, so it does not show up in `ps` or
`/proc/<pid>/cmdline`. `token` warns when its output is not a terminal.

The proxy treats everything it receives as hostile, since the tunnel is on the
public internet and the listening port is on localhost:

- dot segments (`..`, `%2e%2e`, `..;`) are refused, so a published prefix stays
  a prefix rather than a suggestion to the origin;
- `Transfer-Encoding` and conflicting `Content-Length` are refused, which closes
  the request-smuggling path around path-based access rules;
- `X-Forwarded-For`, `X-Forwarded-Prefix` and friends from the client are
  dropped and re-derived, so they cannot be spoofed;
- upstream failures return a fixed 502, so a target URL that embeds credentials
  is not echoed to the client;
- connections and body size are capped, and a stuck client is dropped after 30s.

`routes.json` is written atomically with `mktemp` and is `0600`; the directory
holding it must be owned by the invoking user, not a symlink, and not
group/other-writable. A present-but-unparseable table is an error, not an
invitation to start from scratch, because it holds every published route.

## Layout

```
cfpub.sh          CLI: credentials, API calls, ingress rewriting
cfpub-proxy.py    HTTP/1.1 reverse proxy that strips the path prefix
```

## License

MIT — see [LICENSE](LICENSE).

[![](https://img.shields.io/badge/powered_by-dsh-4D6BFE?style=flat-square&logo=deepseek&logoColor=white)](https://github.com/deepseek-ai/deepseek-harness)

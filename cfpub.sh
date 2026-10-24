#!/usr/bin/env bash
# cfpub - publish local services under one domain, addressed by path.
#
#   https://<domain>/<machine>/<service>   ->  a local port
#
# The tunnel uses config_src=cloudflare, so ingress rules live in the Cloudflare
# API. Publishing is therefore a pure API call: no rebuild, no connector
# restart, effective within seconds.
#
# HTTP services are routed through cfpub-proxy.py, because Cloudflare's ingress
# `path` matcher forwards the full path unchanged -- an app would see
# /machine/service/foo and 404. SSH and other raw TCP services need no proxy;
# they match on path too and reach sshd directly.
#
# Credentials come from the ARGO token that `cloudflared tunnel login` writes to
# ~/.cloudflared/cert.pem, so nothing secret is stored in this repo.

set -euo pipefail

API_BASE=https://api.cloudflare.com/client/v4
NAME_RE='^[a-z0-9]([a-z0-9-]*[a-z0-9])?$'
TUNNEL_SUFFIX=.cfargotunnel.com

PROXY_PORT=${CFPUB_PROXY_PORT:-8080}
SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Route table for the proxy. XDG_STATE_HOME is the conventional spot, but it is
# not always writable (containers, read-only $HOME), so fall back to /tmp and
# finally to the repo next to this script.
default_state() {
  local dir
  for dir in "${XDG_STATE_HOME:-$HOME/.local/state}/cfpub" /tmp/cfpub "$SELF_DIR/cfpub"; do
    if mkdir -p "$dir" 2>/dev/null; then
      printf '%s/routes.json' "$dir"
      return 0
    fi
  done
  die "no writable directory for the route table; set CFPUB_STATE"
}
STATE=${CFPUB_STATE:-}

die() {
  printf 'cfpub: %s\n' "$*" >&2
  exit 1
}
warn() {
  printf 'cfpub: %s\n' "$*" >&2
}
usage() {
  cat <<'EOF'
cfpub - publish local services under one domain, addressed by path

  https://<domain>/<machine>/<service>   ->   a local port

Usage:
  cfpub.sh pub <service> <port|url>   publish /<machine>/<service> -> local service
  cfpub.sh rm <service>               unpublish
  cfpub.sh ls                         list published paths and targets
  cfpub.sh run [--proxy|--connector]   run either half or both (default: both)

Run selectors:
  --connector   only cloudflared. Enough for raw TCP services (ssh://, tcp://);
                needs neither python3 nor a route table.
  --proxy       only the HTTP proxy. Use when the connector already runs
                elsewhere (systemd unit, another shell); needs no credentials.
  (none)        both, the normal case.

Examples:
  cfpub.sh pub web 3000               https://<domain>/<machine>/web -> 127.0.0.1:3000
  cfpub.sh pub ssh ssh://localhost:22 https://<domain>/<machine>/ssh -> sshd (raw TCP)
  cfpub.sh pub api https://127.0.0.1:8443
  cfpub.sh rm web

A bare port always means HTTP and goes through the local proxy (which strips
the path prefix); give an explicit scheme to carry another protocol as-is.

The <machine> segment defaults to `hostname -s` (so this host publishes
/sxyz-79/...); override with CFPUB_HOST_NAME.

Environment:
  CFPUB_HOST_NAME   path segment for this machine (default: hostname -s)
  CFPUB_TUNNEL_ID   tunnel to publish into (auto-detected if the account holds
                    exactly one tunnel)
  CFPUB_DOMAIN      zone to publish under (read from the zone id otherwise)
  CFPUB_CERT        ARGO certificate (default: ~/.cloudflared/cert.pem)
  CFPUB_PROXY_PORT  local port the path-stripping proxy binds (default: 8080)
  CFPUB_STATE       proxy route table (default: $XDG_STATE_HOME/cfpub/routes.json,
                    falling back to /tmp/cfpub then ./cfpub)
  CFPUB_RETRIES     attempts per API call on connection failure (default: 4)
  CFPUB_API_TOKEN, CFPUB_ACCOUNT_ID, CFPUB_ZONE_ID
                    override the values parsed from the certificate
EOF
}

# ---------------------------------------------------------------- credentials

load_credentials() {
  if [ -n "${CFPUB_API_TOKEN:-}" ] && [ -n "${CFPUB_ACCOUNT_ID:-}" ] && [ -n "${CFPUB_ZONE_ID:-}" ]; then
    return 0
  fi

  local cert=${CFPUB_CERT:-$HOME/.cloudflared/cert.pem}
  [ -r "$cert" ] || die "cannot read $cert (run 'cloudflared tunnel login' first)"

  # cert.pem embeds the account token as base64-encoded JSON between ARGO
  # markers; the surrounding lines are PEM framing and must be stripped first.
  local blob
  blob=$(sed -n '/BEGIN ARGO TUNNEL TOKEN/,/END ARGO TUNNEL TOKEN/p' "$cert" |
    grep -v -- '-----' | tr -d '\n' | base64 -d) || die "cannot decode the ARGO token in $cert"

  CFPUB_API_TOKEN=${CFPUB_API_TOKEN:-$(jq -r '.apiToken // empty' <<<"$blob")}
  CFPUB_ACCOUNT_ID=${CFPUB_ACCOUNT_ID:-$(jq -r '.accountID // empty' <<<"$blob")}
  CFPUB_ZONE_ID=${CFPUB_ZONE_ID:-$(jq -r '.zoneID // empty' <<<"$blob")}

  [ -n "$CFPUB_API_TOKEN" ] || die "no API token in $cert"
  [ -n "$CFPUB_ACCOUNT_ID" ] || die "no account id in $cert"
  [ -n "$CFPUB_ZONE_ID" ] || die "no zone id in $cert"
}

api() {
  local method=$1 path=$2 data=${3:-}
  if [ -n "$data" ]; then
    curl -sS --connect-timeout 10 --max-time 30 -X "$method" \
      -H "Authorization: Bearer $CFPUB_API_TOKEN" \
      -H 'Content-Type: application/json' \
      --data "$data" "$API_BASE$path"
  else
    curl -sS --connect-timeout 10 --max-time 30 -X "$method" \
      -H "Authorization: Bearer $CFPUB_API_TOKEN" "$API_BASE$path"
  fi
}

# Cloudflare reports failures in the body with HTTP 200, so every mutating call
# has to look at .success rather than the status code.
api_ok() {
  local out attempts=${CFPUB_RETRIES:-4} i=1
  # A dropped TLS handshake says nothing about the request, so retry it; a real
  # API error is returned with .success=false and must not be retried.
  while :; do
    if out=$(api "$@" 2>/dev/null); then
      break
    fi
    if [ "$i" -ge "$attempts" ]; then
      die "request failed after $attempts attempts: $1 $2"
    fi
    i=$((i + 1))
    sleep 1
  done

  if ! jq -e '.success == true' >/dev/null 2>&1 <<<"$out"; then
    local detail
    detail=$(jq -r '[.errors[]? | "\(.code) \(.message)"] | join("; ")' <<<"$out" 2>/dev/null || true)
    die "API rejected $1 $2: ${detail:-$out}"
  fi
  printf '%s' "$out"
}

# -------------------------------------------------------------------- lookups

tunnel_id() {
  if [ -n "${CFPUB_TUNNEL_ID:-}" ]; then
    printf '%s' "$CFPUB_TUNNEL_ID"
    return 0
  fi

  local out count
  out=$(api_ok GET "/accounts/$CFPUB_ACCOUNT_ID/cfd_tunnel?is_deleted=false")
  count=$(jq '.result | length' <<<"$out")
  case $count in
    0) die "no tunnel in this account (create one with 'cloudflared tunnel create <name>')" ;;
    1) jq -r '.result[0].id' <<<"$out" ;;
    *)
      warn "account holds $count tunnels; pick one via CFPUB_TUNNEL_ID:"
      jq -r '.result[] | "  \(.id)  \(.name)"' <<<"$out" >&2
      exit 1
      ;;
  esac
}

zone_domain() {
  if [ -n "${CFPUB_DOMAIN:-}" ]; then
    printf '%s' "$CFPUB_DOMAIN"
    return 0
  fi
  api_ok GET "/zones/$CFPUB_ZONE_ID" | jq -r '.result.name'
}

machine_segment() {
  if [ -n "${CFPUB_HOST_NAME:-}" ]; then
    printf '%s' "$CFPUB_HOST_NAME"
    return 0
  fi
  local short
  short=$(hostname -s)
  printf '%s' "$short" | tr '[:upper:]' '[:lower:]'
}

ingress_path() {
  printf '/accounts/%s/cfd_tunnel/%s/configurations' "$CFPUB_ACCOUNT_ID" "$(tunnel_id)"
}

proxy_service() {
  printf 'http://127.0.0.1:%s' "$PROXY_PORT"
}

# ----------------------------------------------------------- route table file

# The proxy reads this on demand, so publishing never restarts anything. Only
# HTTP targets need an entry; raw TCP services are wired straight into ingress.
state_update() {
  local prefix=$1 target=$2
  mkdir -p "$(dirname -- "$STATE")"
  local current={}
  if [ -s "$STATE" ]; then
    current=$(jq -c . "$STATE" 2>/dev/null || echo '{}')
  fi
  jq -nc --argjson cur "$current" --arg p "$prefix" --arg t "$target" '
    $cur + {http: (($cur.http // {}) + {($p): $t})}
  ' >"$STATE.tmp" && mv "$STATE.tmp" "$STATE"
}

state_remove() {
  local prefix=$1
  [ -s "$STATE" ] || return 0
  jq -c --arg p "$prefix" 'del(.http[$p])' "$STATE" >"$STATE.tmp" && mv "$STATE.tmp" "$STATE"
}

state_target() {
  [ -s "$STATE" ] || return 0
  jq -r --arg p "$1" '.http[$p] // empty' "$STATE" 2>/dev/null
}

# ------------------------------------------------------------------- ingress

# Rebuilds the ordered ingress list. Cloudflare matches top-down and requires
# the final rule to be unfiltered, so path rules go first (most specific mode
# first), then the apex catch-all into the proxy, then http_status:404.
rewrite_ingress() {
  local apex=$1 prefix=$2 service=${3:-} current next

  current=$(api_ok GET "$(ingress_path)" | jq -c '.result.config.ingress // []')

  next=$(jq -c --arg apex "$apex" --arg p "$prefix" --arg s "$service" --arg proxy "$(proxy_service)" '
    . as $in
    # Other path rules survive untouched; the one for $p is replaced (or
    # dropped when $s is empty, which is what rm does).
    | [ $in[] | select(has("path")) | select(.path != $p) ] as $paths
    | [ $in[] | select(has("hostname")) | select(.hostname != $apex) ] as $others
    | ($paths + (if $s == "" then [] else [{hostname: $apex, path: $p, service: $s}] end)) as $joined
    | ($joined | unique_by(.path)) as $uniq
    # Longest path first: Cloudflare matches top-down, so /a/b must precede /a.
    | ($uniq | sort_by(.path | length) | reverse) as $sorted
    | $others + $sorted + [{hostname: $apex, service: $proxy}] + [{service: "http_status:404"}]
  ' <<<"$current")

  api_ok PUT "$(ingress_path)" "$(jq -nc --argjson i "$next" '{config: {ingress: $i}}')" >/dev/null
}

ensure_apex_dns() {
  local apex=$1 tid existing payload
  tid=$(tunnel_id)
  existing=$(api_ok GET "/zones/$CFPUB_ZONE_ID/dns_records?type=CNAME&name=$apex" |
    jq -r '.result[0].id // empty')
  [ -n "$existing" ] && return 0

  # The apex record makes <domain>/<path> resolvable at all; subdomains from an
  # earlier layout are left alone.
  payload=$(jq -nc --arg n "$apex" --arg c "$tid$TUNNEL_SUFFIX" \
    '{type: "CNAME", name: $n, content: $c, proxied: true, ttl: 1}')
  api_ok POST "/zones/$CFPUB_ZONE_ID/dns_records" "$payload" >/dev/null
  warn "created DNS record for $apex"
}

# ------------------------------------------------------------------- commands

# SSH/RDP and friends are raw TCP: Cloudflare carries them as-is, so they go
# straight from the edge to the port and never touch the HTTP proxy.
is_raw_service() {
  case $1 in
    ssh://* | rdp://* | tcp://* | udp://* | smb://* | tcp+* | *://*:*tcp*) return 0 ;;
    *) return 1 ;;
  esac
}

cmd_pub() {
  local service=${1:-} target=${2:-} resolved
  [ -n "$service" ] && [ -n "$target" ] || die "usage: cfpub.sh pub <service> <port|url>"
  [[ $service =~ $NAME_RE ]] || die "invalid name '$service' (lowercase letters, digits and inner dashes)"

  case $target in
    *://*) resolved=$target ;;
    *[!0-9]*) die "target '$target' is neither a port nor a URL with a scheme" ;;
    *) resolved="http://127.0.0.1:$target" ;;
  esac

  local apex prefix
  apex=$(zone_domain)
  prefix="/$(machine_segment)/$service"

  ensure_apex_dns "$apex"

  if is_raw_service "$resolved"; then
    rewrite_ingress "$apex" "$prefix" "$resolved"
    state_remove "$prefix"
    printf '  https://%s%s -> %s (raw TCP)\n' "$apex" "$prefix" "$resolved" >&2
  else
    # HTTP goes through the proxy, which strips the prefix before forwarding.
    rewrite_ingress "$apex" "$prefix" "$(proxy_service)"
    state_update "$prefix" "$resolved"
    printf '  https://%s%s/ -> %s\n' "$apex" "$prefix" "$resolved" >&2
    printf '  (proxy route written; run "cfpub.sh run" to serve it)\n' >&2
  fi
}

cmd_rm() {
  local service=${1:-}
  [ -n "$service" ] || die "usage: cfpub.sh rm <service>"
  [[ $service =~ $NAME_RE ]] || die "invalid name '$service'"

  local apex prefix
  apex=$(zone_domain)
  prefix="/$(machine_segment)/$service"

  rewrite_ingress "$apex" "$prefix"
  state_remove "$prefix"
  printf '  unpublished %s%s\n' "$apex" "$prefix" >&2
}

cmd_ls() {
  local apex ingress
  apex=$(zone_domain)
  ingress=$(api_ok GET "$(ingress_path)" | jq -c '.result.config.ingress // []')

  # Show the local target rather than the proxy hop, which is an implementation
  # detail no one publishing a service cares about.
  jq -r --arg proxy "$(proxy_service)" --argjson routes \
    "$([ -s "$STATE" ] && jq -c '.http // {}' "$STATE" || echo '{}')" '
    [ .[] | select(has("path")) ][]
    | .path as $p
    | (($routes[$p] // .service)) as $shown
    | (if ($shown | startswith("http")) and ($shown == $proxy) then "UNROUTED" else "" end) as $warn
    | "\($p)\t\($shown)\t\($warn)"
  ' <<<"$ingress" | column -t -s $'\t' 2>/dev/null ||
    jq -r --arg proxy "$(proxy_service)" --argjson routes \
      "$([ -s "$STATE" ] && jq -c '.http // {}' "$STATE" || echo '{}')" '
      [ .[] | select(has("path")) ][]
      | .path as $p | (($routes[$p] // .service)) as $shown
      | "\($p)\t\($shown)"
    ' <<<"$ingress"
}

cmd_token() {
  api_ok GET "/accounts/$CFPUB_ACCOUNT_ID/cfd_tunnel/$(tunnel_id)/token" | jq -r '.result'
}

# Which halves of `run` to start; see parse_run_args.
RUN_PROXY=0
RUN_CONNECTOR=0
PROXY_PID=
TOK_FILE=

# Something already listening on the port means a second `run` would otherwise
# leave the old proxy in place and fail only on the first request.
port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
  return 1
}

cleanup() {
  [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null
  [ -n "$TOK_FILE" ] && rm -f "$TOK_FILE"
  return 0
}

parse_run_args() {
  local arg
  for arg in "$@"; do
    case $arg in
      --proxy) RUN_PROXY=1 ;;
      --connector) RUN_CONNECTOR=1 ;;
      *) die "unknown option for run: '$arg' (try --help)" ;;
    esac
  done
  # No selector means both, which is what most invocations want.
  if [ "$RUN_PROXY" -eq 0 ] && [ "$RUN_CONNECTOR" -eq 0 ]; then
    RUN_PROXY=1
    RUN_CONNECTOR=1
  fi
}

http_route_count() {
  if [ -s "$STATE" ]; then
    jq -r '.http | length' "$STATE" 2>/dev/null || printf '0'
  else
    printf '0'
  fi
}

cmd_run() {
  if [ "$RUN_PROXY" -eq 1 ]; then
    command -v python3 >/dev/null || die "python3 not found on PATH (needed for the HTTP proxy)"
    [ -r "$SELF_DIR/cfpub-proxy.py" ] || die "cfpub-proxy.py missing next to this script"
    port_in_use "$PROXY_PORT" &&
      die "port $PROXY_PORT already in use (another 'cfpub.sh run'?); set CFPUB_PROXY_PORT"
    mkdir -p "$(dirname -- "$STATE")"
    [ -s "$STATE" ] || echo '{"http":{}}' >"$STATE"
  fi

  if [ "$RUN_CONNECTOR" -eq 1 ]; then
    command -v cloudflared >/dev/null || die "cloudflared not found on PATH"
    # A file rather than --token keeps the secret out of `ps`; 0600 in a temp
    # dir only this user can read.
    TOK_FILE=$(mktemp)
    chmod 600 "$TOK_FILE"
  fi

  trap cleanup EXIT INT TERM

  if [ "$RUN_PROXY" -eq 1 ]; then
    CFPUB_STATE=$STATE CFPUB_PROXY_PORT=$PROXY_PORT \
      python3 "$SELF_DIR/cfpub-proxy.py" &
    PROXY_PID=$!
  fi

  # Proxy only: nothing else to supervise, so wait on it and let the trap clean
  # up. Name the missing connector, because the edge answers 530 and that looks
  # like a broken route rather than a half that simply is not running.
  if [ "$RUN_CONNECTOR" -eq 0 ]; then
    warn "proxy only on 127.0.0.1:$PROXY_PORT; no connector, so the edge answers 530 until one runs"
    wait "$PROXY_PID"
    return 0
  fi

  # Connector only, with HTTP routes published: the paths point at a proxy that
  # is not running here, so say so now rather than let them fail silently.
  if [ "$RUN_PROXY" -eq 0 ] && [ "$(http_route_count)" -gt 0 ]; then
    warn "HTTP routes are published but the proxy is off; those paths will fail"
  fi

  cmd_token >"$TOK_FILE"
  if [ "$RUN_PROXY" -eq 1 ]; then
    printf 'cfpub: proxy on 127.0.0.1:%s, connector for tunnel %s\n' "$PROXY_PORT" "$(tunnel_id)" >&2
  else
    printf 'cfpub: connector for tunnel %s (no proxy)\n' "$(tunnel_id)" >&2
  fi

  # `exec` would replace this shell and skip the trap, so run it as a child and
  # keep the trap alive to reap the proxy.
  local rc=0
  cloudflared tunnel --no-autoupdate run --token-file "$TOK_FILE" || rc=$?
  [ "$rc" -ne 0 ] && warn "cloudflared exited with status $rc"
  return 0
}

# ----------------------------------------------------------------------- main

main() {
  local cmd=${1:-}
  shift || true
  case $cmd in
    pub | rm | ls | token | run) ;;
    -h | --help | help | '') usage && exit 0 ;;
    *) die "unknown command '$cmd' (try --help)" ;;
  esac

  # `run --proxy` touches no API at all, so it must work before `tunnel login`.
  if [ "$cmd" = run ]; then
    parse_run_args "$@"
    STATE=${STATE:-$(default_state)}
    if [ "$RUN_CONNECTOR" -eq 1 ]; then
      load_credentials
    fi
    cmd_run
    return 0
  fi

  load_credentials
  STATE=${STATE:-$(default_state)}
  case $cmd in
    pub) cmd_pub "$@" ;;
    rm) cmd_rm "$@" ;;
    ls) cmd_ls "$@" ;;
    token) cmd_token "$@" ;;
  esac
}

main "$@"

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
# Path segment for this machine. Stricter than NAME_RE on purpose: the ingress
# `path` is a regex, so a segment containing `.`, `|`, `*` or `/` would not be
# matched literally -- `CFPUB_HOST_NAME='.*'` used to publish `/.*/web`, which
# matches every machine's `/web`.
HOST_RE='^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$'
# A zone name, optionally with subdomains. No regex metacharacters, no scheme,
# no trailing slash.
DOMAIN_RE='^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$'
TUNNEL_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
TUNNEL_SUFFIX=.cfargotunnel.com

PROXY_PORT=${CFPUB_PROXY_PORT:-8080}
SELF_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

# Route table for the proxy. XDG_STATE_HOME is the conventional spot, but it is
# not always writable (containers, read-only $HOME), so fall back to /tmp and
# finally to the repo next to this script.
#
# The probe has to actually write, not just `mkdir -p`: that returns success on
# any existing directory, so an unwritable one looked writable and `pub` then
# failed *after* DNS and ingress were already committed. And a directory the
# state file lives in is trusted input -- whoever owns it can rewrite routes and
# turn the proxy into an SSRF -- so only a directory we own, that is not a
# symlink, is accepted.
state_dir_ok() {
  local dir=$1 mode probe
  [ -d "$dir" ] || return 1
  # A symlink is not the directory it names: the attacker controls the target.
  [ -L "$dir" ] && return 1
  [ -O "$dir" ] || return 1
  # Group/other-writable means someone else can replace routes.json between
  # writes, which is the same control with an extra step.
  mode=$(stat -c %a "$dir" 2>/dev/null) || return 1
  # The last two octets are the group and other permission triples; octets with
  # the write bit set (2, 3, 6, 7) mean a second user can manipulate the table.
  case ${mode: -2} in
    *2* | *3* | *6* | *7*) return 1 ;;
  esac
  probe=$(mktemp -p "$dir" .cfpub-probe.XXXXXX 2>/dev/null) || return 1
  rm -f "$probe"
  return 0
}

default_state() {
  local dir
  for dir in "${XDG_STATE_HOME:-$HOME/.local/state}/cfpub" /tmp/cfpub "$SELF_DIR/cfpub"; do
    # Only create when missing: `install -d` on an existing directory also
    # rewrites its mode, and silently loosening or tightening a directory the
    # user set up themselves is not ours to do.
    [ -d "$dir" ] || install -d -m 700 "$dir" 2>/dev/null || true
    if state_dir_ok "$dir"; then
      printf '%s/routes.json' "$dir"
      return 0
    fi
  done
  die "no writable directory owned by $(id -un) for the route table; set CFPUB_STATE"
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
  CFPUB_HOST_NAME   path segment for this machine (default: hostname -s);
                    letters, digits and inner dashes only
  CFPUB_TUNNEL_ID   tunnel to publish into (auto-detected if the account holds
                    exactly one tunnel)
  CFPUB_DOMAIN      zone to publish under (read from the zone id otherwise);
                    a bare zone name, no scheme and no trailing slash
  CFPUB_CERT        ARGO certificate (default: ~/.cloudflared/cert.pem)
  CFPUB_PROXY_PORT  local port the path-stripping proxy binds (default: 8080)
  CFPUB_MAX_BODY    largest request body the proxy will buffer (default: 64m)
  CFPUB_MAX_CONNECTIONS
                    concurrent connections the proxy accepts (default: 256)
  CFPUB_TLS_INSECURE
                    accept self-signed certs from https:// targets (default: off)
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

  # A newline in the token would become a second header line in the curl config.
  CFPUB_API_TOKEN=${CFPUB_API_TOKEN//[$'\r\n']/}
  [ -n "$CFPUB_API_TOKEN" ] || die "no API token in $cert"
  [ -n "$CFPUB_ACCOUNT_ID" ] || die "no account id in $cert"
  [ -n "$CFPUB_ZONE_ID" ] || die "no zone id in $cert"
}

api() {
  local method=$1 path=$2 data=${3:-}
  # The token must not appear in argv: /proc/<pid>/cmdline is world-readable, so
  # any local user could read an account-wide credential straight out of `ps`.
  # A config on a file descriptor keeps it out of the process listing.
  local cfg tok
  # curl's config parser honours \ and " inside a quoted value, so a token that
  # contained either would end the string early and inject a stray directive.
  tok=${CFPUB_API_TOKEN//\\/\\\\}
  tok=${tok//\"/\\\"}
  cfg=$(printf 'header = "Authorization: Bearer %s"\nheader = "Content-Type: application/json"\n' "$tok")
  if [ -n "$data" ]; then
    curl -sS --connect-timeout 10 --max-time 30 -X "$method" \
      -K <(printf '%s' "$cfg") --data "$data" "$API_BASE$path"
  else
    curl -sS --connect-timeout 10 --max-time 30 -X "$method" \
      -K <(printf '%s' "$cfg") "$API_BASE$path"
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
    [[ $CFPUB_TUNNEL_ID =~ $TUNNEL_RE ]] ||
      die "CFPUB_TUNNEL_ID is not a tunnel UUID: '$CFPUB_TUNNEL_ID'"
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
  local name
  if [ -n "${CFPUB_DOMAIN:-}" ]; then
    name=$CFPUB_DOMAIN
  else
    name=$(api_ok GET "/zones/$CFPUB_ZONE_ID" | jq -r '.result.name')
  fi
  [[ $name =~ $DOMAIN_RE ]] ||
    die "invalid domain '$name' (expected a bare zone name, e.g. example.com)"
  printf '%s' "$name"
}

machine_segment() {
  local short
  if [ -n "${CFPUB_HOST_NAME:-}" ]; then
    short=$CFPUB_HOST_NAME
  else
    short=$(hostname -s)
  fi
  # This segment is pasted into an ingress `path`, which Cloudflare treats as a
  # regex, and into the proxy's prefix match, which is a literal string. A value
  # containing `.`, `|`, `*`, `/` or a newline is not a machine name in either
  # sense, and `.*` would make every machine's rules match.
  [[ $short =~ $HOST_RE ]] ||
    die "invalid machine segment '$short' in CFPUB_HOST_NAME/hostname (letters, digits and inner dashes)"
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

# Writes the route table atomically. The temp file is created with mktemp, not
# a predictable NAME.tmp: in a shared directory a predictable name is a symlink
# target, and `jq > "$STATE.tmp"` follows the link and overwrites whatever it
# points at. It is 0600 because a target URL can embed credentials.
state_write() {
  local dir tmp
  dir=$(dirname -- "$STATE")
  mkdir -p "$dir"
  tmp=$(mktemp -p "$dir" .routes.XXXXXX) || die "cannot create a temp file in $dir"
  chmod 600 "$tmp" 2>/dev/null || true
  if ! cat >"$tmp"; then
    rm -f "$tmp"
    die "cannot write the route table in $dir"
  fi
  mv -f "$tmp" "$STATE" || { rm -f "$tmp"; die "cannot replace $STATE"; }
}

# The route table is the proxy's whole idea of what to serve, so a present but
# unparseable file is not "empty": resetting it would silently drop every route.
state_load() {
  local cur
  [ -s "$STATE" ] || { printf '{"http":{}}'; return 0; }
  if ! cur=$(jq -c . "$STATE" 2>/dev/null); then
    die "$STATE is not valid JSON; fix or remove it (every route lives there)"
  fi
  printf '%s' "$cur"
}

state_update() {
  local prefix=$1 target=$2 current
  current=$(state_load)
  jq -nc --argjson cur "$current" --arg p "$prefix" --arg t "$target" '
    $cur + {http: (($cur.http // {}) + {($p): $t})}
  ' | state_write
}

state_remove() {
  local prefix=$1 current
  [ -s "$STATE" ] || return 0
  current=$(state_load)
  printf '%s' "$current" | jq -c --arg p "$prefix" 'del(.http[$p])' | state_write
}

state_target() {
  [ -s "$STATE" ] || return 0
  jq -r --arg p "$1" '.http[$p] // empty' "$STATE" 2>/dev/null
}

# ------------------------------------------------------------------- ingress

# Rebuilds the ordered ingress list. Cloudflare matches top-down and requires
# the final rule to be unfiltered, so path rules go first (most specific first),
# then per-hostname tails, then the apex catch-all into the proxy, then any
# legacy unfiltered rule, then http_status:404.
#
# A rule is *ours* only when the hostname AND the path both match. Several
# machines can share one tunnel, and each publishes under its own host; a rule
# that merely shares a path with ours belongs to somebody else and has to
# survive unchanged. Selecting on `.path` alone is what made `pub`/`rm` delete
# and duplicate other hosts' rules, because in a shared tunnel the path is not
# unique -- (hostname, path) is.
rewrite_ingress() {
  local apex=$1 prefix=$2 service=${3:-} current next

  current=$(api_ok GET "$(ingress_path)" | jq -c '.result.config.ingress // []')

  next=$(jq -c --arg apex "$apex" --arg p "$prefix" --arg s "$service" --arg proxy "$(proxy_service)" '
    . as $in
    # Drop exactly three things: the rule we are replacing, our own apex
    # catch-all (rewritten below, so it tracks CFPUB_PROXY_PORT), and the
    # synthetic 404 (re-appended as the sentinel). Everything else is kept.
    | [ $in[]
        | select((((.hostname // "") == $apex) and ((.path // "") == $p)) | not)
        | select((((.hostname // "") == $apex) and (has("path") | not)) | not)
        | select((((.service // "") == "http_status:404") and (has("hostname") | not) and (has("path") | not)) | not)
      ] as $kept
    # Hostname-scoped rules without a path: other subdomains wired up by hand.
    | [ $kept[] | select(has("path") | not) | select(has("hostname")) ] as $tails
    # Rules with neither hostname nor path match every request. Deleting them
    # used to leave a hole where the operator had put a fallback on purpose.
    | [ $kept[] | select((has("path") or has("hostname")) | not) ] as $legacy
    | ([ $kept[] | select(has("path")) ]
       + (if $s == "" then [] else [{hostname: $apex, path: $p, service: $s}] end)) as $paths
    # (hostname, path) identifies a rule; collapsing on path alone merged rules
    # that belong to different hosts into one and silently dropped the loser.
    # Equal-length paths put the hostname-scoped rule first so a path-only rule
    # for the same prefix cannot shadow it.
    | ($paths
       | unique_by([(.hostname // ""), (.path // "")])
       | sort_by([-(.path | length), (has("hostname") | not), (.hostname // "")])) as $sorted
    | $sorted + $tails + [{hostname: $apex, service: $proxy}] + $legacy + [{service: "http_status:404"}]
  ' <<<"$current")

  api_ok PUT "$(ingress_path)" "$(jq -nc --argjson i "$next" '{config: {ingress: $i}}')" >/dev/null
}

ensure_apex_dns() {
  local apex=$1 tid existing payload q
  tid=$(tunnel_id)
  # The name goes into a query string; `&` in it would silently add parameters,
  # and `.result[0]` would then match a record of the wrong type.
  q=$(jq -rn --arg n "$apex" '$n|@uri')
  existing=$(api_ok GET "/zones/$CFPUB_ZONE_ID/dns_records?type=CNAME&name=$q" |
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
# Matched on the scheme only. The old glob list also had `*://*:*tcp*`, which
# used to classify `http://host:1/tcp` as raw TCP and skip the proxy entirely.
is_raw_service() {
  case ${1%%://*} in
    ssh | rdp | tcp | udp | smb) return 0 ;;
    tcp+*) return 0 ;;
    *) return 1 ;;
  esac
}

# A target is either a bare port or an explicit scheme. Anything else is either
# a typo or a scheme the proxy cannot speak (`file://`, `gopher://`), and a URL
# with userinfo would persist a password into the 0600 route table and into `ls`
# output, so it is refused rather than silently ignored by the proxy.
validate_target() {
  local t=$1 scheme rest
  case $t in
    *://*) ;;
    *) return 0 ;;
  esac
  scheme=${t%%://*}
  rest=${t#*://}
  case $scheme in
    http | https | ssh | rdp | tcp | udp | smb | tcp+*) ;;
    *)
      die "unsupported scheme '$scheme' in '$t' (http, https, ssh, rdp, tcp, udp, smb)"
      return 1
      ;;
  esac
  if [ -z "$rest" ]; then
    die "target '$t' has no host"
    return 1
  fi
  case $rest in
    *@*)
      die "target '$t' embeds credentials; publish the port instead"
      return 1
      ;;
  esac
  return 0
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
  validate_target "$resolved"

  local apex prefix
  apex=$(zone_domain)
  prefix="/$(machine_segment)/$service"

  # Refuse a broken route table *before* touching the zone. The state write comes
  # last, so discovering the file is unparseable after DNS and ingress are
  # committed leaves the edge pointing at a route the proxy does not serve.
  if ! is_raw_service "$resolved"; then
    state_load >/dev/null
  fi

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
  #
  # The hostname is a column because a tunnel can be shared. A row whose host is
  # not this machine's apex belongs to somebody else's subdomain, and a row
  # under the same apex but outside our /<machine>/ prefix belongs to another
  # machine on the same tunnel: neither has a local target here, and neither is
  # a problem. Only a route *inside* our own prefix that the proxy cannot serve
  # is flagged, because that is the one case we can still fix.
  jq -r --arg apex "$apex" --arg mine "/$(machine_segment)/" --arg root "/$(machine_segment)" --arg proxy "$(proxy_service)" --argjson routes \
    "$([ -s "$STATE" ] && jq -c '.http // {}' "$STATE" || echo '{}')" '
    [ .[] | select(has("path")) ][]
    | (.hostname // "*") as $h
    | .path as $p
    | (($h == $apex) and (($p == $root) or ($p | startswith($mine)))) as $local
    # A target may carry userinfo; `ls` goes to terminals and logs, so mask it.
    | (if $local then ($routes[$p] // .service) else .service end)
    | sub("(?<s>[a-zA-Z0-9+.-]+://)[^/@]*@"; "\(.s)***@") as $shown
    | (if $local and ($shown == $proxy) then "UNROUTED" else "" end) as $warn
    | "\($h)\t\($p)\t\($shown)\t\($warn)"
  ' <<<"$ingress" | column -t -s $'\t' 2>/dev/null ||
    jq -r --arg apex "$apex" --arg mine "/$(machine_segment)/" --arg root "/$(machine_segment)" --arg proxy "$(proxy_service)" --argjson routes \
      "$([ -s "$STATE" ] && jq -c '.http // {}' "$STATE" || echo '{}')" '
      [ .[] | select(has("path")) ][]
      | (.hostname // "*") as $h | .path as $p
      | (if (($h == $apex) and (($p == $root) or ($p | startswith($mine)))) then ($routes[$p] // .service) else .service end)
      | sub("(?<s>[a-zA-Z0-9+.-]+://)[^/@]*@"; "\(.s)***@") as $shown
      | "\($h)\t\($p)\t\($shown)"
    ' <<<"$ingress"
}

# The tunnel token can join the tunnel as this account, so it is not something to
# drop into a pipe that ends up in a scrollback buffer or a CI log by accident.
cmd_token() {
  [ -t 1 ] || warn "writing the tunnel token to a non-tty stdout; it stays valid until rotated"
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
    [ -s "$STATE" ] || printf '{"http":{}}' | state_write
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

# ingress is read-modify-write over the whole list: two operators (or a wrapper
# script running `pub` twice) can interleave and resurrect a deletion or lose a
# rule. Serialise the mutating commands on a lock file next to the route table.
# `flock` may be missing on minimal systems, so its absence degrades to today's
# behaviour rather than breaking the command.
with_lock() {
  local lock=${STATE%.json}.lock
  if command -v flock >/dev/null 2>&1; then
    mkdir -p "$(dirname -- "$lock")"
    exec 9>"$lock" || die "cannot open $lock"
    flock -w 30 9 || die "another cfpub is holding $lock; try again"
  fi
  "$@"
}

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
    pub) with_lock cmd_pub "$@" ;;
    rm) with_lock cmd_rm "$@" ;;
    ls) cmd_ls "$@" ;;
    token) cmd_token "$@" ;;
  esac
}

main "$@"

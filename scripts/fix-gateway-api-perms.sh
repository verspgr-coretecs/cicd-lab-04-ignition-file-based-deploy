#!/usr/bin/env bash
# fix-gateway-api-perms.sh — restore the APIToken permissions that Ignition's
# first-boot auto-commissioning wipes from core security-properties.
#
# Why this exists: the image bakes services/config with an api-token (`cicd`)
# plus security-properties granting APIToken Access/Read/Write. But when a
# FRESH container boots (every image deploy recreates dev/prod), the gateway's
# auto-commissioning (driven by GATEWAY_ADMIN_USERNAME/PASSWORD) creates a new
# temp_N user source and RESETS readPermissions/writePermissions to
# Roles/Administrator only — which an API token can never hold. Result: the
# baked key authenticates (401 for a bad key) but every call is Forbidden
# (403). This script grafts the APIToken permission entries back into the
# container's live security-properties (keeping whatever systemAuthProfile
# commissioning chose), restarts the gateway, and the key works.
#
# In this lab all three gateways keep persistent volumes, so each one only
# needs this ONCE, right after its very first boot (scripts/setup.sh detects
# the 403 and runs this automatically).
#
# Usage:
#   scripts/fix-gateway-api-perms.sh dev
#   scripts/fix-gateway-api-perms.sh prod
#   scripts/fix-gateway-api-perms.sh local dev prod

set -euo pipefail

. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

command -v python3 >/dev/null || { echo -e "${RED}python3 is required${NC}" >&2; exit 1; }
[ $# -ge 1 ] || { echo "Usage: $0 <local|dev|prod> [more gateways...]" >&2; exit 2; }

SECPROPS_PATH=/usr/local/bin/ignition/data/config/resources/core/ignition/security-properties/config.json

graft() {
  # Adds the APIToken entries to access/read/write/createProject permissions
  # of the JSON file at $1, leaving systemAuthProfile and all other fields as
  # the gateway wrote them.
  python3 - "$1" <<'PYEOF'
import json, sys
path = sys.argv[1]
d = json.load(open(path))

def lvl(*children):
    return [{
        "children": list(children),
        "description": "Represents a user who has been authenticated by the system.",
        "name": "Authenticated",
    }]

roles_admin = {
    "children": [{
        "children": [],
        "description": "System generated security level representing read and write privileges to Gateway configuration",
        "name": "Administrator",
    }],
    "description": "Represents the roles that a user has.",
    "name": "Roles",
}

def api(*names):
    return {"children": [{"children": [], "name": n} for n in names], "name": "APIToken"}

d["accessPermissions"] = {"securityLevels": lvl(api("Access")), "type": "AnyOf"}
d["createProjectPermissions"] = {"securityLevels": lvl(roles_admin, api("Write")), "type": "AnyOf"}
d["readPermissions"] = {"securityLevels": lvl(roles_admin, api("Read")), "type": "AnyOf"}
d["writePermissions"] = {"securityLevels": lvl(roles_admin, api("Write")), "type": "AnyOf"}

json.dump(d, open(path, "w"), indent=2, sort_keys=True)
open(path, "a").write("\n")
PYEOF
}

wait_running() {
  local url="$1"
  for _ in $(seq 1 60); do
    if curl -fsS -m 3 "$url/StatusPing" 2>/dev/null | grep -q RUNNING; then
      return 0
    fi
    sleep 5
  done
  return 1
}

for gw in "$@"; do
  container="$(gateway_container "$gw")" || { echo "ERROR: unknown gateway: $gw" >&2; exit 2; }
  url="$(gateway_url "$gw")"
  echo -e "${GREEN}[$gw]${NC} grafting APIToken permissions into $container..."

  tmp="$(mktemp)"
  docker cp "$container:$SECPROPS_PATH" "$tmp"
  graft "$tmp"
  docker cp "$tmp" "$container:$SECPROPS_PATH"
  rm -f "$tmp"

  echo -e "${GREEN}[$gw]${NC} restarting $container (the gateway only reads this at boot)..."
  docker restart "$container" >/dev/null
  if wait_running "$url"; then
    echo -e "${GREEN}[$gw]${NC} gateway RUNNING — verify with: scripts/scan.sh config --gateway $gw"
  else
    echo -e "${YELLOW}[$gw]${NC} gateway not RUNNING yet; check: docker logs -f $container"
  fi
done

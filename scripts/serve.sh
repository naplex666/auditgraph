#!/usr/bin/env bash
# Serve data/audit.rl over Bolt + HTTP Query API v2 + MCP (loopback only).
# The server prints a generated auth token on startup and writes it to
# data/audit.rl.auth-token; the viewer and MCP clients need that token.
# Requires: relate CLI v1.1.0; run scripts/build_store.sh first.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"

if [ ! -f data/audit.rl ]; then
  echo "data/audit.rl missing - run scripts/build_store.sh first" >&2
  exit 1
fi

exec relate serve --database data/audit.rl --bolt 7687 --http 7474 --mcp 7475

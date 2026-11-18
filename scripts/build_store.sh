#!/usr/bin/env bash
# Regenerate data/audit.rl from data/samples (schema -> slither -> ingest).
# Idempotent: deletes the old store first.
# Requires: relate CLI v1.1.0, Slither 0.11.6 + solc, relate-db 1.1.0.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"

rm -f data/audit.rl data/audit.rl.auth-token

echo "== applying schema =="
relate query --database data/audit.rl --mode envelope < auditgraph/schema.cypher

echo "== ingesting samples =="
python3 -m auditgraph.ingest --project data/samples --db data/audit.rl

echo "== verifying counts =="
relate query --database data/audit.rl --mode envelope \
  "MATCH (n) RETURN labels(n) AS labels, count(*) AS c"
relate query --database data/audit.rl --mode envelope \
  "MATCH ()-[r]->() RETURN type(r) AS rel, count(*) AS c"
echo "store ready: data/audit.rl"

"""CLI wrapper for the AuditGraph showcase queries.

Reads the persistent Relate store and prints envelope JSON:
{"query": <name>, "columns": [...], "rows": [...]}.

No hand-rolled Cypher from user input: every query is a fixed,
parameterized statement; only the parameter VALUES come from argv.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Showcase queries (mirrored in auditgraph/queries.cypher).
# Deliberate deviations from the brief's raw forms, and why:
#  - Q1/Q2/Q3 return DISTINCT named properties (not whole nodes/paths):
#    the raw forms return one row per matching PATH, so Q1 returned 100+
#    rows (mostly duplicates, hitting the agent row cap) and Q3 showed
#    the same (caller, priv) pair twice with no way to tell why.
#  - Q1/Q2/Q3 also return the contract: function names are only unique
#    per contract, so a name-only match spans Vault and VaultSafe.
#    The contract column makes that visible instead of confusing.
#  - Q4 returns severity + CWE id + count (the brief's form grouped by
#    severity only and never showed the CWE).
QUERIES = {
    "blast-radius": (
        "MATCH (f:Function {name: $fn})-[:CALLS|READS|WRITES*1..4]-(x) "
        "RETURN DISTINCT x.contract AS contract, x.name AS name, "
        "labels(x) AS labels"
    ),
    "paths-to-sink": (
        "MATCH p=(entry:Function)-[:CALLS*1..5]->(f:Function)"
        "-[:HAS_SINK]->(s:Sink {kind: $kind}) "
        "RETURN DISTINCT entry.contract AS contract, entry.name AS entry, "
        "f.name AS fn, s.kind AS kind"
    ),
    "reach-privileged": (
        "MATCH p=(f:Function)-[:CALLS*1..6]->"
        "(priv:Function {name: $priv}) "
        "RETURN DISTINCT f.contract AS contract, f.name AS caller, "
        "priv.name AS priv"
    ),
    "findings-by-severity": (
        "MATCH (fd:Finding)-[:HAS_CWE]->(c:CWE) "
        "RETURN fd.severity AS severity, c.id AS cwe, "
        "count(*) AS findings"
    ),
}

DEFAULTS = {
    "blast-radius": {"fn": "withdraw"},
    "paths-to-sink": {"kind": "call.value"},
    "reach-privileged": {"priv": "withdraw"},
    "findings-by-severity": {},
}


def _to_jsonable(value):
    """Convert a relate-db driver value into plain JSON data."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    data = getattr(value, "data", None)
    if callable(data):
        try:
            return _to_jsonable(data())
        except Exception:
            pass
    properties = getattr(value, "properties", None)
    if isinstance(properties, dict):
        out = dict(properties)
        labels = getattr(value, "labels", None)
        if labels:
            out["_labels"] = list(labels)
        return _to_jsonable(out)
    return str(value)


def _row_to_jsonable(row) -> dict:
    if isinstance(row, dict):
        return {k: _to_jsonable(v) for k, v in row.items()}
    data = getattr(row, "data", None)
    if callable(data):
        return _to_jsonable(data())
    return {"value": _to_jsonable(row)}


def run_query(db_path: Path, name: str, params: dict) -> dict:
    """Run one showcase query and return {"query", "columns", "rows"}."""
    import relate

    if name not in QUERIES:
        raise ValueError(f"unknown query: {name}")
    db = relate.connect(str(db_path))
    try:
        cursor = db.execute(QUERIES[name], params)
        columns = list(cursor.description) if cursor.description else []
        # cursor.description holds (name, type_code, ...) tuples.
        columns = [c[0] for c in columns] if columns and isinstance(
            columns[0], (list, tuple)) else columns
        rows = [_row_to_jsonable(row) for row in cursor]
    finally:
        db.close()
    rows.sort(key=lambda r: json.dumps(r, sort_keys=True, default=str))
    return {"query": name, "columns": columns, "rows": rows}


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditgraph.query",
        description="Run AuditGraph showcase queries against a Relate store.",
    )
    parser.add_argument("--db", required=True, help="Relate store path")
    sub = parser.add_subparsers(dest="query", required=True)

    p = sub.add_parser("blast-radius",
                       help="nodes within 4 hops of a function")
    p.add_argument("--fn", default="withdraw")
    p = sub.add_parser("paths-to-sink",
                       help="entry paths to a sink kind")
    p.add_argument("--kind", default="call.value")
    p = sub.add_parser("reach-privileged",
                       help="functions that can reach a privileged function")
    p.add_argument("--priv", default="withdraw")
    sub.add_parser("findings-by-severity",
                   help="findings grouped by severity and CWE")
    sub.add_parser("all", help="run all 4 showcase queries with defaults")

    args = parser.parse_args(argv)
    try:
        if args.query == "all":
            out = {
                name: run_query(Path(args.db), name, DEFAULTS[name])
                for name in QUERIES
            }
            print(json.dumps(out, indent=2, default=str))
            return 0
        params = {
            k: v for k, v in vars(args).items()
            if k in ("fn", "kind", "priv")
        }
        print(json.dumps(
            run_query(Path(args.db), args.query, params),
            indent=2, default=str,
        ))
    except Exception as exc:  # noqa: BLE001 - CLI reports and exits non-zero
        print(f"query failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

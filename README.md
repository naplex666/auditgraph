# AuditGraph

Point AuditGraph at a Solidity repo and it builds a portable, queryable attack-path graph in a single `.rl` file — then any coding agent can ask "what can reach this sink?" in Cypher over MCP.

## Use case

Auditors don't need another list of findings. They need to know **how a finding is reached**: which entry-point functions can call into a vulnerable function, what state that function touches, and what dangerous sink sits at the end of the path. Today that reasoning lives in the auditor's head, or in a pile of Slither output.

AuditGraph connects Slither's facts into a graph and answers path questions directly:

- **Blast radius** — everything within 4 hops of a function (callers, callees, state read/written).
- **Paths to a sink** — every entry path to `call.value`, `delegatecall`, `selfdestruct`, `tx.origin`, or an unprotected initializer.
- **Who can reach a privileged function** — all callers, transitively.
- **Findings by severity and CWE** — what Slither found, grouped.

The demo ships two contracts with the same shape: `Vault` (deliberately vulnerable) and `VaultSafe` (the guarded negative control — checks-effects-interactions, no delegatecall, no selfdestruct, no `tx.origin`, no initializer). Slither finds a High reentrancy finding in `Vault` and none in `VaultSafe`; the graph shows why.

## How it uses Relate

- Mode: **single file** (`data/audit.rl`)
- Why this mode: the whole audit graph is one file you can email, check into git, or hand to a judge, who can open it with `relate query`, serve it with `relate serve`, or load it in a browser via the WASM build. No server to install, no signup, no shared database — the audit travels with the repo it describes. In-memory mode would vanish when the process exits, so judges could not inspect it.
- What the graph models:
  - `(:Contract {name})` — a Solidity contract.
  - `(:Function {name, contract, visibility, payable})` — scoped by contract, so `Vault.withdraw` and `VaultSafe.withdraw` are different nodes.
  - `(:StateVar {name, contract, type})` — state variables.
  - `(:Sink {kind})` — dangerous endpoints: `call.value`, `delegatecall`, `selfdestruct`, `tx.origin`, `unprotected-init`.
  - `(:Finding {id, severity, title, detector})` — one node per Slither detector hit, with a deterministic id (`slither:<check>:<contract>:<function>:<element>`, because Slither's own ids are random UUIDs).
  - `(:CWE {id})` — only for the curated mappings (reentrancy → CWE-841, controlled-delegatecall → CWE-829). Unknown checks get no CWE edge — never invented.
  - Relationships: `(Contract)-[:DEFINES]->(Function)`, `(Function)-[:CALLS]->(Function)`, `(Function)-[:READS|:WRITES]->(StateVar)`, `(Function)-[:HAS_SINK]->(Sink)`, `(Finding)-[:AFFECTS]->(Function)`, `(Finding)-[:HAS_CWE]->(CWE)`.
  - Uniqueness constraints on the natural keys (see `auditgraph/schema.cypher`) make re-ingest idempotent.

How facts become sinks (all provable from Slither output — if a sink can't be proven, it isn't created):

- `call.value`: a low-level `call` with value **and** a reentrancy-eth / arbitrary-send-eth finding on that function.
- `delegatecall`: a low-level `delegatecall` **and** a controlled-delegatecall finding.
- `selfdestruct`: a `selfdestruct` call **and** a suicidal finding.
- `tx.origin`: a tx-origin finding on the function.
- `unprotected-init`: Rule U1 — a code fact, **not** a Slither detector (Slither ships none for this): a public/external function named `initialize`/`init`, with no modifiers, that writes `owner`/`admin`.

What AuditGraph is **not**: it is not an auditor and not a re-run of Slither. Slither finds facts; AuditGraph connects them and answers path questions.

## Setup and run

Prerequisites: Python 3.10+, Relate CLI v1.1.0, `relate-db` 1.1.0, Slither 0.11.6 + solc. No other runtime dependencies (stdlib + `relate-db` only).

```bash
# 1. Build the store from the samples (schema -> slither -> ingest)
./scripts/build_store.sh

# 2. Run all 4 showcase queries
python3 -m auditgraph.query --db data/audit.rl all

# 3. Run the tests (real Slither run + real Relate engine)
python3 -m unittest discover -s tests -v

# 4. Serve the store (Bolt 7687, HTTP 7474, MCP 7475, loopback only)
./scripts/serve.sh
```

Ingest your own project instead of the samples:

```bash
python3 -m auditgraph.ingest --project path/to/your/contracts --db /tmp/my.rl
```

Notes:

- Slither exits 255 whenever findings exist (even Low ones) and still writes valid JSON with `"success": true`. Ingest ignores the exit code and trusts only the JSON `success` field.
- If Slither is missing or fails on an input file, ingest stops with an error. There is deliberately no regex fallback parser.
- `relate query` reads the same store read-only; the HTTP API and MCP need the token printed at serve time (also saved to `data/audit.rl.auth-token`, git-ignored).

### Verified outputs (18 Nov 2026, Relate v1.1.0, Slither 0.11.6)

Store contents after `scripts/build_store.sh` — 39 nodes, 47 relationships:

| Nodes | | Relationships | |
|---|---|---|---|
| Contract | 2 | DEFINES | 10 |
| Function | 10 | CALLS | 3 |
| StateVar | 5 | READS | 9 |
| Sink | 5 | WRITES | 6 |
| Finding | 15 | HAS_SINK | 5 |
| CWE | 2 | AFFECTS | 12 |
| | | HAS_CWE | 2 |

```bash
python3 -m auditgraph.query --db data/audit.rl all
```

- **Q1 blast-radius (`--fn withdraw`) — 13 rows:** Vault deposit, drain, emergencyWithdraw, initialize, kill, withdraw, balances, initialized, owner; VaultSafe deposit, drain, withdraw, balances.
- **Q2 paths-to-sink (`--kind call.value`) — 2 rows:** `drain -> withdraw -> call.value`, `emergencyWithdraw -> withdraw -> call.value`.
- **Q3 reach-privileged (`--priv withdraw`) — 3 rows:** Vault drain, Vault emergencyWithdraw, VaultSafe drain.
- **Q4 findings-by-severity — 2 rows:** `(High, CWE-829, 1)`, `(High, CWE-841, 1)`.

Tests: **14 tests, all passing** (`python3 -m unittest discover -s tests -v`, 47 s).

Server: `scripts/serve.sh` — HTTP Query API v2 returns **200** with Basic auth (`relate:<token>`), **401** without; MCP endpoint returns 200 with auth, 401 without.

### Viewer (no build step, no npm)

1. `scripts/serve.sh` — start the server.
2. Copy the token from `data/audit.rl.auth-token` (the hex part after `relate:`) into the token field.
3. Serve the viewer folder and open it: `cd viewer && python3 -m http.server 8000`, then open http://localhost:8000 — pick a query (Q2 is the default demo) and click it. The page posts to the local HTTP Query API v2 and renders the result as a table plus a simple SVG path diagram. The token is pasted by you, kept only in the page, sent only to localhost, and never written into any file.

## Where the data lives

- `data/audit.rl` — the prebuilt persistent store (single file, 69,632 bytes), generated by `scripts/build_store.sh` from the samples. Open it directly: `relate query --database data/audit.rl --mode envelope "MATCH (n) RETURN count(n)"`.
- `data/samples/Vault.sol` — deliberately vulnerable sample (reentrancy, unprotected init, delegatecall, selfdestruct, tx.origin).
- `data/samples/VaultSafe.sol` — guarded negative control (same shape, no findings above Low).
- `auditgraph/schema.cypher` — the schema + uniqueness constraints, applied by `build_store.sh`.
- `auditgraph/queries.cypher` — the 4 showcase queries.
- `auditgraph/ingest.py` — Slither JSON + Slither Python API → Cypher → Relate.
- `auditgraph/query.py` — CLI wrapper for the showcase queries (parameterized only — no Cypher is ever built from user input).
- `tests/` — `test_ingest.py` (counts, reentrancy path, guarded control, idempotent re-ingest) and `test_queries.py` (exact rows for all 4 queries).

## Honest limits

- **One writer per store.** Relate is a single-process embedded engine: only one process may write a `.rl` file at a time. Concurrent writers are not supported — serve multi-client access over Bolt/HTTP/MCP instead.
- **The graph must fit in RAM.** The whole graph lives in memory while the process runs; very large repos need a server database (Neo4j/Aura), which Relate can pull from and push to over the same Cypher.
- **No auth on the store file itself.** Anyone with the `.rl` file can read it. The served endpoints use a generated token (Basic auth), and Bolt is bound to loopback only — never expose it beyond localhost without an authenticating proxy.
- **Findings are only as good as Slither.** AuditGraph connects Slither's output; it does not find bugs Slither misses, and the `unprotected-init` sink is a documented heuristic (Rule U1), not a Slither detector.
- **Relate is young (launched 11 Nov 2026).** Every Cypher statement in this repo was executed against the live Relate v1.1.0 engine and passes; Neo4j-server-only features (`SHOW DATABASES`, APOC, `db.schema.visualization()`) do not exist in Relate and are not used anywhere here.

// AuditGraph showcase queries (Cypher 25).
// Every statement below was executed against the live Relate engine
// (v1.1.0) and passes. Run them with, e.g.:
//   relate query --database data/audit.rl --mode envelope \
//     --param fn=withdraw < auditgraph/queries.cypher
// Or via the wrapper: python -m auditgraph.query --db data/audit.rl all
//
// NOTE on the brief's raw forms: Q1/Q2/Q3 in CODEX_BRIEF.md return whole
// nodes/paths and match functions by name only. Run verbatim, Q1 returns
// one row per matching path (100+ rows, mostly duplicates, hitting the
// agent row cap) and Q3 shows the same (caller, priv) pair twice with no
// way to tell why (two contracts share the function names). The shipped
// forms below return DISTINCT named properties plus the contract column
// instead — same traversals, readable output. The traversal itself is
// unchanged.

// Q1. Blast radius: everything within 4 hops of a function
// (callers, callees, state read/written, and their neighbours).
MATCH (f:Function {name: $fn})-[:CALLS|READS|WRITES*1..4]-(x) RETURN DISTINCT x.contract AS contract, x.name AS name, labels(x) AS labels;

// Q2. All entry paths to a sink of a given kind.
MATCH p=(entry:Function)-[:CALLS*1..5]->(f:Function)-[:HAS_SINK]->(s:Sink {kind: $kind}) RETURN DISTINCT entry.contract AS contract, entry.name AS entry, f.name AS fn, s.kind AS kind;

// Q3. Who can reach a privileged function?
MATCH p=(f:Function)-[:CALLS*1..6]->(priv:Function {name: $priv}) RETURN DISTINCT f.contract AS contract, f.name AS caller, priv.name AS priv;

// Q4. Findings by severity and CWE.
// (Brief's form grouped by severity only; this form also shows the CWE,
// which is the point of the query.)
MATCH (fd:Finding)-[:HAS_CWE]->(c:CWE) RETURN fd.severity AS severity, c.id AS cwe, count(*) AS findings;

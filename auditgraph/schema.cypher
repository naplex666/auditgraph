// AuditGraph graph schema (Cypher 25).
// Every statement in this file was executed against the live Relate
// engine (v1.1.0) and passes. Applied by scripts/build_store.sh before
// ingest, so the store carries real uniqueness constraints.
// Deliberately NOT used here (Neo4j-server-only, absent from Relate):
//   SHOW DATABASES, APOC procedures, CALL db.schema.visualization(),
//   CALL db.schema.nodeTypeProperties().
//
// Node labels and natural keys (MERGE keys used by ingest):
//   (:Contract {name})                  - one node per contract; name is unique.
//   (:Function {name, contract})        - scoped by contract: Vault.withdraw
//                                         and VaultSafe.withdraw are different nodes.
//   (:StateVar {name, contract})        - scoped by contract, same reason.
//   (:Sink {kind})                      - kinds: call.value, delegatecall,
//                                         selfdestruct, tx.origin,
//                                         unprotected-init.
//   (:Finding {id})                     - deterministic id
//                                         slither:<check>:<contract>:<function>:<element>
//   (:CWE {id})                         - e.g. CWE-841, CWE-829.
//
// Relationship types:
//   (Contract)-[:DEFINES]->(Function)
//   (Function)-[:CALLS]->(Function)
//   (Function)-[:READS]->(StateVar)   (Function)-[:WRITES]->(StateVar)
//   (Function)-[:HAS_SINK]->(Sink)
//   (Finding)-[:AFFECTS]->(Function)  (only when the finding names a function;
//                                      pragma/variable findings have no edge)
//   (Finding)-[:HAS_CWE]->(CWE)       (curated mappings only; unknown checks
//                                      get no CWE edge, never invented)

CREATE CONSTRAINT c_contract_name IF NOT EXISTS FOR (c:Contract) REQUIRE c.name IS UNIQUE;
CREATE CONSTRAINT c_fn_key IF NOT EXISTS FOR (f:Function) REQUIRE (f.contract, f.name) IS UNIQUE;
CREATE CONSTRAINT c_statevar_key IF NOT EXISTS FOR (v:StateVar) REQUIRE (v.contract, v.name) IS UNIQUE;
CREATE CONSTRAINT c_sink_kind IF NOT EXISTS FOR (s:Sink) REQUIRE s.kind IS UNIQUE;
CREATE CONSTRAINT c_finding_id IF NOT EXISTS FOR (fd:Finding) REQUIRE fd.id IS UNIQUE;
CREATE CONSTRAINT c_cwe_id IF NOT EXISTS FOR (w:CWE) REQUIRE w.id IS UNIQUE;
CREATE INDEX idx_finding_detector IF NOT EXISTS FOR (fd:Finding) ON (fd.detector);
CREATE INDEX idx_finding_severity IF NOT EXISTS FOR (fd:Finding) ON (fd.severity);

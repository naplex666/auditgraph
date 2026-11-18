"""Tests for auditgraph.ingest: Slither JSON + API -> Relate store.

Builds a fresh store from data/samples in a temp dir (real Slither run,
real Relate engine) and asserts exact node/relationship counts plus the
hand-checked security facts: the reentrancy path exists in Vault and
does NOT exist in VaultSafe (the negative control).
"""

import tempfile
import unittest
from pathlib import Path

import relate

from auditgraph import ingest

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "samples"


def _scalar(db_path, cypher, params=None):
    db = relate.connect(str(db_path))
    try:
        rows = list(db.execute(cypher, params or {}))
        return rows[0]["c"] if rows else 0
    finally:
        db.close()


def _rows(db_path, cypher, params=None):
    db = relate.connect(str(db_path))
    try:
        return [dict(r) for r in db.execute(cypher, params or {})]
    finally:
        db.close()


class IngestTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="auditgraph-test-")
        cls.db = Path(cls._tmp.name) / "audit.rl"
        cls.statements = ingest.ingest(SAMPLES, cls.db)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_node_counts(self):
        expected = {
            "Contract": 2,
            "Function": 10,  # Vault 7 + VaultSafe 3 (constructor skipped)
            "StateVar": 5,   # Vault 3 + VaultSafe 2
            "Sink": 5,
            "Finding": 15,   # Vault 11 + VaultSafe 4
            "CWE": 2,
        }
        for label, count in expected.items():
            got = _scalar(
                self.db,
                f"MATCH (n:{label}) RETURN count(n) AS c",
            )
            self.assertEqual(got, count, f"{label} count")

    def test_rel_counts(self):
        expected = {
            "DEFINES": 10,
            "CALLS": 3,
            "READS": 9,
            "WRITES": 6,
            "HAS_SINK": 5,
            "AFFECTS": 12,
            "HAS_CWE": 2,
        }
        for rel, count in expected.items():
            got = _scalar(
                self.db,
                f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c",
            )
            self.assertEqual(got, count, f"{rel} count")

    def test_reentrancy_path_exists_in_vault(self):
        rows = _rows(
            self.db,
            "MATCH p=(entry:Function {contract: 'Vault'})-[:CALLS*1..5]->"
            "(f:Function)-[:HAS_SINK]->(s:Sink {kind: 'call.value'}) "
            "RETURN entry.name AS entry, f.name AS fn",
        )
        got = {(r["entry"], r["fn"]) for r in rows}
        self.assertEqual(
            got,
            {("drain", "withdraw"), ("emergencyWithdraw", "withdraw")},
        )

    def test_guarded_contract_has_no_sink(self):
        rows = _rows(
            self.db,
            "MATCH (f:Function {contract: 'VaultSafe'})"
            "-[:HAS_SINK]->(s:Sink) RETURN f.name AS fn, s.kind AS kind",
        )
        self.assertEqual(rows, [])

    def test_guarded_contract_has_no_high_finding(self):
        got = _scalar(
            self.db,
            "MATCH (fd:Finding)-[:AFFECTS]->"
            "(f:Function {contract: 'VaultSafe'}) "
            "WHERE fd.severity IN ['High', 'Medium'] "
            "RETURN count(fd) AS c",
        )
        self.assertEqual(got, 0)

    def test_reentrancy_finding_links_cwe(self):
        rows = _rows(
            self.db,
            "MATCH (fd:Finding {detector: 'reentrancy-eth'})"
            "-[:AFFECTS]->(f:Function), "
            "(fd)-[:HAS_CWE]->(w:CWE) "
            "RETURN fd.severity AS severity, f.contract AS contract, "
            "f.name AS fn, w.id AS cwe",
        )
        self.assertEqual(rows, [{
            "severity": "High",
            "contract": "Vault",
            "fn": "withdraw",
            "cwe": "CWE-841",
        }])

    def test_all_vault_sinks_present(self):
        rows = _rows(
            self.db,
            "MATCH (f:Function {contract: 'Vault'})"
            "-[:HAS_SINK]->(s:Sink) "
            "RETURN f.name AS fn, s.kind AS kind",
        )
        got = {(r["fn"], r["kind"]) for r in rows}
        self.assertEqual(got, {
            ("withdraw", "call.value"),
            ("delegate", "delegatecall"),
            ("kill", "selfdestruct"),
            ("emergencyWithdraw", "tx.origin"),
            ("initialize", "unprotected-init"),
        })

    def test_reingest_is_idempotent(self):
        before_nodes = _scalar(self.db, "MATCH (n) RETURN count(n) AS c")
        before_rels = _scalar(
            self.db, "MATCH ()-[r]->() RETURN count(r) AS c")
        ingest.ingest(SAMPLES, self.db)
        self.assertEqual(
            _scalar(self.db, "MATCH (n) RETURN count(n) AS c"),
            before_nodes)
        self.assertEqual(
            _scalar(self.db, "MATCH ()-[r]->() RETURN count(r) AS c"),
            before_rels)


if __name__ == "__main__":
    unittest.main()

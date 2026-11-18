"""Tests for auditgraph.query: the 4 showcase queries, exact rows.

Builds a fresh store from data/samples in a temp dir and runs every
showcase query through auditgraph.query.run_query (real Relate engine).
"""

import tempfile
import unittest
from pathlib import Path

from auditgraph import ingest, query

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "data" / "samples"


class QueryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory(prefix="auditgraph-test-")
        cls.db = Path(cls._tmp.name) / "audit.rl"
        ingest.ingest(SAMPLES, cls.db)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_blast_radius_withdraw(self):
        out = query.run_query(self.db, "blast-radius", {"fn": "withdraw"})
        got = {(r["contract"], r["name"]) for r in out["rows"]}
        self.assertEqual(got, {
            ("Vault", "deposit"), ("Vault", "drain"),
            ("Vault", "emergencyWithdraw"), ("Vault", "initialize"),
            ("Vault", "kill"), ("Vault", "withdraw"),
            ("Vault", "balances"), ("Vault", "initialized"),
            ("Vault", "owner"),
            ("VaultSafe", "deposit"), ("VaultSafe", "drain"),
            ("VaultSafe", "withdraw"), ("VaultSafe", "balances"),
        })
        self.assertEqual(len(out["rows"]), 13)

    def test_blast_radius_unknown_function(self):
        out = query.run_query(self.db, "blast-radius", {"fn": "nope"})
        self.assertEqual(out["rows"], [])

    def test_paths_to_sink_call_value(self):
        out = query.run_query(
            self.db, "paths-to-sink", {"kind": "call.value"})
        got = {(r["entry"], r["fn"], r["kind"]) for r in out["rows"]}
        self.assertEqual(got, {
            ("drain", "withdraw", "call.value"),
            ("emergencyWithdraw", "withdraw", "call.value"),
        })

    def test_paths_to_sink_delegatecall_has_no_entry(self):
        # Nobody calls delegate(), so no entry path exists to that sink.
        out = query.run_query(
            self.db, "paths-to-sink", {"kind": "delegatecall"})
        self.assertEqual(out["rows"], [])

    def test_reach_privileged_withdraw(self):
        out = query.run_query(
            self.db, "reach-privileged", {"priv": "withdraw"})
        got = {(r["contract"], r["caller"], r["priv"])
               for r in out["rows"]}
        self.assertEqual(got, {
            ("Vault", "drain", "withdraw"),
            ("Vault", "emergencyWithdraw", "withdraw"),
            ("VaultSafe", "drain", "withdraw"),
        })

    def test_findings_by_severity(self):
        out = query.run_query(self.db, "findings-by-severity", {})
        got = {(r["severity"], r["cwe"], r["findings"])
               for r in out["rows"]}
        self.assertEqual(got, {
            ("High", "CWE-829", 1),
            ("High", "CWE-841", 1),
        })


if __name__ == "__main__":
    unittest.main()

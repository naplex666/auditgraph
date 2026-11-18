"""Ingest a Solidity project into a Relate graph store.

Sources of truth — Slither only, no regex, no hand parsing of source:
  1. ``slither <file> --json <tmp>`` (subprocess) — detectors / findings.
     NOTE: Slither exits 255 whenever findings exist, even Low ones, and
     still writes a valid JSON with ``success: true``. The exit code is
     therefore ignored; only the JSON ``success`` field is trusted.
  2. The Slither Python API (same engine, same run) — contracts, functions,
     state variables, internal calls, low-level calls, reads/writes.
     The CLI ``--json`` output contains detectors ONLY, so the structure
     has to come from the API; both halves are Slither output.

Graph model (see auditgraph/schema.cypher):
  Contract -[:DEFINES]-> Function -[:CALLS]-> Function
  Function -[:READS|:WRITES]-> StateVar
  Function -[:HAS_SINK]-> Sink
  Finding -[:AFFECTS]-> Function, Finding -[:HAS_CWE]-> CWE

Sink rules (all provable from Slither output):
  call.value      low-level ``call`` with value AND a reentrancy-eth or
                  arbitrary-send-eth finding on that function.
  delegatecall    low-level ``delegatecall`` AND a controlled-delegatecall
                  finding on that function.
  selfdestruct    a ``selfdestruct``/``suicide`` solidity call AND a
                  suicidal finding on that function.
  tx.origin       a tx-origin finding on that function.
  unprotected-init  Rule U1 (code fact, NOT a Slither detector — Slither
                  ships no detector for unprotected initializers):
                  a public/external function named ``initialize``/``init``
                  with no modifiers that writes a state variable named
                  ``owner`` or ``admin``.

CWE mapping is a small curated table of well-established mappings only.
Unknown checks get NO CWE edge — never invented.

Determinism: every collection is sorted; MERGE on natural keys makes
re-ingest idempotent. Finding ids are synthesized deterministically
(``slither:<check>:<contract>:<function>:<element>``) because Slither's
own ids are random UUIDs.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Curated CWE mappings (well-established only; anything else: no CWE edge).
CWE_MAP = {
    "reentrancy-eth": "CWE-841",
    "reentrancy-no-eth": "CWE-841",
    "controlled-delegatecall": "CWE-829",
}

# Checks that corroborate a value-carrying low-level call sink.
VALUE_CALL_CHECKS = {"reentrancy-eth", "arbitrary-send-eth"}

# Checks that corroborate the other code-fact sinks.
DELEGATECALL_CHECKS = {"controlled-delegatecall"}
SELFDESTRUCT_CHECKS = {"suicidal"}
TX_ORIGIN_CHECKS = {"tx-origin"}

INIT_FUNCTION_NAMES = {"initialize", "init"}
OWNER_VAR_NAMES = {"owner", "admin"}


class IngestError(RuntimeError):
    """Raised when Slither is missing or fails on an input file."""


def _ensure_local_bin_on_path() -> None:
    """Make sure ``~/.local/bin`` is on PATH for child processes.

    Slither (pip --user install) lives there, and Slither itself shells
    out to ``solc`` — which also lives there (solc-select). A fresh
    shell does not have ``~/.local/bin`` on PATH, so without this both
    the CLI call and the Python-API compile step fail to find them.
    Only the current process env is touched, and only once per call.
    """
    local_bin = str(Path.home() / ".local" / "bin")
    path = os.environ.get("PATH", "")
    if local_bin not in path.split(os.pathsep):
        os.environ["PATH"] = local_bin + os.pathsep + path


def _slither_bin() -> str:
    """Resolve the ``slither`` binary.

    Slither is often installed with ``pip --user`` into ``~/.local/bin``,
    which is not on PATH in a fresh shell. Fall back there before giving
    up, so ``python -m unittest`` works without a PATH export.
    """
    found = shutil.which("slither")
    if found:
        return found
    local = Path.home() / ".local" / "bin" / "slither"
    if local.is_file():
        return str(local)
    return "slither"


def _slither_json_for_file(sol_file: Path, tmpdir: Path) -> dict:
    """Run ``slither <file> --json <out>`` and return the parsed JSON.

    Slither's exit code is ignored (255 whenever findings exist);
    only ``success`` in the JSON decides.
    """
    out = tmpdir / (sol_file.stem + ".slither.json")
    _ensure_local_bin_on_path()
    proc = subprocess.run(
        [_slither_bin(), str(sol_file), "--json", str(out)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if not out.exists():
        raise IngestError(
            f"Slither produced no JSON for {sol_file} "
            f"(exit {proc.returncode}). stderr:\n{proc.stderr[-2000:]}"
        )
    data = json.loads(out.read_text())
    if not data.get("success"):
        raise IngestError(
            f"Slither failed on {sol_file}: {data.get('error')!r}"
        )
    return data


def _structure_for_file(sol_file: Path) -> dict:
    """Walk one file with the Slither Python API.

    Returns a dict: contract name -> {
        "file": str, "functions": {name: {...}}, "state_vars": {name: type},
    }
    Function info: visibility, payable, modifiers, internal_calls
    (as (contract, name) pairs), low_level_calls (function_name, has_value),
    has_selfdestruct, reads, writes.
    """
    try:
        from slither import Slither
        from slither.slithir.operations import (
            InternalCall,
            LowLevelCall,
            SolidityCall,
        )
    except ImportError as exc:  # pragma: no cover - environment error
        raise IngestError(
            "Slither Python API is not importable. Install Slither "
            "(pip install slither-analyzer) and retry."
        ) from exc

    sl = Slither(str(sol_file))
    contracts: dict = {}
    for contract in sorted(sl.contracts, key=lambda c: c.name):
        # Only contracts defined in this file (skip imported ones).
        fname = contract.source_mapping.filename.relative
        if Path(fname).name != sol_file.name:
            continue
        funcs: dict = {}
        for fn in sorted(contract.functions, key=lambda f: f.name):
            if getattr(fn, "is_constructor", False):
                continue
            internal = []
            low_level = []
            has_selfdestruct = False
            for ir in fn.internal_calls:
                if isinstance(ir, InternalCall) and ir.function is not None:
                    target = ir.function
                    internal.append((target.contract.name, target.name))
                elif isinstance(ir, SolidityCall):
                    callee = getattr(ir.function, "name", "") or ""
                    # Name carries the signature, e.g. "selfdestruct(address)".
                    if callee.split("(")[0] in ("selfdestruct", "suicide"):
                        has_selfdestruct = True
            for ll in fn.low_level_calls:
                if isinstance(ll, LowLevelCall):
                    low_level.append(
                        (ll.function_name, ll.call_value is not None)
                    )
            funcs[fn.name] = {
                "visibility": str(fn.visibility),
                "payable": bool(fn.payable),
                "modifiers": sorted(m.name for m in fn.modifiers),
                "internal_calls": sorted(set(internal)),
                "low_level_calls": sorted(set(low_level)),
                "has_selfdestruct": has_selfdestruct,
                "reads": sorted(v.name for v in fn.state_variables_read),
                "writes": sorted(v.name for v in fn.state_variables_written),
            }
        contracts[contract.name] = {
            "file": sol_file.name,
            "functions": funcs,
            "state_vars": {
                v.name: str(v.type)
                for v in sorted(
                    contract.state_variables, key=lambda v: v.name
                )
            },
        }
    if not contracts:
        raise IngestError(f"Slither found no contract in {sol_file}")
    return contracts


def _resolve_finding_function(det: dict, structure: dict) -> tuple | None:
    """Resolve a Slither detector to (contract, function), or None.

    Prefers the function element's parent contract; falls back to the
    node element's source file + function name.
    """
    file_to_contracts: dict[str, set] = {}
    fn_to_contracts: dict[str, set] = {}
    for cname, cinfo in structure.items():
        file_to_contracts.setdefault(cinfo["file"], set()).add(cname)
        for fname in cinfo["functions"]:
            fn_to_contracts.setdefault(fname, set()).add(cname)

    for el in det.get("elements", []):
        tsf = el.get("type_specific_fields", {}) or {}
        parent = tsf.get("parent") or {}
        if el.get("type") == "function" and parent.get("type") == "contract":
            return (parent.get("name"), el.get("name"))
        # Variable / node elements carry their enclosing function as parent.
        if parent.get("type") == "function":
            fname = parent.get("name")
            src = el.get("source_mapping") or {}
            fname_rel = src.get("filename_relative", "")
            if fname and fname_rel:
                for cname in sorted(
                    file_to_contracts.get(Path(fname_rel).name, set())
                ):
                    if fname in structure[cname]["functions"]:
                        return (cname, fname)
            if fname and fn_to_contracts.get(fname):
                return (sorted(fn_to_contracts[fname])[0], fname)
        if el.get("type") == "function":
            name = el.get("name")
            if name and fn_to_contracts.get(name):
                return (sorted(fn_to_contracts[name])[0], name)
    return None


def _finding_id(det: dict, resolved: tuple | None, seen: dict) -> str:
    """Deterministic Finding id (Slither's own ids are random UUIDs)."""
    check = det.get("check", "unknown")
    if resolved:
        contract, fn = resolved
        element = ""
        for el in det.get("elements", []):
            if el.get("type") in ("function", "variable", "node"):
                element = el.get("name", "")
                break
        base = f"slither:{check}:{contract}:{fn}:{element}"
    else:
        element = ""
        src_file = ""
        for el in det.get("elements", []):
            element = el.get("name", "")
            src_file = Path(
                (el.get("source_mapping") or {}).get(
                    "filename_relative", "")
            ).name
            break
        base = f"slither:{check}:global:{src_file}:{element}"
    if base not in seen:
        seen[base] = 1
        return base
    seen[base] += 1
    return f"{base}#{seen[base]}"


def _sinks_for_function(
    cname: str, fname: str, finfo: dict, finding_checks: set
) -> set:
    """Apply the documented sink rules to one function."""
    sinks = set()
    low = finfo["low_level_calls"]
    if any(name == "call" and has_value for name, has_value in low):
        if finding_checks & VALUE_CALL_CHECKS:
            sinks.add("call.value")
    if any(name == "delegatecall" for name, _ in low):
        if finding_checks & DELEGATECALL_CHECKS:
            sinks.add("delegatecall")
    if finfo["has_selfdestruct"] and finding_checks & SELFDESTRUCT_CHECKS:
        sinks.add("selfdestruct")
    if finding_checks & TX_ORIGIN_CHECKS:
        sinks.add("tx.origin")
    # Rule U1: unprotected initializer (code fact, no Slither detector).
    if (
        fname in INIT_FUNCTION_NAMES
        and finfo["visibility"] in ("public", "external")
        and not finfo["modifiers"]
        and set(finfo["writes"]) & OWNER_VAR_NAMES
    ):
        sinks.add("unprotected-init")
    return sinks


def build_statements(project: Path) -> list:
    """Run Slither over every .sol file in ``project`` and build Cypher.

    Returns a list of (cypher, params) tuples in deterministic order.
    ``project`` may be a single .sol file or a directory.
    """
    if project.is_file():
        sol_files = [project]
    else:
        sol_files = sorted(project.glob("*.sol"))
    if not sol_files:
        raise IngestError(f"No .sol files found in {project}")

    statements: list = []
    seen_finding_ids: dict = {}

    with tempfile.TemporaryDirectory(prefix="auditgraph-slither-") as td:
        tmpdir = Path(td)
        for sol_file in sol_files:
            detectors = _slither_json_for_file(sol_file, tmpdir)[
                "results"
            ].get("detectors", [])
            structure = _structure_for_file(sol_file)

            # Index findings per (contract, function) for sink rules.
            checks_by_fn: dict[tuple, set] = {}
            finding_rows = []
            for det in sorted(
                detectors, key=lambda d: (d.get("check", ""), d.get("id", ""))
            ):
                resolved = _resolve_finding_function(det, structure)
                fid = _finding_id(det, resolved, seen_finding_ids)
                if resolved:
                    checks_by_fn.setdefault(resolved, set()).add(
                        det.get("check", "")
                    )
                description = (det.get("description") or "").splitlines()
                title = (description[0].strip() if description else
                         det.get("check", ""))[:160]
                finding_rows.append(
                    (fid, det.get("impact", ""), title,
                     det.get("check", ""), resolved)
                )

            # --- nodes ---
            for cname in sorted(structure):
                cinfo = structure[cname]
                statements.append((
                    "MERGE (c:Contract {name: $name}) "
                    "SET c.file = $file",
                    {"name": cname, "file": cinfo["file"]},
                ))
                for vname in sorted(cinfo["state_vars"]):
                    statements.append((
                        "MERGE (v:StateVar {name: $name, contract: $contract}) "
                        "SET v.type = $type",
                        {"name": vname, "contract": cname,
                         "type": cinfo["state_vars"][vname]},
                    ))
                for fname in sorted(cinfo["functions"]):
                    finfo = cinfo["functions"][fname]
                    statements.append((
                        "MERGE (f:Function {name: $name, contract: $contract}) "
                        "SET f.visibility = $visibility, "
                        "f.payable = $payable",
                        {"name": fname, "contract": cname,
                         "visibility": finfo["visibility"],
                         "payable": finfo["payable"]},
                    ))
                    for sink in sorted(_sinks_for_function(
                        cname, fname, finfo,
                        checks_by_fn.get((cname, fname), set()),
                    )):
                        statements.append((
                            "MERGE (s:Sink {kind: $kind})",
                            {"kind": sink},
                        ))

            # --- findings + CWE nodes ---
            for fid, severity, title, check, _resolved in finding_rows:
                statements.append((
                    "MERGE (fd:Finding {id: $id}) "
                    "SET fd.severity = $severity, fd.title = $title, "
                    "fd.detector = $detector",
                    {"id": fid, "severity": severity, "title": title,
                     "detector": check},
                ))
                if check in CWE_MAP:
                    statements.append((
                        "MERGE (w:CWE {id: $id})",
                        {"id": CWE_MAP[check]},
                    ))

            # --- relationships ---
            for cname in sorted(structure):
                cinfo = structure[cname]
                for fname in sorted(cinfo["functions"]):
                    finfo = cinfo["functions"][fname]
                    statements.append((
                        "MATCH (c:Contract {name: $contract}), "
                        "(f:Function {name: $name, contract: $contract}) "
                        "MERGE (c)-[:DEFINES]->(f)",
                        {"contract": cname, "name": fname},
                    ))
                    for target_contract, target_fn in finfo["internal_calls"]:
                        if target_fn not in structure.get(
                            target_contract, {}
                        ).get("functions", {}):
                            continue
                        statements.append((
                            "MATCH (a:Function {name: $a, contract: $ac}), "
                            "(b:Function {name: $b, contract: $bc}) "
                            "MERGE (a)-[:CALLS]->(b)",
                            {"a": fname, "ac": cname,
                             "b": target_fn, "bc": target_contract},
                        ))
                    for vname in finfo["reads"]:
                        if vname not in cinfo["state_vars"]:
                            continue
                        statements.append((
                            "MATCH (f:Function {name: $name, contract: $contract}), "
                            "(v:StateVar {name: $vname, contract: $contract}) "
                            "MERGE (f)-[:READS]->(v)",
                            {"name": fname, "contract": cname,
                             "vname": vname},
                        ))
                    for vname in finfo["writes"]:
                        if vname not in cinfo["state_vars"]:
                            continue
                        statements.append((
                            "MATCH (f:Function {name: $name, contract: $contract}), "
                            "(v:StateVar {name: $vname, contract: $contract}) "
                            "MERGE (f)-[:WRITES]->(v)",
                            {"name": fname, "contract": cname,
                             "vname": vname},
                        ))
                    for sink in sorted(_sinks_for_function(
                        cname, fname, finfo,
                        checks_by_fn.get((cname, fname), set()),
                    )):
                        statements.append((
                            "MATCH (f:Function {name: $name, contract: $contract}), "
                            "(s:Sink {kind: $kind}) "
                            "MERGE (f)-[:HAS_SINK]->(s)",
                            {"name": fname, "contract": cname,
                             "kind": sink},
                        ))
            for fid, _sev, _title, check, resolved in finding_rows:
                if resolved:
                    contract, fname = resolved
                    statements.append((
                        "MATCH (fd:Finding {id: $id}), "
                        "(f:Function {name: $name, contract: $contract}) "
                        "MERGE (fd)-[:AFFECTS]->(f)",
                        {"id": fid, "name": fname, "contract": contract},
                    ))
                if check in CWE_MAP:
                    statements.append((
                        "MATCH (fd:Finding {id: $id}), "
                        "(w:CWE {id: $cwe}) "
                        "MERGE (fd)-[:HAS_CWE]->(w)",
                        {"id": fid, "cwe": CWE_MAP[check]},
                    ))
    return statements


def ingest(project: Path, db_path: Path) -> int:
    """Build (or rebuild) the Relate store at ``db_path`` from ``project``.

    Returns the number of Cypher statements executed.
    """
    import relate

    _ensure_local_bin_on_path()
    statements = build_statements(project)
    db = relate.connect(str(db_path))
    try:
        try:
            for cypher, params in statements:
                db.execute(cypher, params)
            db.commit()
        except Exception:
            db.rollback()
            raise
    finally:
        db.close()
    return len(statements)


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditgraph.ingest",
        description="Ingest a Solidity project into a Relate graph store.",
    )
    parser.add_argument("--project", required=True,
                        help="Solidity file or directory of .sol files")
    parser.add_argument("--db", required=True,
                        help="Relate store path (single .rl file)")
    args = parser.parse_args(argv)
    try:
        count = ingest(Path(args.project), Path(args.db))
    except IngestError as exc:
        print(f"ingest failed: {exc}", file=sys.stderr)
        return 1
    print(f"ingested {count} statements into {args.db}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

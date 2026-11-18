"""AuditGraph: a Solidity repo as a portable, queryable attack-path graph.

Point it at a Solidity project and it builds a Relate graph store
(a single ``.rl`` file) of contracts, functions, state variables,
sinks, Slither findings and CWEs — then answers path questions
(blast radius, paths to a sink, who can reach a privileged function)
in Cypher.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]

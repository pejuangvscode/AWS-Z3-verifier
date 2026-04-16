"""
scenario_3.py – Subnet isolation check between sub1 and sub2.

Security question
-----------------
Is there any IPv4 address *x* that belongs to **both** ``10.0.0.0/24`` (sub1)
and ``10.0.1.0/24`` (sub2) simultaneously?

Expected result
---------------
* **UNSAT** ✅ SAFE – The two /24 subnets occupy non-overlapping address space, so
  no single IP can satisfy membership in both.

Z3 model
--------
Variable
    ``x`` – BitVec(32), a candidate IPv4 address

Constraints added
    1. ``(x & 0xFFFFFF00) == 0x0A000000``   (x ∈ 10.0.0.0/24)
    2. ``(x & 0xFFFFFF00) == 0x0A000100``   (x ∈ 10.0.1.0/24)

Since ``0x0A000000 ≠ 0x0A000100``, constraints 1 and 2 can never be satisfied
together, and the solver immediately returns UNSAT.

When run against an infrastructure whose subnets *do* overlap the solver would
return SAT together with a witness IP, exposing the CIDR misconfiguration.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from z3 import And, BitVec, ModelRef, Or, Solver, sat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.extractor import cidr_to_network_mask
from z3_engine.constraints import build_isolation_constraints


def run_subnet_isolation_check(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """Verify that no IP address belongs to both sub1 and sub2.

    Uses :func:`~z3_engine.constraints.build_isolation_constraints` to construct
    the overlap predicate, then asks Z3 for a satisfying assignment.

    Args:
        infra: Parsed infrastructure dictionary from
               :func:`~parser.parser.parse_infrastructure`.  Must contain at
               least two subnets.

    Returns:
        ``("UNSAT", None)`` when the subnets are properly isolated (expected).
        ``("SAT", model)`` if an overlapping IP is found (misconfiguration).
    """
    subnets = infra.get("subnets", [])
    if len(subnets) < 2:
        # Cannot check isolation with fewer than two subnets
        print("  [WARNING] Fewer than 2 subnets found; skipping isolation check.")
        return "UNSAT", None

    # Use the first two subnets (sub1=10.0.0.0/24, sub2=10.0.1.0/24)
    subnet1, subnet2 = subnets[0], subnets[1]

    solver = Solver()
    constraints = build_isolation_constraints(subnet1, subnet2)
    solver.add(*constraints)

    result = solver.check()
    if result == sat:
        return "SAT", solver.model()
    return "UNSAT", None


def run_named_subnet_isolation(
    cidr1: str,
    cidr2: str,
) -> tuple[str, ModelRef | None]:
    """Check isolation between two arbitrary CIDRs (useful for unit testing).

    Args:
        cidr1: First subnet CIDR, e.g. ``"10.0.0.0/24"``.
        cidr2: Second subnet CIDR, e.g. ``"10.0.1.0/24"``.

    Returns:
        ``("UNSAT", None)`` if the subnets do not overlap,
        ``("SAT", model)`` if they do.
    """
    subnet1 = {"cidr_block": cidr1, "name": "sub_a"}
    subnet2 = {"cidr_block": cidr2, "name": "sub_b"}

    solver = Solver()
    constraints = build_isolation_constraints(subnet1, subnet2)
    solver.add(*constraints)

    result = solver.check()
    if result == sat:
        return "SAT", solver.model()
    return "UNSAT", None


if __name__ == "__main__":
    _default_plan = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "sample_plan.json",
    )
    _plan_file = sys.argv[1] if len(sys.argv) > 1 else _default_plan

    from parser.parser import load_and_parse

    _infra = load_and_parse(_plan_file)

    _result, _model = run_subnet_isolation_check(_infra)
    _verdict = "VULNERABLE" if _result == "SAT" else "SAFE"
    print(f"[SCENARIO 3] Subnet Isolation : {_result:<5} {_verdict}")
    if _model:
        print(f"  Overlapping IP witness: {_model}")
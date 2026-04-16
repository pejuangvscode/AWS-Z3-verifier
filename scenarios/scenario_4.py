"""
scenario_4.py – Unrestricted egress / data exfiltration path.

Security question
-----------------
Can an EC2 instance in the VPC reach **any** internet destination on **any**
port, creating an unrestricted data-exfiltration channel?

Expected result
---------------
* **SAT** ⚠️  VULNERABLE – The baseline configuration has:
  * Egress rule: all traffic (protocol ``-1``, port 0–0) to ``0.0.0.0/0``.
  * Route table: default route ``0.0.0.0/0 → igw-*`` (public subnet).
  Together these form a complete outbound path.

Z3 model
--------
Variables
    ``src_ip``    – BitVec(32), the EC2 instance's IPv4 address  (inside the subnet)
    ``egress_port`` – BitVec(16), the destination TCP/UDP port

Constraints added
    1. ``src_ip ∈ subnet_cidr``            (EC2 is in a known subnet)
    2. IGW route exists (analytical precondition – not a Z3 variable)
    3. Egress SG rule allows all traffic → ``BoolVal(True)``

If the solver returns ``sat`` the model gives a concrete (src_ip, egress_port)
witness demonstrating the exfiltration channel.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from z3 import And, BitVec, BoolVal, ModelRef, Or, Solver, sat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.extractor import extract_route_table, extract_security_group_rules
from z3_engine.constraints import build_egress_constraints


def _has_igw_route(infra: dict[str, Any]) -> bool:
    """Return True if *infra* contains at least one route table with an IGW route."""
    for rt in infra.get("route_tables", []):
        for r in extract_route_table(rt):
            if r["destination_cidr"] == "0.0.0.0/0" and (r.get("gateway_id") or "").startswith("igw-"):
                return True
    return False


def run_egress_check(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """Verify whether EC2 instances can exfiltrate data via unrestricted egress.

    Evaluates the full path:
    ``EC2 → subnet → route table → IGW → internet``

    Uses the first security group and first subnet found in *infra*.  In the
    sample infrastructure both EC2 instances share the same security group and
    both subnets use the same route table.

    Args:
        infra: Parsed infrastructure dictionary from
               :func:`~parser.parser.parse_infrastructure`.

    Returns:
        ``("SAT", model)`` if an unrestricted egress path exists (vulnerable).
        ``("UNSAT", None)`` if egress is properly restricted.
    """
    # Precondition checks
    if not _has_igw_route(infra):
        return "UNSAT", None

    security_groups = infra.get("security_groups", [])
    subnets = infra.get("subnets", [])
    route_tables = infra.get("route_tables", [])

    if not security_groups or not subnets or not route_tables:
        return "UNSAT", None

    # Use the EC2 security group (first SG), first subnet, first route table
    sg = security_groups[0]
    subnet = subnets[0]
    route_table = route_tables[0]

    solver = Solver()
    constraints = build_egress_constraints(sg, subnet, route_table)
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

    _result, _model = run_egress_check(_infra)
    _verdict = "VULNERABLE" if _result == "SAT" else "SAFE"
    print(f"[SCENARIO 4] Unrestricted Egress : {_result:<5} {_verdict}")
    if _model:
        print(f"  Counterexample: {_model}")
"""
scenario_1.py – Internet → EC2 reachability via SSH (port 22) and HTTP (port 80).

Security question
-----------------
Can an arbitrary host on the public internet reach an EC2 instance in the VPC
directly on port 22 (SSH) or port 80 (HTTP)?

Expected results (vulnerable baseline config)
---------------------------------------------
* SSH  → **SAT**  ⚠️  VULNERABLE  (SG allows 0.0.0.0/0:22)
* HTTP → **SAT**  ⚠️  VULNERABLE  (SG allows 0.0.0.0/0:80)

Z3 model
--------
Variables
    ``internet_ip``  – BitVec(32), any public IPv4 address
    ``ec2_ip``       – BitVec(32), an IPv4 address inside one of the EC2 subnets

Constraints added
    1. ``internet_ip ∈ 0.0.0.0/0``           (any IP satisfies this)
    2. ``ec2_ip ∈ subnet_cidr``               (EC2 lives in a known subnet)
    3. Security group has an ingress rule where
       ``source_cidr == 0.0.0.0/0`` and the target port is in ``[from_port, to_port]``
    4. Route table has a default route to an IGW (checked analytically — not part
       of the Z3 formula but required as a precondition).

If the solver returns ``sat`` the model gives a concrete (internet_ip, ec2_ip)
witness.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from z3 import And, BitVec, BitVecVal, BoolVal, ModelRef, Not, Or, Solver, sat

# Allow standalone execution from any working directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.extractor import cidr_to_network_mask, extract_route_table, extract_security_group_rules
from z3_engine.models import ip_in_subnet, port_in_range


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _has_igw_route(infra: dict[str, Any]) -> bool:
    """Return True if *infra* contains at least one route table with an IGW route."""
    for rt in infra.get("route_tables", []):
        for r in extract_route_table(rt):
            if r["destination_cidr"] == "0.0.0.0/0" and (r.get("gateway_id") or "").startswith("igw-"):
                return True
    return False


def _check_port_reachability(
    infra: dict[str, Any],
    target_port: int,
    var_suffix: str,
) -> tuple[str, ModelRef | None]:
    """Generic helper: can an internet host reach any EC2 subnet on *target_port*?

    Args:
        infra:       Parsed infrastructure dictionary.
        target_port: The TCP port to test (e.g. 22 for SSH, 80 for HTTP).
        var_suffix:  A short string appended to Z3 variable names to avoid
                     name collisions when both checks run in the same process.

    Returns:
        ``("SAT", model)`` if the path is open, ``("UNSAT", None)`` otherwise.
    """
    # Precondition: subnet must be publicly reachable via IGW
    if not _has_igw_route(infra):
        return "UNSAT", None

    solver = Solver()
    internet_ip = BitVec(f"internet_ip_{var_suffix}", 32)
    ec2_ip = BitVec(f"ec2_ip_{var_suffix}", 32)

    # ── Constraint 1: EC2 IP must be in one of the known subnets ──
    subnet_cidrs = [s.get("cidr_block") for s in infra.get("subnets", []) if s.get("cidr_block")]
    if not subnet_cidrs:
        return "UNSAT", None

    subnet_parts = [ip_in_subnet(ec2_ip, *cidr_to_network_mask(c)) for c in subnet_cidrs]
    solver.add(Or(*subnet_parts) if len(subnet_parts) > 1 else subnet_parts[0])

    # ── Constraint 2: a security group must allow *target_port* from an internet CIDR ──
    port_bv = BitVecVal(target_port, 16)
    sg_allows = False

    for sg in infra.get("security_groups", []):
        for rule in extract_security_group_rules(sg):
            if rule["direction"] != "ingress":
                continue
            if not (rule["from_port"] <= target_port <= rule["to_port"]):
                continue
            for cidr_block in rule.get("cidr_blocks", []):
                net, mask = cidr_to_network_mask(cidr_block)
                # Add a constraint: internet_ip must satisfy this ingress CIDR
                solver.add(ip_in_subnet(internet_ip, net, mask))
                sg_allows = True
                break  # one matching cidr is sufficient
        if sg_allows:
            break

    if not sg_allows:
        return "UNSAT", None

    # ── Constraint 3: the port must be in the matching rule's range (trivial) ──
    solver.add(port_in_range(port_bv, target_port, target_port))

    result = solver.check()
    if result == sat:
        return "SAT", solver.model()
    return "UNSAT", None


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def run_ssh_reachability(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """Verify whether an internet host can reach EC2 via SSH (port 22).

    Args:
        infra: Parsed infrastructure dictionary from
               :func:`~parser.parser.parse_infrastructure`.

    Returns:
        ``("SAT", model)`` if SSH is reachable from the internet (vulnerable),
        ``("UNSAT", None)`` if it is not.
    """
    return _check_port_reachability(infra, 22, "ssh")


def run_http_reachability(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """Verify whether an internet host can reach EC2 via HTTP (port 80).

    Args:
        infra: Parsed infrastructure dictionary from
               :func:`~parser.parser.parse_infrastructure`.

    Returns:
        ``("SAT", model)`` if HTTP is reachable from the internet (vulnerable),
        ``("UNSAT", None)`` if it is not.
    """
    return _check_port_reachability(infra, 80, "http")


# ──────────────────────────────────────────────────────────────────────────────
# Standalone entry point
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _default_plan = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "tests",
        "sample_plan.json",
    )
    _plan_file = sys.argv[1] if len(sys.argv) > 1 else _default_plan

    from parser.parser import load_and_parse

    _infra = load_and_parse(_plan_file)

    _r_ssh, _m_ssh = run_ssh_reachability(_infra)
    _v_ssh = "⚠️  VULNERABLE" if _r_ssh == "SAT" else "✅  SAFE"
    print(f"[SCENARIO 1] Internet→EC2 SSH  : {_r_ssh:<5} {_v_ssh}")
    if _m_ssh:
        print(f"  Counterexample: {_m_ssh}")

    _r_http, _m_http = run_http_reachability(_infra)
    _v_http = "⚠️  VULNERABLE" if _r_http == "SAT" else "✅  SAFE"
    print(f"[SCENARIO 1] Internet→EC2 HTTP : {_r_http:<5} {_v_http}")
    if _m_http:
        print(f"  Counterexample: {_m_http}")

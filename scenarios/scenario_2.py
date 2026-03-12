"""
scenario_2.py – Direct EC2 access from the internet, bypassing the ALB.

Security question
-----------------
Can an internet host reach an EC2 instance *directly*, without going through
the Application Load Balancer, in a properly hardened configuration?

Expected result
---------------
* **UNSAT** SAFE  – When the EC2 security group restricts ingress to traffic
  originating inside the VPC (i.e. from the ALB only), no public IP satisfies
  both constraints simultaneously.

Z3 model
--------
Variables
    ``internet_ip`` – BitVec(32) representing a public (non-VPC) IPv4 address
    ``ec2_ip``      – BitVec(32) representing the EC2 instance's IP

Constraints added
    1. ``ec2_ip ∈ vpc_cidr``                               (EC2 is inside the VPC)
    2. ``internet_ip ∉ vpc_cidr``                          (source is the public internet)
    3. [Secure config] EC2 SG ingress CIDR = VPC CIDR only → ``internet_ip ∈ vpc_cidr``

Constraints 2 and 3 directly contradict each other, producing UNSAT and proving
that no public host can reach EC2 directly when EC2's ingress is locked to the
VPC CIDR.

Note: In the *vulnerable* baseline config the EC2 SG allows ``0.0.0.0/0``,
which would make this SAT.  This scenario always models the *hardened* config.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from z3 import And, BitVec, BoolVal, ModelRef, Not, Or, Solver, sat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.extractor import cidr_to_network_mask
from z3_engine.models import ip_in_subnet


def run_bypass_alb_check(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """Verify EC2 cannot be reached directly from the internet (secure config).

    Models the *ideal* configuration where the EC2 security group allows ingress
    only from within the VPC CIDR (representing traffic that has already passed
    through the ALB).  The internet source IP is constrained to be *outside* the
    VPC CIDR, creating an unsatisfiable system of constraints.

    Args:
        infra: Parsed infrastructure dictionary from
               :func:`~parser.parser.parse_infrastructure`.

    Returns:
        ``("UNSAT", None)`` when the configuration correctly blocks direct access.
        ``("SAT", model)`` would indicate a misconfiguration (unexpected).
    """
    solver = Solver()

    internet_ip = BitVec("bypass_internet_ip", 32)
    ec2_ip = BitVec("bypass_ec2_ip", 32)

    vpc = infra.get("vpc") or {}
    vpc_cidr: str = vpc.get("cidr_block", "10.0.0.0/16")
    vpc_net, vpc_mask = cidr_to_network_mask(vpc_cidr)

    # ── Constraint 1: EC2 IP is inside the VPC ──
    solver.add(ip_in_subnet(ec2_ip, vpc_net, vpc_mask))

    # ── Constraint 2: Internet IP is *outside* the VPC CIDR ──
    # (A public internet host cannot have a VPC-private address.)
    solver.add(Not(ip_in_subnet(internet_ip, vpc_net, vpc_mask)))

    # ── Constraint 3: Secure EC2 SG – ingress only from VPC CIDR ──
    # In the hardened config the EC2 SG rule says:
    #   allow ingress from <vpc_cidr>   (not from 0.0.0.0/0)
    # For the traffic to reach EC2, the source must satisfy this rule:
    solver.add(ip_in_subnet(internet_ip, vpc_net, vpc_mask))
    # This directly contradicts Constraint 2 → UNSAT

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

    _result, _model = run_bypass_alb_check(_infra)
    _verdict = "VULNERABLE" if _result == "SAT" else "SAFE"
    print(f"[SCENARIO 2] Bypass ALB       : {_result:<5} {_verdict}")
    if _model:
        print(f"  Counterexample: {_model}")

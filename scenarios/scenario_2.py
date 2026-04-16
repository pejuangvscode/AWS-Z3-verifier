"""
scenario_2.py – Direct EC2 access from the internet, bypassing the ALB.

Security question
-----------------
Can an internet host reach an EC2 instance *directly*, without going through
the Application Load Balancer?

This scenario reads the actual Security Group configuration from the parsed
infrastructure (sample_plan.json) rather than using a hardcoded "ideal" config.
It evaluates the real-world IaC as written.

Expected result (actual main.tf config)
----------------------------------------
* **SAT** ⚠️  VULNERABLE – In main.tf, EC2 and ALB share the same single
  Security Group (webSg) which allows ingress from 0.0.0.0/0 on port 80.
  Because the EC2 SG is not restricted to VPC-internal traffic only,
  Z3 finds a valid internet IP that satisfies all constraints simultaneously,
  proving that ALB does NOT function as the sole entry point.

Z3 model
--------
Variables
    ``internet_ip`` – BitVec(32) representing a public (non-VPC) IPv4 address
    ``ec2_ip``      – BitVec(32) representing the EC2 instance's IP

Constraints added
    1. ``ec2_ip ∈ vpc_cidr``           (EC2 is inside the VPC)
    2. ``internet_ip ∉ vpc_cidr``      (source is a public internet address)
    3. EC2 SG ingress CIDR from infra  (read from actual security group rules)

If constraint 3 uses ``0.0.0.0/0`` (as in webSg), constraints 2 and 3 are
compatible → SAT (VULNERABLE): a public IP can reach EC2 directly.

If constraint 3 were restricted to the VPC CIDR only, constraints 2 and 3
would contradict → UNSAT (SAFE): direct access is blocked.

Laporan disimpan otomatis ke: reports/scenario_2/report_N.txt
"""

from __future__ import annotations

import os
import sys
from typing import Any

from z3 import BitVec, BitVecVal, ModelRef, Not, Or, Solver, sat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parser.extractor import cidr_to_network_mask, extract_security_group_rules
from z3_engine.models import ip_in_subnet, port_in_range


def run_bypass_alb_check(infra: dict[str, Any]) -> tuple[str, ModelRef | None]:
    """Verify whether EC2 can be reached directly from the internet,
    bypassing the ALB, based on the *actual* Security Group rules in infra.

    Reads ingress rules from the real security group in the parsed infrastructure
    instead of assuming a hardened configuration. This reflects the true
    state of the IaC as deployed.

    Logic:
        - internet_ip must be OUTSIDE the VPC (it is a real internet host)
        - For each EC2 ingress SG rule allowing HTTP (port 80) from a CIDR:
            - If that CIDR includes addresses outside the VPC (e.g. 0.0.0.0/0),
              then internet_ip can satisfy the SG rule → SAT (VULNERABLE)
            - If all CIDRs are VPC-internal only, no internet IP can satisfy
              the rule while also being outside the VPC → UNSAT (SAFE)

    Args:
        infra: Parsed infrastructure dictionary from
               :func:`~parser.parser.parse_infrastructure`.

    Returns:
        ``("SAT", model)``   when EC2 is reachable directly from internet
                             (ALB is NOT enforced as the sole entry point).
        ``("UNSAT", None)``  when EC2 is unreachable from internet directly
                             (ALB correctly acts as the sole entry point).
    """
    solver = Solver()

    internet_ip = BitVec("bypass_internet_ip", 32)
    ec2_ip = BitVec("bypass_ec2_ip", 32)

    # ── Read VPC CIDR from infra ──────────────────────────────────────────────
    vpc = infra.get("vpc") or {}
    vpc_cidr: str = vpc.get("cidr_block", "10.0.0.0/16")
    vpc_net, vpc_mask = cidr_to_network_mask(vpc_cidr)

    # ── Constraint 1: EC2 IP is inside the VPC ───────────────────────────────
    solver.add(ip_in_subnet(ec2_ip, vpc_net, vpc_mask))

    # ── Constraint 2: Internet IP is OUTSIDE the VPC CIDR ───────────────────
    # A real public internet host cannot have a VPC-private address.
    solver.add(Not(ip_in_subnet(internet_ip, vpc_net, vpc_mask)))

    # ── Constraint 3: Read actual EC2 ingress SG rules from infra ────────────
    # We check port 80 (HTTP) — the primary application port.
    # If the SG allows 0.0.0.0/0 on port 80, then internet_ip can match,
    # which is compatible with Constraint 2 → SAT (VULNERABLE).
    # If the SG restricts to VPC CIDR only, Constraint 2 and 3 contradict → UNSAT.
    TARGET_PORT = 80
    sg_allows_from_internet = False

    for sg in infra.get("security_groups", []):
        for rule in extract_security_group_rules(sg):
            if rule["direction"] != "ingress":
                continue
            if not (rule["from_port"] <= TARGET_PORT <= rule["to_port"]):
                continue
            for cidr_block in rule.get("cidr_blocks", []):
                net, mask = cidr_to_network_mask(cidr_block)
                # Add: internet_ip must satisfy this SG ingress CIDR
                solver.add(ip_in_subnet(internet_ip, net, mask))
                sg_allows_from_internet = True
                break
        if sg_allows_from_internet:
            break

    # If no SG rule allows port 80 ingress at all → no path possible
    if not sg_allows_from_internet:
        return "UNSAT", None

    # ── Ask Z3 ───────────────────────────────────────────────────────────────
    # SAT  → internet_ip is outside VPC AND satisfies the SG rule → VULNERABLE
    # UNSAT → no such ip exists → SAFE
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
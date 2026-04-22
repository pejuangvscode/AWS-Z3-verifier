"""
constraints.py – Z3 constraint builders for AWS network reachability analysis.

Each builder constructs a set of Z3 ``BoolRef`` expressions that together model
a specific reachability or isolation property.  Pass the resulting list to a
``z3.Solver`` to check satisfiability:

* ``SAT``  → a concrete witness exists (e.g. a packet that reaches the target).
* ``UNSAT`` → no such witness exists (the property is unreachable / safe).
"""

from __future__ import annotations

from typing import Any

from z3 import And, BitVec, BoolRef, BoolVal, Not, Or

from parser.extractor import (
    cidr_to_network_mask,
    extract_route_table,
    extract_security_group_rules,
)
from z3_engine.models import ip_in_subnet, port_in_range


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _has_igw_route(route_table: dict[str, Any]) -> bool:
    """Return ``True`` if *route_table* has a default route to an IGW."""
    routes = extract_route_table(route_table)
    return any(
        r.get("destination_cidr") == "0.0.0.0/0"
        and (r.get("gateway_id") or "").startswith("igw-")
        for r in routes
    )


def _any_igw_route(route_tables: list[dict[str, Any]]) -> bool:
    """Return ``True`` if *any* route table in the list has an IGW default route."""
    return any(_has_igw_route(rt) for rt in route_tables)


# ──────────────────────────────────────────────────────────────────────────────
# Public constraint builders
# ──────────────────────────────────────────────────────────────────────────────

def build_reachability_constraints(infra_dict: dict[str, Any]) -> list[BoolRef]:
    """Build Z3 constraints modelling the full inbound path to EC2.

    Path modelled::

        Internet → IGW → Route Table → Public Subnet → Security Group → EC2

    The resulting list represents the conjunction of all conditions that must
    hold simultaneously for a remote host to reach an EC2 instance.  If the
    conjunction is ``SAT``, the solver returns a concrete (internet_ip, ec2_ip,
    port) triple demonstrating the reachable path.

    Args:
        infra_dict: Structured infrastructure dict from
                    :func:`~parser.parser.parse_infrastructure`.

    Returns:
        A list of Z3 ``BoolRef`` constraints.  An empty or ``[BoolVal(False)]``
        list represents an unreachable path.
    """
    route_tables: list[dict[str, Any]] = infra_dict.get("route_tables", [])

    # ── Prerequisite: at least one public route to the internet ──
    if not _any_igw_route(route_tables):
        return [BoolVal(False)]

    internet_ip = BitVec("reach_internet_ip", 32)
    dest_ip = BitVec("reach_dest_ip", 32)
    port_var = BitVec("reach_port", 16)

    # ── Destination must be within a known EC2 subnet ──
    subnet_parts: list[BoolRef] = []
    for subnet in infra_dict.get("subnets", []):
        cidr = subnet.get("cidr_block", "")
        if cidr:
            net, mask = cidr_to_network_mask(cidr)
            subnet_parts.append(ip_in_subnet(dest_ip, net, mask))

    if not subnet_parts:
        return [BoolVal(False)]

    dest_in_any_subnet = Or(*subnet_parts) if len(subnet_parts) > 1 else subnet_parts[0]

    # ── Security group must allow the traffic ──
    sg_allow_parts: list[BoolRef] = []
    for sg in infra_dict.get("security_groups", []):
        for rule in extract_security_group_rules(sg):
            if rule["direction"] != "ingress":
                continue
            for cidr_block in rule.get("cidr_blocks", []):
                net, mask = cidr_to_network_mask(cidr_block)
                source_allowed = ip_in_subnet(internet_ip, net, mask)
                fp, tp = rule["from_port"], rule["to_port"]
                if fp == 0 and tp == 0 and rule["protocol"] == "-1":
                    # All-traffic rule
                    sg_allow_parts.append(source_allowed)
                else:
                    sg_allow_parts.append(And(source_allowed, port_in_range(port_var, fp, tp)))

    if not sg_allow_parts:
        return [BoolVal(False)]

    sg_allows = Or(*sg_allow_parts) if len(sg_allow_parts) > 1 else sg_allow_parts[0]

    return [And(dest_in_any_subnet, sg_allows)]


def build_isolation_constraints(
    subnet1: dict[str, Any],
    subnet2: dict[str, Any],
) -> list[BoolRef]:
    """Build Z3 constraints that check for IP-space overlap between two subnets.

    The constraint asserts the existence of an IP address *x* that satisfies
    *both* subnet membership predicates simultaneously:

    .. math::

        \\exists x \\;.\\; x \\in \\mathit{subnet}_1 \\wedge x \\in \\mathit{subnet}_2

    * ``SAT``  → the subnets have overlapping address space (misconfiguration).
    * ``UNSAT`` → the subnets are properly isolated (no common IP).

    Args:
        subnet1: First subnet dict with a ``"cidr_block"`` key.
        subnet2: Second subnet dict with a ``"cidr_block"`` key.

    Returns:
        A single-element list containing the overlap constraint.
    """
    cidr1 = subnet1.get("cidr_block", "0.0.0.0/0")
    cidr2 = subnet2.get("cidr_block", "0.0.0.0/0")

    net1, mask1 = cidr_to_network_mask(cidr1)
    net2, mask2 = cidr_to_network_mask(cidr2)

    x = BitVec("isolation_x", 32)
    return [And(ip_in_subnet(x, net1, mask1), ip_in_subnet(x, net2, mask2))]


def build_egress_constraints(
    sg_dict: dict[str, Any],
    subnet_dict: dict[str, Any],
    route_table: dict[str, Any],
) -> list[BoolRef]:
    """Build Z3 constraints modelling the EC2 outbound (egress) data path.

    Path modelled::

        EC2 (in subnet) → Egress Security Group Rule → Route Table → IGW → Internet

    All three conditions must hold for data exfiltration to be possible:

    1. The source IP is within *subnet_dict*'s CIDR.
    2. The egress security group rule allows traffic to ``0.0.0.0/0``.
    3. The route table has a default route (``0.0.0.0/0``) to an IGW.

    Args:
        sg_dict:     Security group dict with egress rules.
        subnet_dict: Subnet dict containing the EC2 instance.
        route_table: Route table dict associated with the subnet.

    Returns:
        A list of Z3 ``BoolRef`` constraints.  ``SAT`` means unrestricted data
        exfiltration is possible.
    """
    # ── Prerequisite: subnet must have an outbound IGW route ──
    if not _has_igw_route(route_table):
        return [BoolVal(False)]

    cidr = subnet_dict.get("cidr_block", "0.0.0.0/32")
    net, mask = cidr_to_network_mask(cidr)

    src_ip = BitVec("egress_src_ip", 32)
    port_var = BitVec("egress_port", 16)

    src_in_subnet = ip_in_subnet(src_ip, net, mask)

    # ── Collect egress rules that allow traffic to the internet (0.0.0.0/0) ──
    egress_parts: list[BoolRef] = []
    for rule in extract_security_group_rules(sg_dict):
        if rule["direction"] != "egress":
            continue
        for cidr_block in rule.get("cidr_blocks", []):
            if cidr_block != "0.0.0.0/0":
                continue
            fp, tp = rule["from_port"], rule["to_port"]
            if fp == 0 and tp == 0 and rule["protocol"] == "-1":
                # All-traffic egress rule
                egress_parts.append(BoolVal(True))
            else:
                egress_parts.append(port_in_range(port_var, fp, tp))

    if not egress_parts:
        return [BoolVal(False)]

    egress_allowed = Or(*egress_parts) if len(egress_parts) > 1 else egress_parts[0]

    return [And(src_in_subnet, egress_allowed)]
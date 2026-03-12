"""
axioms.py – AWS-implicit security axioms encoded as Z3 Boolean expressions.

These axioms capture AWS behavioural defaults that are not expressed explicitly
in a Terraform plan but still govern traffic flow:

* Security groups are *default-deny*: without an explicit allow rule no traffic
  reaches the instance.
* A subnet is *public* only when its associated route table routes ``0.0.0.0/0``
  to an Internet Gateway (``igw-*``).
"""

from __future__ import annotations

from typing import Any

from z3 import BoolRef, BoolVal

from parser.extractor import extract_route_table


def default_deny_axiom() -> BoolRef:
    """Return the AWS default-deny axiom as a Z3 Boolean constant.

    AWS security groups are *stateful allow-lists*: if no ingress rule matches,
    the packet is silently dropped.  This is modelled as the logical bottom
    value (⊥ / ``False``) so that it can be composed with ``Or`` — any explicit
    allow rule that evaluates to ``True`` will override it.

    Returns:
        ``BoolVal(False)`` — no traffic is permitted by default.
    """
    return BoolVal(False)


def igw_reachability_axiom(route_tables: list[dict[str, Any]]) -> BoolRef:
    """Check whether any route table provides a default route to the internet.

    An Internet Gateway is identified by a ``gateway_id`` that starts with
    ``"igw-"``.  A default route is ``destination_cidr == "0.0.0.0/0"``.

    Args:
        route_tables: List of raw route-table dicts from
                      :func:`~parser.parser.parse_infrastructure`.  Each entry
                      is passed through :func:`~parser.extractor.extract_route_table`
                      internally.

    Returns:
        ``BoolVal(True)`` if at least one route table has a default IGW route,
        ``BoolVal(False)`` otherwise.
    """
    for rt in route_tables:
        routes = extract_route_table(rt)
        for route in routes:
            dest = route.get("destination_cidr", "")
            gw = route.get("gateway_id") or ""
            if dest == "0.0.0.0/0" and gw.startswith("igw-"):
                return BoolVal(True)

    return BoolVal(False)


def subnet_public_axiom(
    subnet: dict[str, Any],
    route_table: dict[str, Any],
) -> BoolRef:
    """Determine whether *subnet* is publicly reachable via *route_table*.

    A subnet is *public* in AWS when the route table associated with it contains
    a default route (``0.0.0.0/0``) pointing to an Internet Gateway.  This
    axiom evaluates that condition and returns the appropriate Z3 constant.

    Args:
        subnet: Subnet dict from :func:`~parser.parser.parse_infrastructure`.
                Included for future association-check extensions; not directly
                inspected in the current implementation.
        route_table: Route-table dict from
                     :func:`~parser.parser.parse_infrastructure`.

    Returns:
        ``BoolVal(True)`` if *route_table* has a ``0.0.0.0/0 → igw-*`` route,
        ``BoolVal(False)`` otherwise.
    """
    routes = extract_route_table(route_table)

    for route in routes:
        dest = route.get("destination_cidr", "")
        gw = route.get("gateway_id") or ""
        if dest == "0.0.0.0/0" and gw.startswith("igw-"):
            return BoolVal(True)

    return BoolVal(False)

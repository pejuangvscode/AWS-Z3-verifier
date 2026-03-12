"""
extractor.py – Helper functions to extract and convert network attributes from
the structured infrastructure dict returned by :mod:`parser.parser`.
"""

from __future__ import annotations

import ipaddress
from typing import Any


def cidr_to_network_mask(cidr: str) -> tuple[int, int]:
    """Convert a CIDR notation string to a ``(network_address_int, mask_int)`` pair.

    Both values are unsigned 32-bit integers so they can be directly consumed by
    Z3 ``BitVecVal(value, 32)`` calls.

    Args:
        cidr: CIDR notation string, e.g. ``"10.0.0.0/24"`` or ``"0.0.0.0/0"``.

    Returns:
        ``(network_address_as_int, netmask_as_int)``

    Example::

        >>> cidr_to_network_mask("10.0.0.0/24")
        (167772160, 4294967040)   # 0x0A000000, 0xFFFFFF00

        >>> cidr_to_network_mask("0.0.0.0/0")
        (0, 0)                    # matches every IP
    """
    network = ipaddress.IPv4Network(cidr, strict=False)
    return int(network.network_address), int(network.netmask)


def extract_security_group_rules(sg_dict: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all ingress and egress rules from a security-group entry.

    Handles both list-style rules (standard ``terraform show -json`` output) and
    the case where the list value is ``None`` (Terraform sometimes emits that for
    empty rule sets).

    Args:
        sg_dict: A security-group dict as returned by :func:`~parser.parser.parse_infrastructure`.
                 Expected to contain ``"ingress"`` and/or ``"egress"`` list keys.

    Returns:
        A list of rule dicts, each with the following keys:

        .. code-block:: python

            {
                "direction":               "ingress" | "egress",
                "from_port":               int,
                "to_port":                 int,
                "protocol":                str,          # e.g. "tcp", "-1"
                "cidr_blocks":             list[str],
                "ipv6_cidr_blocks":        list[str],
                "source_security_group_id": str | None,
            }
    """
    rules: list[dict[str, Any]] = []

    for direction in ("ingress", "egress"):
        raw_rules = sg_dict.get(direction) or []
        if not isinstance(raw_rules, list):
            continue

        for rule in raw_rules:
            if not isinstance(rule, dict):
                continue

            # Normalise "security_groups" which terraform may emit as a list
            raw_sg_ref = rule.get("security_groups") or rule.get("source_security_group_id")
            sg_ref: str | None = None
            if isinstance(raw_sg_ref, list) and raw_sg_ref:
                sg_ref = raw_sg_ref[0]
            elif isinstance(raw_sg_ref, str) and raw_sg_ref:
                sg_ref = raw_sg_ref

            rules.append(
                {
                    "direction": direction,
                    "from_port": int(rule.get("from_port", 0)),
                    "to_port": int(rule.get("to_port", 0)),
                    "protocol": str(rule.get("protocol", "-1")),
                    "cidr_blocks": list(rule.get("cidr_blocks", None) or []),
                    "ipv6_cidr_blocks": list(rule.get("ipv6_cidr_blocks", None) or []),
                    "source_security_group_id": sg_ref,
                }
            )

    return rules


def extract_route_table(rt_dict: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract all routes from a route-table entry.

    Args:
        rt_dict: A route-table dict as returned by
                 :func:`~parser.parser.parse_infrastructure`.  The routes are
                 expected to live under the ``"route"`` key.

    Returns:
        A list of route dicts, each with the following keys:

        .. code-block:: python

            {
                "destination_cidr": str,        # e.g. "0.0.0.0/0"
                "gateway_id":       str | None,  # "igw-*" for internet gateways
                "nat_gateway_id":   str | None,
                "instance_id":      str | None,
            }
    """
    routes: list[dict[str, Any]] = []
    raw_routes = rt_dict.get("route") or []

    if not isinstance(raw_routes, list):
        return routes

    for route in raw_routes:
        if not isinstance(route, dict):
            continue

        routes.append(
            {
                "destination_cidr": route.get("cidr_block", ""),
                "gateway_id": route.get("gateway_id") or None,
                "nat_gateway_id": route.get("nat_gateway_id") or None,
                "instance_id": route.get("instance_id") or None,
            }
        )

    return routes

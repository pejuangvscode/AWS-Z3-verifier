"""
models.py – Z3 BitVector primitives for IP-address and port-range reasoning.

All IP addresses are represented as 32-bit unsigned bit-vectors so that subnet
membership can be expressed as pure bit-masking, which Z3 solves efficiently.
Ports are modelled as 16-bit unsigned bit-vectors (0–65535).
"""

from __future__ import annotations

from typing import Any

from z3 import And, BitVec, BitVecRef, BitVecVal, BoolRef, ULE


def ip_in_subnet(ip_bitvec: BitVecRef, network_int: int, mask_int: int) -> BoolRef:
    """Return a Z3 constraint asserting *ip_bitvec* belongs to the given subnet.

    The predicate is the standard host-bits test used by all IP stacks:

    .. math::

        (\\mathit{ip} \\wedge_{32} \\mathit{mask}) = \\mathit{network}

    Args:
        ip_bitvec: A Z3 ``BitVec(32)`` variable representing an IPv4 address.
        network_int: The subnet's network address as an unsigned 32-bit integer
                     (obtained from :func:`~parser.extractor.cidr_to_network_mask`).
        mask_int:    The subnet's netmask as an unsigned 32-bit integer.

    Returns:
        A Z3 ``BoolRef`` that is satisfiable iff *ip_bitvec* is in the subnet.

    Example::

        >>> from z3 import BitVec, Solver, sat
        >>> ip = BitVec("ip", 32)
        >>> solver = Solver()
        >>> solver.add(ip_in_subnet(ip, 0x0A000000, 0xFFFFFF00))  # 10.0.0.0/24
        >>> solver.check()
        sat
    """
    mask_bv = BitVecVal(mask_int, 32)
    network_bv = BitVecVal(network_int, 32)
    return (ip_bitvec & mask_bv) == network_bv


def port_in_range(port_var: BitVecRef, from_port: int, to_port: int) -> BoolRef:
    """Return a Z3 constraint asserting *port_var* is within ``[from_port, to_port]``.

    Unsigned less-than-or-equal (``ULE``) is used so that the full 16-bit range
    (0–65535) is handled correctly without sign confusion.

    Args:
        port_var:  A Z3 ``BitVec(16)`` variable representing a TCP/UDP port.
        from_port: Inclusive lower bound of the port range (0–65535).
        to_port:   Inclusive upper bound of the port range (0–65535).

    Returns:
        A Z3 ``BoolRef``: ``from_port ≤ port_var ≤ to_port``.
    """
    from_bv = BitVecVal(from_port, 16)
    to_bv = BitVecVal(to_port, 16)
    return And(ULE(from_bv, port_var), ULE(port_var, to_bv))


def build_subnet_model(subnet_dict: dict[str, Any]) -> dict[str, Any]:
    """Build a Z3 symbolic model for a subnet.

    Creates a fresh ``BitVec(32)`` variable scoped to the subnet so that the
    solver can reason about which IP addresses belong to this subnet.

    Args:
        subnet_dict: A subnet dict from :func:`~parser.parser.parse_infrastructure`.
                     Must contain a ``"cidr_block"`` key.  ``"name"`` or
                     ``"address"`` are used to derive a unique variable name.

    Returns:
        A dict with the following keys:

        .. code-block:: python

            {
                "name":        str,         # human-readable label
                "cidr":        str,         # original CIDR string
                "network_int": int,         # network address as 32-bit int
                "mask_int":    int,         # netmask as 32-bit int
                "ip_var":      BitVecRef,   # Z3 BitVec(32) for IPs in this subnet
            }
    """
    from parser.extractor import cidr_to_network_mask

    name: str = subnet_dict.get("name") or subnet_dict.get("address") or "unknown"
    cidr: str = subnet_dict.get("cidr_block", "0.0.0.0/0")
    network_int, mask_int = cidr_to_network_mask(cidr)

    # Derive a valid Z3 identifier (no hyphens/dots)
    safe_name = name.replace("-", "_").replace(".", "_")
    ip_var: BitVecRef = BitVec(f"ip_{safe_name}", 32)

    return {
        "name": name,
        "cidr": cidr,
        "network_int": network_int,
        "mask_int": mask_int,
        "ip_var": ip_var,
    }

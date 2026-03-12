"""
test_models.py – Unit tests for the z3_engine.models module.

Tests cover:
* :func:`~z3_engine.models.ip_in_subnet`
* :func:`~z3_engine.models.port_in_range`
* :func:`~z3_engine.models.build_subnet_model`
"""

from __future__ import annotations

import pytest
from z3 import BitVec, BitVecVal, ModelRef, Solver, sat, unsat

from parser.extractor import cidr_to_network_mask
from z3_engine.models import build_subnet_model, ip_in_subnet, port_in_range


# ─────────────────────────────────────────────────────────────────────────────
# ip_in_subnet
# ─────────────────────────────────────────────────────────────────────────────

class TestIpInSubnet:
    """Tests for the ip_in_subnet Z3 predicate."""

    def _solve_with_value(self, ip_int: int, cidr: str) -> bool:
        """Return True if the concrete IP satisfies the subnet membership predicate."""
        net, mask = cidr_to_network_mask(cidr)
        solver = Solver()
        ip_var = BitVec("test_ip", 32)
        solver.add(ip_var == BitVecVal(ip_int, 32))
        solver.add(ip_in_subnet(ip_var, net, mask))
        return solver.check() == sat

    def test_ip_in_24_subnet(self) -> None:
        # 10.0.0.100 ∈ 10.0.0.0/24
        assert self._solve_with_value(0x0A000064, "10.0.0.0/24")

    def test_ip_at_network_address(self) -> None:
        # 10.0.0.0 ∈ 10.0.0.0/24
        assert self._solve_with_value(0x0A000000, "10.0.0.0/24")

    def test_ip_outside_24_subnet(self) -> None:
        # 10.0.1.1 ∉ 10.0.0.0/24
        assert not self._solve_with_value(0x0A000101, "10.0.0.0/24")

    def test_ip_in_16_subnet(self) -> None:
        # 10.0.1.50 ∈ 10.0.0.0/16
        assert self._solve_with_value(0x0A000132, "10.0.0.0/16")

    def test_any_ip_in_0_0_0_0_0(self) -> None:
        # Any IP should match 0.0.0.0/0 (mask=0 → network=0, any & 0 == 0)
        assert self._solve_with_value(0x01020304, "0.0.0.0/0")

    def test_symbolic_ip_sat(self) -> None:
        """Symbolic IP can be found inside a subnet."""
        net, mask = cidr_to_network_mask("10.0.0.0/24")
        ip = BitVec("sym_ip_sat", 32)
        solver = Solver()
        solver.add(ip_in_subnet(ip, net, mask))
        assert solver.check() == sat

    def test_overlap_different_subnets_unsat(self) -> None:
        """No single IP belongs to both 10.0.0.0/24 and 10.0.1.0/24."""
        from z3 import And

        net1, mask1 = cidr_to_network_mask("10.0.0.0/24")
        net2, mask2 = cidr_to_network_mask("10.0.1.0/24")
        x = BitVec("overlap_x", 32)
        solver = Solver()
        solver.add(And(ip_in_subnet(x, net1, mask1), ip_in_subnet(x, net2, mask2)))
        assert solver.check() == unsat


# ─────────────────────────────────────────────────────────────────────────────
# port_in_range
# ─────────────────────────────────────────────────────────────────────────────

class TestPortInRange:
    """Tests for the port_in_range Z3 predicate."""

    def _check(self, port_val: int, from_port: int, to_port: int) -> bool:
        port_var = BitVec("p", 16)
        solver = Solver()
        solver.add(port_var == BitVecVal(port_val, 16))
        solver.add(port_in_range(port_var, from_port, to_port))
        return solver.check() == sat

    def test_port_at_lower_bound(self) -> None:
        assert self._check(22, 22, 22)

    def test_port_at_upper_bound(self) -> None:
        assert self._check(80, 80, 80)

    def test_port_in_range(self) -> None:
        assert self._check(1024, 1000, 2000)

    def test_port_below_range(self) -> None:
        assert not self._check(21, 22, 22)

    def test_port_above_range(self) -> None:
        assert not self._check(81, 80, 80)

    def test_wide_range(self) -> None:
        # Port 0 should be in range [0, 65535]
        assert self._check(0, 0, 65535)

    def test_symbolic_port_sat(self) -> None:
        p = BitVec("sym_port", 16)
        solver = Solver()
        solver.add(port_in_range(p, 8000, 9000))
        assert solver.check() == sat

    def test_contradictory_range_unsat(self) -> None:
        """port ≥ 9000 AND port ≤ 443 is unsatisfiable."""
        from z3 import And

        p = BitVec("contra_port", 16)
        solver = Solver()
        solver.add(port_in_range(p, 9000, 9000))
        solver.add(port_in_range(p, 443, 443))
        assert solver.check() == unsat


# ─────────────────────────────────────────────────────────────────────────────
# build_subnet_model
# ─────────────────────────────────────────────────────────────────────────────

class TestBuildSubnetModel:
    """Tests for the build_subnet_model factory."""

    def _subnet_dict(self, name: str = "sub1", cidr: str = "10.0.0.0/24") -> dict:
        return {"name": name, "cidr_block": cidr}

    def test_returns_dict(self) -> None:
        model = build_subnet_model(self._subnet_dict())
        assert isinstance(model, dict)

    def test_contains_expected_keys(self) -> None:
        model = build_subnet_model(self._subnet_dict())
        for key in ("name", "cidr", "network_int", "mask_int", "ip_var"):
            assert key in model, f"Missing key: {key}"

    def test_cidr_round_trip(self) -> None:
        model = build_subnet_model(self._subnet_dict(cidr="10.0.1.0/24"))
        assert model["cidr"] == "10.0.1.0/24"
        assert model["network_int"] == 0x0A000100
        assert model["mask_int"] == 0xFFFFFF00

    def test_ip_var_is_bitvec(self) -> None:
        from z3 import is_bv

        model = build_subnet_model(self._subnet_dict())
        assert is_bv(model["ip_var"])

    def test_ip_var_size_32(self) -> None:
        model = build_subnet_model(self._subnet_dict())
        assert model["ip_var"].size() == 32

    def test_ip_var_name_derived_from_subnet(self) -> None:
        model = build_subnet_model(self._subnet_dict(name="public-subnet-1"))
        # Hyphens should be replaced with underscores
        assert "public_subnet_1" in str(model["ip_var"])

    def test_ip_var_satisfies_own_subnet(self) -> None:
        """The model's ip_var should be satisfiable within its own subnet."""
        model = build_subnet_model(self._subnet_dict())
        solver = Solver()
        solver.add(ip_in_subnet(model["ip_var"], model["network_int"], model["mask_int"]))
        assert solver.check() == sat

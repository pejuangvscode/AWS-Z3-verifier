"""
test_scenarios.py – Integration tests for all five security scenarios.

Each test loads the bundled ``sample_plan.json`` to build the infrastructure
model and then asserts the expected SAT/UNSAT result for each scenario.

Expected results (by design of the sample infrastructure)
----------------------------------------------------------
Scenario 1 – SSH reachability    : SAT   (SG allows 0.0.0.0/0 on port 22)
Scenario 1 – HTTP reachability   : SAT   (SG allows 0.0.0.0/0 on port 80)
Scenario 2 – ALB bypass          : SAT   (vulnerable, EC2 and ALB share same SG with 0.0.0.0/0)
Scenario 3 – Subnet isolation    : UNSAT (10.0.0.0/24 and 10.0.1.0/24 don't overlap)
Scenario 4 – Unrestricted egress : SAT   (all-traffic egress rule + IGW route)
Scenario 5 – After fix, SSH      : UNSAT (ingress restricted to VPC CIDR only)
Scenario 5 – After fix, egress   : UNSAT (egress restricted to port 443 only)
"""

from __future__ import annotations

import os

import pytest

from parser.parser import load_and_parse

# ── Shared fixture ────────────────────────────────────────────────────────────
SAMPLE_PLAN = os.path.join(os.path.dirname(__file__), "sample_plan.json")


@pytest.fixture(scope="module")
def infra() -> dict:
    """Load and parse the sample plan once for all tests in this module."""
    return load_and_parse(SAMPLE_PLAN)


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 1 – Internet → EC2 (SSH / HTTP)
# ─────────────────────────────────────────────────────────────────────────────

class TestScenario1:
    def test_ssh_reachability_is_sat(self, infra: dict) -> None:
        """SSH port 22 is open to the internet → SAT (vulnerable)."""
        from scenarios.scenario_1 import run_ssh_reachability

        result, model = run_ssh_reachability(infra)
        assert result == "SAT", "Expected SAT: SG allows 0.0.0.0/0 on port 22"
        assert model is not None

    def test_http_reachability_is_sat(self, infra: dict) -> None:
        """HTTP port 80 is open to the internet → SAT (vulnerable)."""
        from scenarios.scenario_1 import run_http_reachability

        result, model = run_http_reachability(infra)
        assert result == "SAT", "Expected SAT: SG allows 0.0.0.0/0 on port 80"
        assert model is not None

    def test_closed_port_is_unsat(self, infra: dict) -> None:
        """Port 5432 (PostgreSQL) is not in any ingress rule → UNSAT."""
        from scenarios.scenario_1 import _check_port_reachability

        result, model = _check_port_reachability(infra, 5432, "postgres")
        assert result == "UNSAT"
        assert model is None


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 2 – ALB bypass
# ─────────────────────────────────────────────────────────────────────────────

class TestScenario2:
    def test_bypass_alb_is_sat(self, infra: dict) -> None:
        """EC2 and ALB share same SG (0.0.0.0/0 on port 80) → SAT (internet can bypass ALB)."""
        from scenarios.scenario_2 import run_bypass_alb_check

        result, model = run_bypass_alb_check(infra)
        assert result == "SAT", "Expected SAT: EC2 SG allows 0.0.0.0/0, direct access possible"
        assert model is not None


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 3 – Subnet isolation
# ─────────────────────────────────────────────────────────────────────────────

class TestScenario3:
    def test_sub1_sub2_are_isolated(self, infra: dict) -> None:
        """10.0.0.0/24 and 10.0.1.0/24 do not overlap → UNSAT."""
        from scenarios.scenario_3 import run_subnet_isolation_check

        result, model = run_subnet_isolation_check(infra)
        assert result == "UNSAT", "Expected UNSAT: subnets should not overlap"
        assert model is None

    def test_overlapping_cidrs_give_sat(self) -> None:
        """Two identical CIDRs should produce SAT (overlap detected)."""
        from scenarios.scenario_3 import run_named_subnet_isolation

        result, model = run_named_subnet_isolation("10.0.0.0/24", "10.0.0.0/24")
        assert result == "SAT", "Expected SAT: same CIDR means 100% overlap"
        assert model is not None

    def test_non_overlapping_cidrs_give_unsat(self) -> None:
        from scenarios.scenario_3 import run_named_subnet_isolation

        result, _ = run_named_subnet_isolation("192.168.0.0/24", "192.168.1.0/24")
        assert result == "UNSAT"

    def test_supernet_and_subnet_overlap(self) -> None:
        """10.0.0.0/16 contains 10.0.0.0/24, so overlap exists → SAT."""
        from scenarios.scenario_3 import run_named_subnet_isolation

        result, model = run_named_subnet_isolation("10.0.0.0/16", "10.0.0.0/24")
        assert result == "SAT"


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 4 – Unrestricted egress
# ─────────────────────────────────────────────────────────────────────────────

class TestScenario4:
    def test_unrestricted_egress_is_sat(self, infra: dict) -> None:
        """All-traffic egress + IGW route → SAT (data exfiltration possible)."""
        from scenarios.scenario_4 import run_egress_check

        result, model = run_egress_check(infra)
        assert result == "SAT", "Expected SAT: unrestricted egress is present"
        assert model is not None


# ─────────────────────────────────────────────────────────────────────────────
# Scenario 5 – After security hardening
# ─────────────────────────────────────────────────────────────────────────────

class TestScenario5:
    def test_fixed_ssh_is_unsat(self) -> None:
        """SSH ingress restricted to VPC CIDR → UNSAT (internet blocked)."""
        from scenarios.scenario_5 import run_fixed_ssh_check

        result, model = run_fixed_ssh_check()
        assert result == "UNSAT", "Expected UNSAT: SSH now restricted to VPC CIDR"
        assert model is None

    def test_fixed_egress_is_unsat(self) -> None:
        """Egress restricted to port 443 → UNSAT (no arbitrary port exfiltration)."""
        from scenarios.scenario_5 import run_fixed_egress_check

        result, model = run_fixed_egress_check()
        assert result == "UNSAT", "Expected UNSAT: egress restricted to port 443"
        assert model is None

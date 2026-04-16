"""
test_parser.py – Unit tests for the parser package.

Tests cover:
* :func:`~parser.extractor.cidr_to_network_mask`
* :func:`~parser.extractor.extract_security_group_rules`
* :func:`~parser.extractor.extract_route_table`
* :func:`~parser.parser.parse_infrastructure`
* :func:`~parser.parser.load_and_parse` (against ``sample_plan.json``)
"""

from __future__ import annotations

import json
import os
import pytest

from parser.extractor import (
    cidr_to_network_mask,
    extract_route_table,
    extract_security_group_rules,
)
from parser.parser import load_and_parse, parse_infrastructure

# ── Path to the bundled sample plan ──────────────────────────────────────────
SAMPLE_PLAN_PATH = os.path.join(os.path.dirname(__file__), "sample_plan.json")


# ─────────────────────────────────────────────────────────────────────────────
# cidr_to_network_mask
# ─────────────────────────────────────────────────────────────────────────────

class TestCidrToNetworkMask:
    def test_slash_24(self) -> None:
        net, mask = cidr_to_network_mask("10.0.0.0/24")
        # 10.0.0.0 = 0x0A000000
        assert net == 0x0A000000
        # 255.255.255.0 = 0xFFFFFF00
        assert mask == 0xFFFFFF00

    def test_slash_16(self) -> None:
        net, mask = cidr_to_network_mask("10.0.0.0/16")
        assert net == 0x0A000000
        # 255.255.0.0 = 0xFFFF0000
        assert mask == 0xFFFF0000

    def test_slash_0(self) -> None:
        net, mask = cidr_to_network_mask("0.0.0.0/0")
        assert net == 0
        assert mask == 0

    def test_slash_32(self) -> None:
        net, mask = cidr_to_network_mask("192.168.1.1/32")
        # 192.168.1.1 = 0xC0A80101
        assert net == 0xC0A80101
        assert mask == 0xFFFFFFFF

    def test_returns_tuple_of_ints(self) -> None:
        result = cidr_to_network_mask("172.16.0.0/12")
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert all(isinstance(v, int) for v in result)

    def test_second_subnet(self) -> None:
        net, mask = cidr_to_network_mask("10.0.1.0/24")
        # 10.0.1.0 = 0x0A000100
        assert net == 0x0A000100
        assert mask == 0xFFFFFF00


# ─────────────────────────────────────────────────────────────────────────────
# extract_security_group_rules
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractSecurityGroupRules:
    def _sample_sg(self) -> dict:
        return {
            "name": "ec2-sg",
            "ingress": [
                {
                    "from_port": 22,
                    "to_port": 22,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": [],
                    "security_groups": [],
                },
                {
                    "from_port": 80,
                    "to_port": 80,
                    "protocol": "tcp",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": [],
                    "security_groups": [],
                },
            ],
            "egress": [
                {
                    "from_port": 0,
                    "to_port": 0,
                    "protocol": "-1",
                    "cidr_blocks": ["0.0.0.0/0"],
                    "ipv6_cidr_blocks": [],
                    "security_groups": [],
                }
            ],
        }

    def test_returns_list(self) -> None:
        rules = extract_security_group_rules(self._sample_sg())
        assert isinstance(rules, list)

    def test_correct_total_count(self) -> None:
        rules = extract_security_group_rules(self._sample_sg())
        # 2 ingress + 1 egress
        assert len(rules) == 3

    def test_directions(self) -> None:
        rules = extract_security_group_rules(self._sample_sg())
        ingress = [r for r in rules if r["direction"] == "ingress"]
        egress = [r for r in rules if r["direction"] == "egress"]
        assert len(ingress) == 2
        assert len(egress) == 1

    def test_ssh_rule_fields(self) -> None:
        rules = extract_security_group_rules(self._sample_sg())
        ssh = next(r for r in rules if r["from_port"] == 22)
        assert ssh["to_port"] == 22
        assert ssh["protocol"] == "tcp"
        assert "0.0.0.0/0" in ssh["cidr_blocks"]

    def test_egress_all_traffic(self) -> None:
        rules = extract_security_group_rules(self._sample_sg())
        egress = next(r for r in rules if r["direction"] == "egress")
        assert egress["protocol"] == "-1"
        assert egress["from_port"] == 0

    def test_empty_sg(self) -> None:
        rules = extract_security_group_rules({})
        assert rules == []

    def test_none_rules(self) -> None:
        rules = extract_security_group_rules({"ingress": None, "egress": None})
        assert rules == []


# ─────────────────────────────────────────────────────────────────────────────
# extract_route_table
# ─────────────────────────────────────────────────────────────────────────────

class TestExtractRouteTable:
    def _sample_rt(self) -> dict:
        return {
            "name": "public_rt",
            "route": [
                {
                    "cidr_block": "0.0.0.0/0",
                    "gateway_id": "igw-0123456789abcdef0",
                    "nat_gateway_id": "",
                    "instance_id": "",
                }
            ],
        }

    def test_returns_list(self) -> None:
        routes = extract_route_table(self._sample_rt())
        assert isinstance(routes, list)

    def test_route_count(self) -> None:
        routes = extract_route_table(self._sample_rt())
        assert len(routes) == 1

    def test_destination_cidr(self) -> None:
        routes = extract_route_table(self._sample_rt())
        assert routes[0]["destination_cidr"] == "0.0.0.0/0"

    def test_gateway_id(self) -> None:
        routes = extract_route_table(self._sample_rt())
        assert routes[0]["gateway_id"] == "igw-0123456789abcdef0"

    def test_empty_route_table(self) -> None:
        routes = extract_route_table({})
        assert routes == []

    def test_none_route_key(self) -> None:
        routes = extract_route_table({"route": None})
        assert routes == []


# ─────────────────────────────────────────────────────────────────────────────
# parse_infrastructure / load_and_parse
# ─────────────────────────────────────────────────────────────────────────────

class TestParseInfrastructure:
    def _plan_from_json(self) -> dict:
        with open(SAMPLE_PLAN_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def test_vpc_present(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert infra["vpc"] is not None

    def test_vpc_cidr(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert infra["vpc"]["cidr_block"] == "10.0.0.0/16"

    def test_two_subnets(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["subnets"]) == 4  # sub1, sub2 (public) + sub3, sub4 (private)

    def test_subnet_cidrs(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        cidrs = {s["cidr_block"] for s in infra["subnets"]}
        assert "10.0.0.0/24" in cidrs
        assert "10.0.1.0/24" in cidrs
        assert "10.0.2.0/24" in cidrs
        assert "10.0.3.0/24" in cidrs

    def test_security_groups(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["security_groups"]) == 4  # webSg, albSg, bastionSg, dbSg

    def test_route_table(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["route_tables"]) == 2  # public RT (IGW) + private RT (NAT GW)

    def test_ec2_instances(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["ec2_instances"]) == 5  # web1, web2, bastion, appserver, dbserver

    def test_igw_present(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["internet_gateways"]) == 1

    def test_alb_present(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["albs"]) == 1

    def test_s3_bucket(self) -> None:
        infra = parse_infrastructure(self._plan_from_json())
        assert len(infra["s3_buckets"]) == 3  # example, logs, backup

    def test_load_and_parse_matches(self) -> None:
        infra = load_and_parse(SAMPLE_PLAN_PATH)
        assert infra["vpc"]["cidr_block"] == "10.0.0.0/16"

    def test_missing_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_and_parse("/nonexistent/path/plan.json")

    def test_empty_plan_returns_empty_infra(self) -> None:
        infra = parse_infrastructure({})
        assert infra["vpc"] is None
        assert infra["subnets"] == []

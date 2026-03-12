"""
parser.py – Load and parse Terraform plan JSON into a structured infrastructure dict.

Supports both real ``terraform show -json`` output and the mock sample JSON at
``tests/sample_plan.json`` so that all scenarios can run without AWS credentials.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_plan(file_path: str) -> dict[str, Any]:
    """Load a Terraform plan JSON file from *file_path* and return the raw dict.

    Args:
        file_path: Absolute or relative path to a ``terraform show -json`` output file.

    Returns:
        The parsed JSON as a Python dictionary.

    Raises:
        FileNotFoundError: If *file_path* does not exist on disk.
        json.JSONDecodeError: If the file content is not valid JSON.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Terraform plan file not found: {file_path}")

    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _get_planned_resources(plan: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the flat list of resources from *plan*'s ``planned_values`` section.

    Args:
        plan: Raw terraform plan dictionary (output of :func:`load_plan`).

    Returns:
        List of resource dicts; empty list if the key path is absent.
    """
    try:
        return plan["planned_values"]["root_module"].get("resources", [])
    except (KeyError, TypeError):
        return []


def parse_infrastructure(plan: dict[str, Any]) -> dict[str, Any]:
    """Parse a Terraform plan dict into a structured infrastructure dictionary.

    Extracts every AWS resource type relevant to network security analysis:
    VPCs, subnets, security groups, route tables, EC2 instances, Internet
    Gateways, Application Load Balancers, and S3 buckets.

    The function merges ``name`` and ``address`` into every resource entry so
    that downstream callers can always identify resources by a stable key.

    Args:
        plan: Parsed terraform plan dictionary.  May come from :func:`load_plan`
              or from a hand-crafted mock dict for unit testing.

    Returns:
        A structured dict with the following top-level keys::

            {
                "vpc":               dict | None,
                "subnets":           list[dict],
                "security_groups":   list[dict],
                "route_tables":      list[dict],
                "ec2_instances":     list[dict],
                "internet_gateways": list[dict],
                "albs":              list[dict],
                "s3_buckets":        list[dict],
            }

        Each entry is the resource's ``values`` dict enriched with the
        top-level ``name`` and ``address`` fields.
    """
    resources = _get_planned_resources(plan)

    infra: dict[str, Any] = {
        "vpc": None,
        "subnets": [],
        "security_groups": [],
        "route_tables": [],
        "ec2_instances": [],
        "internet_gateways": [],
        "albs": [],
        "s3_buckets": [],
    }

    for resource in resources:
        rtype: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {}) or {}
        name: str = resource.get("name", "")
        address: str = resource.get("address", "")

        # Build the enriched entry once
        entry: dict[str, Any] = {"name": name, "address": address, **values}

        if rtype == "aws_vpc":
            infra["vpc"] = entry
        elif rtype == "aws_subnet":
            infra["subnets"].append(entry)
        elif rtype == "aws_security_group":
            infra["security_groups"].append(entry)
        elif rtype == "aws_route_table":
            infra["route_tables"].append(entry)
        elif rtype == "aws_instance":
            infra["ec2_instances"].append(entry)
        elif rtype == "aws_internet_gateway":
            infra["internet_gateways"].append(entry)
        elif rtype in ("aws_lb", "aws_alb"):
            infra["albs"].append(entry)
        elif rtype == "aws_s3_bucket":
            infra["s3_buckets"].append(entry)

    return infra


def load_and_parse(file_path: str) -> dict[str, Any]:
    """Convenience wrapper: load *file_path* and return the parsed infrastructure.

    Equivalent to ``parse_infrastructure(load_plan(file_path))``.

    Args:
        file_path: Path to a Terraform plan JSON file.

    Returns:
        Structured infrastructure dictionary (see :func:`parse_infrastructure`).
    """
    return parse_infrastructure(load_plan(file_path))

"""
parser package – Terraform plan JSON loading and infrastructure extraction.
"""

from parser.parser import (
    load_plan,
    parse_infrastructure,
    parse_tf_configuration,
    load_and_parse_auto,
    load_and_parse,
)
from parser.extractor import (
    cidr_to_network_mask,
    extract_security_group_rules,
    extract_route_table,
)

__all__ = [
    "load_plan",
    "parse_infrastructure",
    "parse_tf_configuration",
    "load_and_parse_auto",
    "load_and_parse",
    "cidr_to_network_mask",
    "extract_security_group_rules",
    "extract_route_table",
]

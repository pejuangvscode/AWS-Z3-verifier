"""
parser.py – Parse Terraform inputs into a structured infrastructure dict.

Supported sources:
1. Terraform plan JSON (``terraform show -json``)
2. Raw Terraform HCL files (``.tf``), either a single file or a directory

For HCL input, variable defaults (``var.*``) and common resource references
(``aws_x.y.id``) are resolved into concrete values so scenarios can be verified
without generating an intermediate JSON plan.
"""

from __future__ import annotations

import json
import importlib
import re
from pathlib import Path
from typing import Any


_INTERPOLATION_PATTERN = re.compile(r"\$\{\s*([^}]+)\s*\}")

_RESOURCE_ID_PREFIX: dict[str, str] = {
    "aws_vpc": "vpc",
    "aws_subnet": "subnet",
    "aws_security_group": "sg",
    "aws_route_table": "rtb",
    "aws_internet_gateway": "igw",
    "aws_nat_gateway": "nat",
    "aws_instance": "i",
    "aws_lb": "alb",
    "aws_alb": "alb",
    "aws_eip": "eipalloc",
}


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


def _discover_tf_files(tf_path: Path) -> list[Path]:
    """Return sorted Terraform ``.tf`` files for *tf_path*.

    If *tf_path* is a file, all ``.tf`` files in its parent directory are used
    so variable defaults and cross-file references are resolved consistently.
    """
    if not tf_path.exists():
        raise FileNotFoundError(f"Terraform path not found: {tf_path}")

    if tf_path.is_file():
        if tf_path.suffix.lower() != ".tf":
            raise ValueError(f"Expected a .tf file, got: {tf_path}")
        files = sorted(tf_path.parent.glob("*.tf"))
    else:
        files = sorted(tf_path.glob("*.tf"))

    if not files:
        raise ValueError(f"No .tf files found at: {tf_path}")

    return files


def _strip_line_comments(text: str) -> str:
    """Remove ``#`` and ``//`` line comments while preserving quoted strings."""
    stripped_lines: list[str] = []

    for line in text.splitlines():
        out_chars: list[str] = []
        in_string = False
        escaped = False
        i = 0

        while i < len(line):
            ch = line[i]

            if in_string:
                out_chars.append(ch)
                if escaped:
                    escaped = False
                elif ch == "\\":
                    escaped = True
                elif ch == '"':
                    in_string = False
                i += 1
                continue

            if ch == '"':
                in_string = True
                out_chars.append(ch)
                i += 1
                continue

            if ch == "#":
                break

            if ch == "/" and i + 1 < len(line) and line[i + 1] == "/":
                break

            out_chars.append(ch)
            i += 1

        stripped_lines.append("".join(out_chars))

    return "\n".join(stripped_lines)


def _find_matching_brace(text: str, open_brace_index: int) -> int:
    """Return index of matching closing brace for ``text[open_brace_index]``."""
    depth = 0
    in_string = False
    escaped = False

    for idx in range(open_brace_index, len(text)):
        ch = text[idx]

        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx

    raise ValueError("Unbalanced braces in Terraform source")


def _split_top_level_csv(text: str) -> list[str]:
    """Split comma-separated values while respecting nesting and quotes."""
    items: list[str] = []
    current: list[str] = []
    bracket_depth = 0
    paren_depth = 0
    brace_depth = 0
    in_string = False
    escaped = False

    for ch in text:
        if in_string:
            current.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            current.append(ch)
            continue

        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth -= 1
        elif ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1

        if ch == "," and bracket_depth == 0 and paren_depth == 0 and brace_depth == 0:
            item = "".join(current).strip()
            if item:
                items.append(item)
            current = []
            continue

        current.append(ch)

    tail = "".join(current).strip()
    if tail:
        items.append(tail)

    return items


def _parse_scalar_or_collection(raw_value: str) -> Any:
    """Parse a Terraform expression into basic Python primitives when possible."""
    value = raw_value.strip().rstrip(",")

    if value.startswith("[") and value.endswith("]"):
        inner = value[1:-1].strip()
        if not inner:
            return []
        return [_parse_scalar_or_collection(item) for item in _split_top_level_csv(inner)]

    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        return value[1:-1]

    lower = value.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False

    if re.fullmatch(r"-?\d+", value):
        return int(value)

    return value


def _read_assignment_value(block_body: str, start_idx: int) -> tuple[str, int]:
    """Read assignment value from *start_idx* until end of expression."""
    i = start_idx
    in_string = False
    escaped = False
    bracket_depth = 0
    paren_depth = 0
    brace_depth = 0

    while i < len(block_body):
        ch = block_body[i]

        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue

        if ch == '"':
            in_string = True
            i += 1
            continue

        if ch == "[":
            bracket_depth += 1
        elif ch == "]":
            bracket_depth -= 1
        elif ch == "(":
            paren_depth += 1
        elif ch == ")":
            paren_depth -= 1
        elif ch == "{":
            brace_depth += 1
        elif ch == "}":
            if brace_depth > 0:
                brace_depth -= 1
            else:
                break

        if ch == "\n" and bracket_depth == 0 and paren_depth == 0 and brace_depth == 0:
            break

        i += 1

    return block_body[start_idx:i].strip(), i


def _parse_hcl_block_body(block_body: str) -> dict[str, Any]:
    """Parse assignments and nested blocks from a Terraform block body."""
    result: dict[str, Any] = {}
    i = 0

    while i < len(block_body):
        while i < len(block_body) and block_body[i].isspace():
            i += 1
        if i >= len(block_body):
            break

        ident_match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", block_body[i:])
        if not ident_match:
            i += 1
            continue

        key = ident_match.group(0)
        i += len(key)

        while i < len(block_body) and block_body[i].isspace():
            i += 1

        if i < len(block_body) and block_body[i] == "=":
            i += 1
            while i < len(block_body) and block_body[i].isspace():
                i += 1
            raw_value, i = _read_assignment_value(block_body, i)
            result[key] = _parse_scalar_or_collection(raw_value)
            continue

        if i < len(block_body) and block_body[i] == "{":
            block_start = i
            block_end = _find_matching_brace(block_body, block_start)
            nested_raw = block_body[block_start + 1:block_end]
            nested = _parse_hcl_block_body(nested_raw)
            result.setdefault(key, []).append(nested)
            i = block_end + 1
            continue

        while i < len(block_body) and block_body[i] != "\n":
            i += 1

    return result


def _load_hcl_documents_fallback(tf_files: list[Path]) -> list[dict[str, Any]]:
    """Parse Terraform files without third-party dependencies.

    This parser handles the Terraform subset used by the current security
    verifier: variable defaults, resource attributes, and nested rule/route
    blocks.
    """
    documents: list[dict[str, Any]] = []

    for tf_file in tf_files:
        raw_text = tf_file.read_text(encoding="utf-8")
        text = _strip_line_comments(raw_text)

        doc: dict[str, Any] = {"variable": [], "resource": []}

        for var_match in re.finditer(r'(?m)^\s*variable\s+"([^"]+)"\s*\{', text):
            var_name = var_match.group(1)
            open_idx = var_match.end() - 1
            close_idx = _find_matching_brace(text, open_idx)
            body = text[open_idx + 1:close_idx]
            doc["variable"].append({var_name: _parse_hcl_block_body(body)})

        for res_match in re.finditer(
            r'(?m)^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{',
            text,
        ):
            rtype = res_match.group(1)
            rname = res_match.group(2)
            open_idx = res_match.end() - 1
            close_idx = _find_matching_brace(text, open_idx)
            body = text[open_idx + 1:close_idx]
            parsed_attrs = _parse_hcl_block_body(body)
            doc["resource"].append({rtype: {rname: parsed_attrs}})

        documents.append(doc)

    return documents


def _load_hcl_documents(tf_files: list[Path]) -> list[dict[str, Any]]:
    """Load Terraform HCL files.

    Uses ``python-hcl2`` when available; otherwise falls back to the built-in
    parser so .tf evaluation still works in minimal environments.
    """
    try:
        hcl2 = importlib.import_module("hcl2")
    except ModuleNotFoundError:
        return _load_hcl_documents_fallback(tf_files)

    documents: list[dict[str, Any]] = []
    for tf_file in tf_files:
        with open(tf_file, "r", encoding="utf-8") as fh:
            parsed = hcl2.load(fh)
            if isinstance(parsed, dict):
                documents.append(parsed)
    return documents


def _collect_variable_defaults(documents: list[dict[str, Any]]) -> dict[str, Any]:
    """Collect Terraform variable defaults from parsed HCL docs."""
    defaults: dict[str, Any] = {}

    for doc in documents:
        for var_block in doc.get("variable", []):
            if not isinstance(var_block, dict):
                continue

            for var_name, var_cfg in var_block.items():
                if isinstance(var_cfg, dict) and "default" in var_cfg:
                    defaults[var_name] = var_cfg["default"]

    return defaults


def _collect_resource_blocks(
    documents: list[dict[str, Any]],
) -> list[tuple[str, str, dict[str, Any]]]:
    """Flatten HCL ``resource`` blocks into ``(type, name, attrs)`` tuples."""
    blocks: list[tuple[str, str, dict[str, Any]]] = []

    for doc in documents:
        for resource_block in doc.get("resource", []):
            if not isinstance(resource_block, dict):
                continue

            for rtype, named_blocks in resource_block.items():
                if not isinstance(named_blocks, dict):
                    continue

                for rname, attrs in named_blocks.items():
                    if isinstance(attrs, dict):
                        blocks.append((rtype, rname, attrs))

    return blocks


def _synthetic_resource_id(
    rtype: str,
    rname: str,
    attrs: dict[str, Any],
) -> str:
    """Create deterministic synthetic IDs for Terraform resources.

    These IDs are sufficient for solver predicates that rely on string prefixes,
    such as ``igw-*`` and ``nat-*`` route target checks.
    """
    if rtype == "aws_s3_bucket":
        bucket_name = attrs.get("bucket")
        if isinstance(bucket_name, str) and bucket_name:
            return bucket_name
        return f"bucket-{rname}"

    prefix = _RESOURCE_ID_PREFIX.get(rtype, "res")
    return f"{prefix}-{rname}"


def _resolve_token(
    token: str,
    variables: dict[str, Any],
    resource_refs: dict[str, str],
) -> Any:
    """Resolve a single Terraform token (``var.x`` or ``aws_x.y.id``)."""
    token = token.strip()

    if token.startswith("var."):
        var_name = token.split(".", 1)[1]
        return variables.get(var_name, token)

    return resource_refs.get(token, token)


def _resolve_hcl_value(
    value: Any,
    variables: dict[str, Any],
    resource_refs: dict[str, str],
) -> Any:
    """Recursively resolve variables and interpolations in parsed HCL values."""
    if isinstance(value, dict):
        return {
            key: _resolve_hcl_value(sub_value, variables, resource_refs)
            for key, sub_value in value.items()
        }

    if isinstance(value, list):
        return [_resolve_hcl_value(v, variables, resource_refs) for v in value]

    if not isinstance(value, str):
        return value

    full_match = re.fullmatch(r"\$\{\s*([^}]+)\s*\}", value)
    if full_match:
        return _resolve_token(full_match.group(1), variables, resource_refs)

    direct = _resolve_token(value, variables, resource_refs)
    if direct != value:
        return direct

    if "${" in value:
        def _replace(match: re.Match[str]) -> str:
            resolved = _resolve_token(match.group(1), variables, resource_refs)
            return str(resolved)

        return _INTERPOLATION_PATTERN.sub(_replace, value)

    return value


def _ensure_list(value: Any) -> list[Any]:
    """Normalize Terraform block payload into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_resource_values(rtype: str, values: dict[str, Any]) -> dict[str, Any]:
    """Normalize resource values so downstream extraction is shape-stable."""
    normalized = dict(values)

    if rtype == "aws_security_group":
        normalized["ingress"] = _ensure_list(normalized.get("ingress"))
        normalized["egress"] = _ensure_list(normalized.get("egress"))

    if rtype == "aws_route_table":
        normalized["route"] = _ensure_list(normalized.get("route"))

    if rtype == "aws_instance":
        normalized["vpc_security_group_ids"] = _ensure_list(
            normalized.get("vpc_security_group_ids")
        )

    return normalized


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
        "albs": [],          # TAMBAHAN BARU
        "s3_buckets": [],    # TAMBAHAN BARU
    }
    for resource in resources:
        rtype: str = resource.get("type", "")
        values: dict[str, Any] = resource.get("values", {}) or {}
        name: str = resource.get("name", "")
        address: str = resource.get("address", "")

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


def parse_tf_configuration(tf_path: str) -> dict[str, Any]:
    """Parse Terraform ``.tf`` source directly into the infrastructure dict.

    This parser is intentionally lightweight and targets attributes needed by
    the security scenarios (VPC, subnets, SG rules, route tables, EC2, IGW,
    ALB, S3). It resolves:

    * ``var.<name>`` from variable defaults in ``*.tf`` files
    * common resource ID references (``aws_x.y.id``)

    Args:
        tf_path: Path to a Terraform ``.tf`` file or a directory containing
                 Terraform files.

    Returns:
        Structured infrastructure dictionary equivalent to :func:`parse_infrastructure`.
    """
    path = Path(tf_path)
    tf_files = _discover_tf_files(path)
    documents = _load_hcl_documents(tf_files)

    variable_defaults = _collect_variable_defaults(documents)
    resource_blocks = _collect_resource_blocks(documents)

    # Build synthetic reference map in a first pass so second-pass resolution
    # can substitute tokens like aws_internet_gateway.igw.id.
    resource_refs: dict[str, str] = {}
    for rtype, rname, attrs in resource_blocks:
        synthetic_id = _synthetic_resource_id(rtype, rname, attrs)
        resource_refs[f"{rtype}.{rname}.id"] = synthetic_id

    planned_resources: list[dict[str, Any]] = []
    for rtype, rname, attrs in resource_blocks:
        resolved_values = _resolve_hcl_value(attrs, variable_defaults, resource_refs)
        if not isinstance(resolved_values, dict):
            continue

        normalized_values = _normalize_resource_values(rtype, resolved_values)

        planned_resources.append(
            {
                "type": rtype,
                "name": rname,
                "address": f"{rtype}.{rname}",
                "values": normalized_values,
            }
        )

    synthetic_plan = {
        "planned_values": {
            "root_module": {
                "resources": planned_resources,
            }
        }
    }

    return parse_infrastructure(synthetic_plan)


def load_and_parse_auto(path: str) -> dict[str, Any]:
    """Load and parse Terraform input from either JSON plan or ``.tf`` source.

    Auto-detection rules:
    * ``.json`` file -> Terraform plan JSON parser
    * ``.tf`` file   -> HCL parser across all sibling ``.tf`` files
    * directory      -> HCL parser across all ``.tf`` files in that directory
    """
    input_path = Path(path)

    if not input_path.exists():
        raise FileNotFoundError(f"Terraform input not found: {path}")

    if input_path.is_dir() or input_path.suffix.lower() == ".tf":
        return parse_tf_configuration(path)

    return parse_infrastructure(load_plan(path))


def load_and_parse(file_path: str) -> dict[str, Any]:
    """Backward-compatible loader that now auto-detects JSON or HCL input.

    Args:
        file_path: Path to either:
            * Terraform plan JSON file, or
            * Terraform ``.tf`` file, or
            * Directory containing Terraform ``.tf`` files.

    Returns:
        Structured infrastructure dictionary.
    """
    return load_and_parse_auto(file_path)

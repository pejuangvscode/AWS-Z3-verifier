#!/usr/bin/env python3
"""
main.py – AWS Infrastructure Security Verifier using Z3 SMT Solver.

Run all five security scenarios against a Terraform plan JSON file and print a
summary table showing SAT (vulnerable) or UNSAT (safe) for each check.

Usage
-----
    python main.py [terraform_plan.json]

If no file path is given, the bundled ``tests/sample_plan.json`` is used so the
tool runs out-of-the-box without real AWS credentials.

Summary table format
--------------------
    [SCENARIO 1] Internet→EC2 SSH     : SAT VULNERABLE
    [SCENARIO 1] Internet→EC2 HTTP    : SAT VULNERABLE
    [SCENARIO 2] Bypass ALB           : UNSAT SAFE
    [SCENARIO 3] Subnet Isolation     : UNSAT SAFE
    [SCENARIO 4] Unrestricted Egress  : SAT VULNERABLE
    [SCENARIO 5] After Fix - SSH      : UNSAT SAFE
    [SCENARIO 5] After Fix - Egress   : UNSAT SAFE

    Setiap run otomatis menyimpan laporan ke:
    reports/main/report_1.txt
    reports/main/report_2.txt
"""

from __future__ import annotations
 
import argparse
import sys
from pathlib import Path
from typing import Any
 
from z3 import ModelRef
 
 
# ──────────────────────────────────────────────────────────────────────────────
# Output helpers
# ──────────────────────────────────────────────────────────────────────────────
 
def _verdict(result: str) -> str:
    return "VULNERABLE" if result == "SAT" else "SAFE"
 
 
def _print_row(label: str, result: str, model: ModelRef | None = None) -> None:
    """Print a single result row, optionally followed by the Z3 counterexample."""
    print(f"  {label:<40}: {result:<5} {_verdict(result)}")
    if model is not None:
        assignments = ", ".join(
            f"{d.name()}={model[d]}" for d in model.decls()
        )
        print(f"    └─ counterexample: [{assignments}]")
 
 
# ──────────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────────
 
def main() -> None:
    """Entry point: parse CLI args, run all scenarios, print + save summary."""
    arg_parser = argparse.ArgumentParser(
        description=(
            "AWS Infrastructure Security Verifier – "
            "uses Z3 SMT Solver to check Terraform plan JSON."
        )
    )
    arg_parser.add_argument(
        "plan_file",
        nargs="?",
        default=str(Path(__file__).parent / "tests" / "sample_plan.json"),
        help=(
            "Path to a 'terraform show -json' output file. "
            "Defaults to tests/sample_plan.json."
        ),
    )
    args = arg_parser.parse_args()
 
    plan_path = Path(args.plan_file)
    if not plan_path.exists():
        print(f"[ERROR] Plan file not found: {plan_path}", file=sys.stderr)
        sys.exit(1)
 
    print()
    print("=" * 65)
    print("  AWS Infrastructure Security Verifier (Z3 SMT)")
    print("=" * 65)
    print(f"  Plan: {plan_path.resolve()}")
    print("=" * 65)
 
    # ── Load infrastructure ──────────────────────────────────────────────────
    from parser.parser import load_and_parse
 
    try:
        infra = load_and_parse(str(plan_path))
    except Exception as exc:
        print(f"[ERROR] Failed to parse plan: {exc}", file=sys.stderr)
        sys.exit(1)
 
    print(
        f"\n  Resources parsed: "
        f"{len(infra.get('subnets', []))} subnets, "
        f"{len(infra.get('security_groups', []))} security groups, "
        f"{len(infra.get('route_tables', []))} route tables, "
        f"{len(infra.get('ec2_instances', []))} EC2 instances"
    )
    print()
 
    # ── Setup reporter ───────────────────────────────────────────────────────
    from report import Reporter
    rpt = Reporter("main")
 
    # ── Run scenarios ────────────────────────────────────────────────────────
    from scenarios.scenario_1 import run_http_reachability, run_ssh_reachability
    from scenarios.scenario_2 import run_bypass_alb_check
    from scenarios.scenario_3 import run_subnet_isolation_check
    from scenarios.scenario_4 import run_egress_check
    from scenarios.scenario_5 import run_fixed_egress_check, run_fixed_ssh_check
 
    results: list[tuple[str, str, ModelRef | None]] = []
 
    def run(label: str, fn: Any, *args_: Any) -> None:
        result, model = fn(*args_)
        results.append((label, result, model))
        rpt.add_result(label.strip(), result, model)
 
    run("[SCENARIO 1] Internet→EC2 SSH    ", run_ssh_reachability, infra)
    run("[SCENARIO 1] Internet→EC2 HTTP   ", run_http_reachability, infra)
    run("[SCENARIO 2] Bypass ALB          ", run_bypass_alb_check, infra)
    run("[SCENARIO 3] Subnet Isolation    ", run_subnet_isolation_check, infra)
    run("[SCENARIO 4] Unrestricted Egress ", run_egress_check, infra)
    run("[SCENARIO 5] After Fix - SSH     ", run_fixed_ssh_check)
    run("[SCENARIO 5] After Fix - Egress  ", run_fixed_egress_check)
 
    # ── Print summary table ──────────────────────────────────────────────────
    print("  SECURITY VERIFICATION RESULTS")
    print("  " + "-" * 63)
    for label, result, model in results:
        _print_row(label, result, model)
    print("  " + "-" * 63)
 
    vuln_count = sum(1 for _, r, _ in results if r == "SAT")
    safe_count = len(results) - vuln_count
    print(f"\n  Summary: {vuln_count} VULNERABLE  |  {safe_count} SAFE\n")
 
    # ── Save report ──────────────────────────────────────────────────────────
    rpt.save(extra_notes=f"Plan file: {plan_path.resolve()}")
 
    # Exit with non-zero code if any vulnerabilities found
    sys.exit(1 if vuln_count > 0 else 0)
 
 
if __name__ == "__main__":
    main()
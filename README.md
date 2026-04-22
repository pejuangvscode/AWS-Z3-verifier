# AWS Infrastructure Security Verifier (Z3 SMT)

A Python tool for **formal verification** of AWS network security properties
using the Z3 SMT Solver.

The current pipeline supports **direct evaluation from Terraform source files**
(without generating a JSON plan first), while still supporting Terraform JSON
plan input for backward compatibility.

---

## What This Tool Checks

The verifier models AWS networking behavior and checks the following properties:

1. Internet reachability to EC2 on SSH and HTTP
2. Direct EC2 access bypassing ALB
3. Subnet CIDR overlap (isolation)
4. Unrestricted egress / exfiltration path
5. Re-verification after hardening fixes

Each scenario returns:
- `SAT` (vulnerable): the unsafe path is possible
- `UNSAT` (safe): the unsafe path is not possible in the model

When `SAT`, the solver prints a concrete counterexample model.

---

## Input Modes (Auto-Detected)

The parser auto-detects the input type:

- **Terraform source directory** (recommended): `terraform/`
- **Single Terraform file**: `terraform/main.tf`
- **Terraform plan JSON** (optional compatibility): `plan.json`

### Direct `.tf` parsing behavior

When input is `.tf`:
- If a single `.tf` file is provided, all sibling `.tf` files in the same folder
  are loaded.
- Variable defaults (e.g. `var.cidr`) are resolved.
- Common resource references (e.g. `aws_internet_gateway.igw.id`) are resolved
  into deterministic values.
- If `python-hcl2` is available, it is used.
- If not available, a built-in fallback parser is used.

This means the main workflow no longer requires `terraform plan -json`.

---

## Project Structure

```text
final_project/
├── main.py
├── report.py
├── requirements.txt
├── README.md
├── parser/
│   ├── __init__.py
│   ├── parser.py
│   └── extractor.py
├── z3_engine/
│   ├── __init__.py
│   ├── models.py
│   ├── axioms.py
│   └── constraints.py
├── scenarios/
│   ├── __init__.py
│   ├── scenario_1.py
│   ├── scenario_2.py
│   ├── scenario_3.py
│   ├── scenario_4.py
│   └── scenario_5.py
├── terraform/
│   ├── provider.tf
│   ├── variables.tf
│   ├── main.tf
│   ├── private_network.tf
│   ├── sg_extra.tf
│   ├── extra_instances.tf
│   ├── userdata.sh
│   └── userdata1.sh
├── tests/
│   ├── sample_plan.json
│   ├── test_parser.py
│   ├── test_models.py
│   └── test_scenarios.py
└── output/
```

---

## Quick Start (Using venv)

### 1. Create and activate virtual environment

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Run verifier (direct Terraform source)

```bash
python main.py terraform
```

Or point to a single file (sibling `.tf` files are still included):

```bash
python main.py terraform/main.tf
```

### 4. Optional: run with Terraform JSON plan

```bash
python main.py tests/sample_plan.json
```

### 5. Run tests

```bash
python -m pytest tests -v
```

---

## Latest Verified Output (Direct `.tf` Input)

Run command:

```bash
python main.py terraform
```

Observed summary:

```text
Resources parsed: 4 subnets, 4 security groups, 2 route tables,
                  5 EC2 instances, 1 ALB, 3 S3 Buckets

[SCENARIO 1] Internet->EC2 SSH          : SAT   VULNERABLE
[SCENARIO 1] Internet->EC2 HTTP         : SAT   VULNERABLE
[SCENARIO 2] Bypass ALB                 : SAT   VULNERABLE
[SCENARIO 3] Subnet Isolation           : UNSAT SAFE
[SCENARIO 4] Unrestricted Egress        : SAT   VULNERABLE
[SCENARIO 5] After Fix - SSH            : UNSAT SAFE
[SCENARIO 5] After Fix - Egress         : UNSAT SAFE

Summary: 4 VULNERABLE | 3 SAFE
```

Report output is saved to:

- `output/main/report.txt`

---

## Formal Modeling Notes

- IPv4 addresses are modeled as 32-bit bit-vectors.
- Subnet membership uses:

```text
(ip & mask) == network
```

- Port checks are modeled as range constraints.
- AWS implicit behavior (default deny, route-based reachability) is encoded as
  axioms and constraints.

---

## Exit Code Behavior

- Exit code `0`: no vulnerability found
- Exit code `1`: at least one scenario returned `SAT` (vulnerable)

This behavior is intended for CI/CD gate integration.

---

## Dependencies

| Package | Purpose |
|---|---|
| `z3-solver` | SMT solving engine |
| `pytest` | Test runner |

---

## License

MIT

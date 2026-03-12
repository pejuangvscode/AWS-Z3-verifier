# AWS Infrastructure Security Verifier (Z3 SMT)

A Python tool that performs **formal security verification** of AWS infrastructure
by analysing Terraform plan JSON output with the **Z3 SMT Solver**.  Instead of
running live traffic or relying on heuristics, the tool encodes network security
properties as mathematical constraints and asks Z3 to either find a violating
example (SAT = vulnerable) or prove none exists (UNSAT = safe).

---

## Project Structure

```
final_project/
├── terraform/
│   ├── main.tf           # VPC, subnets, IGW, route table, SGs, EC2, ALB, S3
│   ├── variables.tf
│   └── outputs.tf
├── parser/
│   ├── __init__.py
│   ├── parser.py         # Load & parse terraform plan JSON → structured dict
│   └── extractor.py      # CIDR conversion, rule extraction helpers
├── z3_engine/
│   ├── __init__.py
│   ├── models.py         # BitVec IP / port primitives
│   ├── axioms.py         # AWS implicit security axioms
│   └── constraints.py    # Reachability / isolation / egress constraint builders
├── scenarios/
│   ├── __init__.py
│   ├── scenario_1.py     # Internet → EC2 on port 22 & 80
│   ├── scenario_2.py     # Direct EC2 access bypassing ALB
│   ├── scenario_3.py     # Subnet isolation (no CIDR overlap)
│   ├── scenario_4.py     # Unrestricted egress / data exfiltration
│   └── scenario_5.py     # Re-verify after applying security fixes
├── tests/
│   ├── __init__.py
│   ├── sample_plan.json  # Mock terraform plan (no AWS credentials needed)
│   ├── test_parser.py
│   ├── test_models.py
│   └── test_scenarios.py
├── main.py               # CLI entry point
├── requirements.txt
└── README.md
```

---

## Infrastructure Topology

| Resource | Details |
|---|---|
| VPC | `10.0.0.0/16` |
| Subnet sub1 | `10.0.0.0/24`  (public, us-east-1a) |
| Subnet sub2 | `10.0.1.0/24`  (public, us-east-1b) |
| Internet Gateway | Default route `0.0.0.0/0` → IGW |
| EC2 SG (baseline) | Ingress: TCP/22, TCP/80 from `0.0.0.0/0`; Egress: all |
| EC2 instances | 2 × t3.micro, one per subnet |
| ALB | Application Load Balancer across both subnets |
| S3 Bucket | `my-data-bucket-secure-demo` |

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run all scenarios against the bundled sample plan

```bash
python main.py
```

Or supply your own `terraform show -json` output:

```bash
terraform show -json tfplan.bin > plan.json
python main.py plan.json
```

### 3. Run individual scenarios

```bash
python scenarios/scenario_1.py          # SSH & HTTP reachability
python scenarios/scenario_2.py          # ALB bypass
python scenarios/scenario_3.py          # Subnet isolation
python scenarios/scenario_4.py          # Unrestricted egress
python scenarios/scenario_5.py          # Post-fix verification
```

### 4. Run the test suite

```bash
pytest tests/ -v
```

---

## Expected Output

```
=================================================================
  AWS Infrastructure Security Verifier (Z3 SMT)
=================================================================
  Plan: tests/sample_plan.json
=================================================================

  Resources parsed: 2 subnets, 2 security groups, 1 route tables, 2 EC2 instances

  SECURITY VERIFICATION RESULTS
  -----------------------------------------------------------------
  [SCENARIO 1] Internet→EC2 SSH     : SAT   VULNERABLE
  [SCENARIO 1] Internet→EC2 HTTP    : SAT   VULNERABLE
  [SCENARIO 2] Bypass ALB           : UNSAT SAFE
  [SCENARIO 3] Subnet Isolation     : UNSAT SAFE
  [SCENARIO 4] Unrestricted Egress  : SAT   VULNERABLE
  [SCENARIO 5] After Fix - SSH      : UNSAT SAFE
  [SCENARIO 5] After Fix - Egress   : UNSAT SAFE
  -----------------------------------------------------------------

  Summary: 3 VULNERABLE  |  4 SAFE
```

---

## How It Works

### Formal Model

IP addresses are encoded as **32-bit unsigned bit-vectors** (`z3.BitVec(32)`).
Subnet membership is the standard bit-masking predicate:

```
ip ∈ CIDR  ⟺  (ip & mask) == network_address
```

Port ranges use **16-bit unsigned bit-vectors** with unsigned comparison (`ULE`):

```
port ∈ [from, to]  ⟺  from ≤ port ≤ to
```

### AWS Axioms

| Axiom | Encoding |
|---|---|
| Default-deny | `BoolVal(False)` – no traffic without explicit allow |
| Public subnet | Route table has `0.0.0.0/0 → igw-*` |
| IGW reachability | Checked analytically as a precondition |

### Scenario Summary

| # | Check | Baseline | After Fix |
|---|---|---|---|
| 1 | Internet → EC2 SSH (port 22) | SAT | UNSAT |
| 1 | Internet → EC2 HTTP (port 80) | SAT | — |
| 2 | Direct access bypassing ALB | UNSAT | — |
| 3 | sub1 / sub2 CIDR overlap | UNSAT | — |
| 4 | Unrestricted egress / exfil | SAT | UNSAT |

### Recommended Fixes

**Scenario 1 – SSH exposure**
```hcl
ingress {
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["10.0.0.0/16"]  # VPC CIDR only, not 0.0.0.0/0
}
```

**Scenario 4 – Unrestricted egress**
```hcl
egress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]   # HTTPS only, not all-traffic
}
```

---

## Generating a Real Terraform Plan

```bash
cd terraform/
terraform init
terraform plan -out=tfplan.bin
terraform show -json tfplan.bin > ../tests/real_plan.json
cd ..
python main.py tests/real_plan.json
```

> **Note:** You need valid AWS credentials and an existing key pair; adjust
> `variables.tf` accordingly.

---

## Dependencies

| Package | Purpose |
|---|---|
| `z3-solver` | Z3 SMT theorem prover (Python bindings) |
| `pytest` | Test runner |

---

## License

MIT

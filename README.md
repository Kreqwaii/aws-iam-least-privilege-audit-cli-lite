# AWS IAM Policy & Least-Privilege Audit CLI (Lite)

Zero-dependency **Python 3.9+ stdlib** CLI for auditing **AWS IAM**, **Trust**, and **S3 Bucket Policy** JSON files against 13 least-privilege security rules, complete with security scoring (0–100) and **Text / JSON / Markdown** reports.

## Quick Start

```bash
# Clone or install locally
pip install -e .

# Audit a single policy file
python -m iam_audit.cli examples/sample_policy.json

# Generate a Markdown report and fail CI on CRITICAL findings
python -m iam_audit.cli examples/sample_policy.json --format markdown --fail-on CRITICAL

# Output JSON for automation pipelines
python -m iam_audit.cli examples/sample_policy.json --format json --min-score 80
```

## Audit Rules (Lite)

| Rule ID | Severity | Description |
| :--- | :--- | :--- |
| `IAM001` | CRITICAL | Wildcard `Action: *` (full administrative privileges) |
| `IAM002` | HIGH | Wildcard `Resource: *` on Allow statement |
| `IAM003` | CRITICAL | Wildcard `Principal: *` without restrictive `Condition` |
| `IAM004` | CRITICAL | `iam:PassRole` combined with compute/execution actions (privilege escalation) |
| `IAM005` | HIGH | `sts:AssumeRole` trust policy without `sts:ExternalId` or `aws:MultiFactorAuthPresent` |
| `IAM006` | HIGH | Public S3 access without `aws:SecureTransport: true` |
| `IAM007` | HIGH | Overly broad KMS permissions (`kms:*`, `kms:Decrypt`) on `Resource: *` |
| `IAM008` | HIGH | Overly broad SecretsManager permissions on `Resource: *` |
| `IAM009` | MEDIUM | Service-wide wildcard actions (e.g., `s3:*`, `iam:*`, `ec2:*`) |
| `IAM010` | MEDIUM | Use of `NotAction` or `NotResource` in Allow statements |
| `IAM011` | CRITICAL | IAM policy/credential mutation actions (`iam:CreatePolicyVersion`, `iam:AttachUserPolicy`, etc.) |
| `IAM012` | LOW | Sensitive action missing any `Condition` block |
| `IAM013` | MEDIUM | Federated `sts:AssumeRoleWithSAML` / `WebIdentity` with wildcard Principal |

## Lite vs Pro Studio

| Feature | Lite CLI (Open Source) | Pro Studio |
| :--- | :---: | :---: |
| 13 Core Least-Privilege Rules | Yes | Yes |
| Zero-Dependency Python 3.9+ Stdlib | Yes | Yes |
| Text / JSON / Markdown Reports | Yes | Yes |
| Live AWS Account & IAM Graph Scan | — | Yes |
| Terraform / CloudFormation / CDK Policy Extraction | — | Yes |
| Auto-Generated Least-Privilege Policy Diffs | — | Yes |
| Custom OPA / Rego & Compliance Packs (SOC2, ISO27001) | — | Yes |

Upgrade to **Pro Studio** or request custom AWS security automation: **[FunPay Pro Showcase](https://funpay.com/users/20096179/)**

## License

MIT

"""Least-privilege audit rules for AWS IAM, Trust, and S3 Bucket policies."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Set


@dataclass(frozen=True)
class RuleMeta:
    rule_id: str
    title: str
    severity: str
    description: str


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    statement_index: int
    sid: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


RULES: Dict[str, RuleMeta] = {
    "IAM001": RuleMeta(
        "IAM001",
        "Wildcard Action (*)",
        "CRITICAL",
        "Statement grants Action: '*' (full administrative privileges).",
    ),
    "IAM002": RuleMeta(
        "IAM002",
        "Wildcard Resource (*)",
        "HIGH",
        "Allow statement applies to Resource: '*' without scoping.",
    ),
    "IAM003": RuleMeta(
        "IAM003",
        "Wildcard Principal (*)",
        "CRITICAL",
        "Policy allows Principal: '*' without restrictive conditions.",
    ),
    "IAM004": RuleMeta(
        "IAM004",
        "iam:PassRole Privilege Escalation",
        "CRITICAL",
        "Combines iam:PassRole with compute/execution actions (ec2, lambda, ecs, glue, cloudformation).",
    ),
    "IAM005": RuleMeta(
        "IAM005",
        "sts:AssumeRole Without ExternalId or MFA",
        "HIGH",
        "Trust policy allows sts:AssumeRole without aws:MultiFactorAuthPresent or sts:ExternalId.",
    ),
    "IAM006": RuleMeta(
        "IAM006",
        "Public S3 Access Without SecureTransport",
        "HIGH",
        "S3 statement allows broad/public access without enforcing aws:SecureTransport = true.",
    ),
    "IAM007": RuleMeta(
        "IAM007",
        "Overly Broad KMS Permissions",
        "HIGH",
        "Grants kms:* or kms:Decrypt/Encrypt on Resource: '*'.",
    ),
    "IAM008": RuleMeta(
        "IAM008",
        "Overly Broad SecretsManager Permissions",
        "HIGH",
        "Grants secretsmanager:* or secretsmanager:GetSecretValue on Resource: '*'.",
    ),
    "IAM009": RuleMeta(
        "IAM009",
        "Service-Wide Wildcard Action",
        "MEDIUM",
        "Uses service-wide wildcard (e.g., s3:*, iam:*, ec2:*) instead of specific actions.",
    ),
    "IAM010": RuleMeta(
        "IAM010",
        "Use of NotAction or NotResource",
        "MEDIUM",
        "Allow statement uses NotAction or NotResource, which often grants unintended access.",
    ),
    "IAM011": RuleMeta(
        "IAM011",
        "IAM Policy Mutation / Escalation Action",
        "CRITICAL",
        "Grants iam:CreatePolicyVersion, iam:AttachUserPolicy, iam:PutUserPolicy, or iam:CreateAccessKey.",
    ),
    "IAM012": RuleMeta(
        "IAM012",
        "Missing Condition on Sensitive Action",
        "LOW",
        "Sensitive administrative or data-exfiltration action lacks any Condition block.",
    ),
    "IAM013": RuleMeta(
        "IAM013",
        "sts:AssumeRoleWithSAML / WebIdentity Broad Principal",
        "MEDIUM",
        "Federated AssumeRole statement uses wildcard or unscoped Principal.",
    ),
}

SEVERITY_WEIGHTS: Dict[str, int] = {
    "CRITICAL": 25,
    "HIGH": 15,
    "MEDIUM": 8,
    "LOW": 3,
}


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_actions(stmt: Dict[str, Any]) -> List[str]:
    return [str(a).strip() for a in _as_list(stmt.get("Action"))]


def _normalize_resources(stmt: Dict[str, Any]) -> List[str]:
    return [str(r).strip() for r in _as_list(stmt.get("Resource"))]


def _has_wildcard_principal(stmt: Dict[str, Any]) -> bool:
    principal = stmt.get("Principal")
    if principal == "*":
        return True
    if isinstance(principal, dict):
        for val in principal.values():
            if "*" in _as_list(val):
                return True
    return False


def _condition_has_key(condition: Any, target_key: str) -> bool:
    if not isinstance(condition, dict):
        return False
    target_lower = target_key.lower()
    for _, cond_map in condition.items():
        if isinstance(cond_map, dict):
            for k in cond_map.keys():
                if str(k).lower() == target_lower:
                    return True
    return False


def _condition_enforces_secure_transport(condition: Any) -> bool:
    if not isinstance(condition, dict):
        return False
    for op, cond_map in condition.items():
        if str(op).lower() in ("bool", "boolifexists") and isinstance(cond_map, dict):
            for k, v in cond_map.items():
                if str(k).lower() == "aws:securetransport":
                    vals = [str(x).lower() for x in _as_list(v)]
                    if "true" in vals:
                        return True
    return False


def audit_policy(policy: Dict[str, Any]) -> List[Finding]:
    """Audit a parsed AWS IAM / Trust / S3 Bucket Policy dict and return findings."""
    findings: List[Finding] = []
    statements = _as_list(policy.get("Statement"))

    escalation_compute_prefixes = (
        "ec2:runinstances",
        "lambda:createfunction",
        "lambda:updatefunctioncode",
        "ecs:registertaskdefinition",
        "ecs:runtask",
        "glue:createjob",
        "cloudformation:createstack",
    )
    iam_mutation_actions: Set[str] = {
        "iam:createpolicyversion",
        "iam:setdefaultpolicyversion",
        "iam:attachuserpolicy",
        "iam:attachrolepolicy",
        "iam:attachgrouppolicy",
        "iam:putuserpolicy",
        "iam:putrolepolicy",
        "iam:createaccesskey",
        "iam:updateloginprofile",
    }

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue
        effect = str(stmt.get("Effect", "")).strip().lower()
        if effect != "allow":
            continue

        sid = str(stmt.get("Sid", ""))
        actions = _normalize_actions(stmt)
        actions_lower = [a.lower() for a in actions]
        resources = _normalize_resources(stmt)
        condition = stmt.get("Condition")

        # IAM001: Action: *
        if "*" in actions:
            findings.append(
                Finding(
                    "IAM001",
                    RULES["IAM001"].severity,
                    RULES["IAM001"].title,
                    "Statement grants 'Action: *' (full admin access).",
                    idx,
                    sid,
                )
            )

        # IAM002: Resource: *
        if "*" in resources:
            findings.append(
                Finding(
                    "IAM002",
                    RULES["IAM002"].severity,
                    RULES["IAM002"].title,
                    "Allow statement uses 'Resource: *'. Scope to specific ARNs.",
                    idx,
                    sid,
                )
            )

        # IAM003: Principal: *
        if _has_wildcard_principal(stmt) and not condition:
            findings.append(
                Finding(
                    "IAM003",
                    RULES["IAM003"].severity,
                    RULES["IAM003"].title,
                    "Statement allows 'Principal: *' without any Condition.",
                    idx,
                    sid,
                )
            )

        # IAM004: iam:PassRole escalation combos
        has_passrole = any(a in ("iam:passrole", "iam:*", "*") for a in actions_lower)
        has_compute = any(
            a.startswith(escalation_compute_prefixes) or a in ("ec2:*", "lambda:*", "ecs:*", "*")
            for a in actions_lower
        )
        if has_passrole and has_compute:
            findings.append(
                Finding(
                    "IAM004",
                    RULES["IAM004"].severity,
                    RULES["IAM004"].title,
                    "Combines iam:PassRole with compute/execution actions, enabling privilege escalation.",
                    idx,
                    sid,
                )
            )

        # IAM005: sts:AssumeRole without ExternalId or MFA
        if "sts:assumerole" in actions_lower and "Principal" in stmt:
            has_mfa = _condition_has_key(condition, "aws:MultiFactorAuthPresent")
            has_ext = _condition_has_key(condition, "sts:ExternalId")
            if not (has_mfa or has_ext):
                findings.append(
                    Finding(
                        "IAM005",
                        RULES["IAM005"].severity,
                        RULES["IAM005"].title,
                        "Trust policy allows sts:AssumeRole without MFA or sts:ExternalId condition.",
                        idx,
                        sid,
                    )
                )

        # IAM006: Public S3 without SecureTransport
        is_s3_stmt = any(a.startswith("s3:") or a == "*" for a in actions_lower)
        if is_s3_stmt and _has_wildcard_principal(stmt) and not _condition_enforces_secure_transport(condition):
            findings.append(
                Finding(
                    "IAM006",
                    RULES["IAM006"].severity,
                    RULES["IAM006"].title,
                    "Public S3 statement lacks 'aws:SecureTransport: true' condition.",
                    idx,
                    sid,
                )
            )

        # IAM007: Overly broad KMS
        if any(a in ("kms:*", "kms:decrypt", "kms:encrypt", "kms:reencrypt*") for a in actions_lower) and "*" in resources:
            findings.append(
                Finding(
                    "IAM007",
                    RULES["IAM007"].severity,
                    RULES["IAM007"].title,
                    "Overly broad KMS permissions on 'Resource: *'.",
                    idx,
                    sid,
                )
            )

        # IAM008: Overly broad SecretsManager
        if any(a in ("secretsmanager:*", "secretsmanager:getsecretvalue") for a in actions_lower) and "*" in resources:
            findings.append(
                Finding(
                    "IAM008",
                    RULES["IAM008"].severity,
                    RULES["IAM008"].title,
                    "Overly broad SecretsManager permissions on 'Resource: *'.",
                    idx,
                    sid,
                )
            )

        # IAM009: Service-wide wildcard action (e.g., s3:*, iam:*)
        svc_wildcards = [a for a in actions_lower if a.endswith(":*") and a != "*"]
        if svc_wildcards:
            findings.append(
                Finding(
                    "IAM009",
                    RULES["IAM009"].severity,
                    RULES["IAM009"].title,
                    f"Service-wide wildcard action(s) used: {', '.join(svc_wildcards)}.",
                    idx,
                    sid,
                )
            )

        # IAM010: NotAction / NotResource
        if "NotAction" in stmt or "NotResource" in stmt:
            findings.append(
                Finding(
                    "IAM010",
                    RULES["IAM010"].severity,
                    RULES["IAM010"].title,
                    "Allow statement uses NotAction or NotResource.",
                    idx,
                    sid,
                )
            )

        # IAM011: IAM mutation / escalation actions
        found_mutations = [a for a in actions_lower if a in iam_mutation_actions]
        if found_mutations:
            findings.append(
                Finding(
                    "IAM011",
                    RULES["IAM011"].severity,
                    RULES["IAM011"].title,
                    f"Grants IAM policy/credential mutation action(s): {', '.join(found_mutations)}.",
                    idx,
                    sid,
                )
            )

        # IAM012: Missing Condition on sensitive action
        if not condition and any(
            a in ("iam:passrole", "sts:assumerole", "kms:decrypt", "secretsmanager:getsecretvalue")
            for a in actions_lower
        ):
            findings.append(
                Finding(
                    "IAM012",
                    RULES["IAM012"].severity,
                    RULES["IAM012"].title,
                    "Sensitive action lacks any Condition constraint.",
                    idx,
                    sid,
                )
            )

        # IAM013: Federated AssumeRole broad principal
        if any(a in ("sts:assumerolewithsaml", "sts:assumerolewithwebidentity") for a in actions_lower):
            if _has_wildcard_principal(stmt):
                findings.append(
                    Finding(
                        "IAM013",
                        RULES["IAM013"].severity,
                        RULES["IAM013"].title,
                        "Federated AssumeRole statement uses wildcard Principal.",
                        idx,
                        sid,
                    )
                )

    return findings


def calculate_score(findings: List[Finding]) -> int:
    """Calculate a 0-100 least-privilege security score (100 = no findings)."""
    penalty = sum(SEVERITY_WEIGHTS.get(f.severity, 5) for f in findings)
    return max(0, 100 - penalty)

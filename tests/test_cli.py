"""Unit tests for AWS IAM Policy & Least-Privilege Audit CLI (Lite)."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from iam_audit.cli import main
from iam_audit.rules import RULES, audit_policy, calculate_score


class TestIamAuditRules(unittest.TestCase):
    def test_rules_count_at_least_12(self) -> None:
        self.assertGreaterEqual(len(RULES), 12)

    def test_clean_least_privilege_policy_scores_100(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ScopedS3Read",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::my-bucket/prefix/*"],
                }
            ],
        }
        findings = audit_policy(policy)
        self.assertEqual(findings, [])
        self.assertEqual(calculate_score(findings), 100)

    def test_deny_statement_is_ignored(self) -> None:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                }
            ],
        }
        self.assertEqual(audit_policy(policy), [])

    def test_iam001_wildcard_action(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b/*"}]}
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM001", ids)

    def test_iam002_wildcard_resource(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM002", ids)

    def test_iam003_wildcard_principal_no_condition(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-east-1:123456789012:q",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM003", ids)

    def test_iam003_wildcard_principal_dict_aws(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "sqs:SendMessage",
                    "Resource": "arn:aws:sqs:us-east-1:123456789012:q",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM003", ids)

    def test_iam004_passrole_ec2_escalation(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "ec2:RunInstances"],
                    "Resource": "arn:aws:iam::123456789012:role/app",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM004", ids)

    def test_iam004_passrole_lambda_escalation(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "lambda:CreateFunction"],
                    "Resource": "arn:aws:iam::123456789012:role/app",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM004", ids)

    def test_iam005_assumerole_without_mfa_or_external_id(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "sts:AssumeRole",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM005", ids)

    def test_iam005_assumerole_with_external_id_passes(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "abc-123"}},
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertNotIn("IAM005", ids)

    def test_iam005_assumerole_with_mfa_passes(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertNotIn("IAM005", ids)

    def test_iam006_public_s3_without_secure_transport(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-bucket/*",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM006", ids)

    def test_iam006_public_s3_with_secure_transport_passes(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::public-bucket/*",
                    "Condition": {"Bool": {"aws:SecureTransport": "true"}},
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertNotIn("IAM006", ids)

    def test_iam007_broad_kms(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*"}]}
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM007", ids)

    def test_iam008_broad_secretsmanager(self) -> None:
        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM008", ids)

    def test_iam009_service_wildcard(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*"}]}
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM009", ids)

    def test_iam010_not_action(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "arn:aws:s3:::b/*"}]}
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM010", ids)

    def test_iam010_not_resource(self) -> None:
        policy = {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"}]}
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM010", ids)

    def test_iam011_iam_mutation_action(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "iam:AttachUserPolicy",
                    "Resource": "arn:aws:iam::123456789012:user/dev",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM011", ids)

    def test_iam012_missing_condition_on_sensitive_action(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Resource": "arn:aws:kms:us-east-1:123456789012:key/abc",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM012", ids)

    def test_iam013_federated_assumerole_wildcard_principal(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sts:AssumeRoleWithWebIdentity",
                }
            ]
        }
        ids = {f.rule_id for f in audit_policy(policy)}
        self.assertIn("IAM013", ids)

    def test_score_floor_is_zero(self) -> None:
        policy = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": ["*", "iam:PassRole", "ec2:RunInstances", "iam:CreatePolicyVersion"],
                    "Resource": "*",
                }
            ]
        }
        score = calculate_score(audit_policy(policy))
        self.assertEqual(score, 0)


class TestIamAuditCli(unittest.TestCase):
    def test_cli_json_output(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["examples/sample_policy.json", "--format", "json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(len(data), 1)
        self.assertLess(data[0]["score"], 100)

    def test_cli_markdown_output(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["examples/sample_policy.json", "--format", "markdown"])
        self.assertEqual(code, 0)
        self.assertIn("# AWS IAM Least-Privilege Audit Report (Lite)", buf.getvalue())

    def test_cli_fail_on_critical_returns_1(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["examples/sample_policy.json", "--fail-on", "CRITICAL"])
        self.assertEqual(code, 1)

    def test_cli_min_score_returns_1(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["examples/sample_policy.json", "--min-score", "95"])
        self.assertEqual(code, 1)

    def test_cli_directory_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "clean.json"
            p.write_text(
                json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/k"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main([tmp, "--min-score", "100"])
            self.assertEqual(code, 0)
            self.assertIn("Score: 100/100", buf.getvalue())

    def test_cli_missing_file_returns_2(self) -> None:
        code = main(["nonexistent_policy_12345.json"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()

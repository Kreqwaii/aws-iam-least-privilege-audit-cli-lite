"""AWS IAM Policy & Least-Privilege Audit CLI (Lite)."""

__version__ = "0.1.0"

from .rules import RULES, Finding, audit_policy, calculate_score

__all__ = ["RULES", "Finding", "audit_policy", "calculate_score", "__version__"]

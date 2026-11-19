"""CLI entrypoint for AWS IAM Policy & Least-Privilege Audit CLI (Lite)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from . import __version__
from .rules import Finding, audit_policy, calculate_score

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


def _collect_json_files(paths: List[str]) -> List[Path]:
    files: List[Path] = []
    for raw in paths:
        p = Path(raw)
        if p.is_file():
            files.append(p)
        elif p.is_dir():
            files.extend(sorted(p.rglob("*.json")))
        else:
            raise FileNotFoundError(f"Path not found: {raw}")
    return files


def audit_file(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or "Statement" not in data:
        raise ValueError(f"Invalid IAM policy JSON (missing 'Statement'): {path}")
    findings = audit_policy(data)
    score = calculate_score(findings)
    return {
        "file": str(path),
        "score": score,
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


def format_markdown(results: List[Dict[str, Any]]) -> str:
    lines = ["# AWS IAM Least-Privilege Audit Report (Lite)", ""]
    for res in results:
        lines.append(f"## `{res['file']}` — Score: **{res['score']}/100** ({res['finding_count']} findings)")
        lines.append("")
        if not res["findings"]:
            lines.append("No least-privilege violations detected.")
            lines.append("")
            continue
        lines.append("| Rule | Severity | Statement | Title | Details |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for f in res["findings"]:
            stmt_label = f"#{f['statement_index']}" + (f" ({f['sid']})" if f["sid"] else "")
            lines.append(
                f"| `{f['rule_id']}` | **{f['severity']}** | {stmt_label} | {f['title']} | {f['message']} |"
            )
        lines.append("")
    return "\n".join(lines)


def format_text(results: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    for res in results:
        lines.append(f"=== {res['file']} | Score: {res['score']}/100 | Findings: {res['finding_count']} ===")
        for f in res["findings"]:
            stmt_label = f"stmt#{f['statement_index']}" + (f"[{f['sid']}]" if f["sid"] else "")
            lines.append(f"  [{f['severity']}] {f['rule_id']} ({stmt_label}): {f['message']}")
        if not res["findings"]:
            lines.append("  [PASS] No least-privilege violations detected.")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="iam-audit",
        description="Zero-dependency AWS IAM, Trust & S3 Bucket Policy Least-Privilege Audit CLI (Lite).",
    )
    parser.add_argument("paths", nargs="+", help="Policy JSON file(s) or directory to scan.")
    parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help="Output format (default: text).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"],
        default="NONE",
        help="Exit with code 1 if any finding meets or exceeds this severity.",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Exit with code 1 if any policy scores below this threshold (0-100).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        files = _collect_json_files(args.paths)
        if not files:
            print("No JSON policy files found.", file=sys.stderr)
            return 2
        results = [audit_file(f) for f in files]
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "markdown":
        print(format_markdown(results))
    else:
        print(format_text(results))

    fail_threshold = SEVERITY_ORDER[args.fail_on]
    for res in results:
        if res["score"] < args.min_score:
            return 1
        if fail_threshold > 0:
            for f in res["findings"]:
                if SEVERITY_ORDER.get(f["severity"], 0) >= fail_threshold:
                    return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

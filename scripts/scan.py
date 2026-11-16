#!/usr/bin/env python3
"""Run available SAST tools and normalize findings to JSON.

Usage:
    python3 scan.py --path /path/to/project --json scan.json
    python3 scan.py --path . --tools bandit,semgrep,ruff --use-uvx

Tools are optional: missing tools are reported as "skipped" and do not fail
the audit. The script never writes to the audited project.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

import _common as common

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

BUILTIN_SEMGREP_CONFIG = (
    Path(__file__).resolve().parent.parent / "rules" / "security" / "semgrep_rules.yaml"
)


def map_bandit_severity(value: str | None) -> str:
    return {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }.get((value or "").upper(), "info")


def map_semgrep_severity(value: str | None) -> str:
    return {
        "CRITICAL": "critical",
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }.get((value or "").upper(), "info")


def map_ruff_severity(code: str | None) -> str:
    code = (code or "").upper()
    if code.startswith("S"):
        return "medium"
    if code.startswith(("F", "E", "W", "B", "C", "N")):
        return "low"
    return "info"


def _resolve_semgrep_config(config: str | None) -> str:
    if config:
        return config
    if BUILTIN_SEMGREP_CONFIG.exists():
        return str(BUILTIN_SEMGREP_CONFIG)
    return "p/python"


def first_cwe(metadata) -> str:
    if not isinstance(metadata, dict):
        return ""
    cwe = metadata.get("cwe")
    if isinstance(cwe, str):
        return cwe.split(":")[0].strip()
    if isinstance(cwe, list) and cwe:
        return str(cwe[0]).split(":")[0].strip()
    return ""


def run_bandit(root: Path, timeout: int, use_uvx: bool):
    prefix = common.tool_prefix("bandit", use_uvx)
    if not prefix:
        return None, {"status": "skipped", "reason": "bandit not found"}
    excludes = ",".join(str(root / name) for name in sorted(common.DEFAULT_EXCLUDES))
    cmd = prefix + ["-r", str(root), "-f", "json", "-q", "-x", excludes]
    code, out, err = common.run(cmd, timeout=timeout)
    payload = common.load_json(out)
    if payload is None:
        return None, {
            "status": "error",
            "exit_code": code,
            "reason": (err or out or "unparseable output")[:500],
        }
    findings = []
    for item in payload.get("results", []):
        findings.append(
            {
                "tool": "bandit",
                "rule": item.get("test_id", ""),
                "name": item.get("test_name", ""),
                "severity": map_bandit_severity(item.get("issue_severity")),
                "confidence": (item.get("issue_confidence") or "").lower(),
                "file": item.get("filename", ""),
                "line": int(item.get("line_number") or 0),
                "message": item.get("issue_text", ""),
                "cwe": "",
            }
        )
    return findings, {"status": "ok", "exit_code": code, "count": len(findings)}


def run_semgrep(root: Path, timeout: int, use_uvx: bool, config: str):
    prefix = common.tool_prefix("semgrep", use_uvx, python_version="3.12")
    if not prefix:
        return None, {"status": "skipped", "reason": "semgrep not found"}
    cmd = prefix + [
        "--json",
        "--quiet",
        "--config",
        config,
        "--timeout",
        str(max(30, timeout)),
        "--max-target-bytes",
        "2000000",
        str(root),
    ]
    code, out, err = common.run(cmd, timeout=timeout + 30)
    payload = common.load_json(out)
    if payload is None:
        return None, {
            "status": "error",
            "exit_code": code,
            "reason": (err or out or "unparseable output")[:500],
        }
    errors = payload.get("errors") or []
    if errors:
        messages = "; ".join(str(item.get("message", ""))[:200] for item in errors[:3])
        return None, {
            "status": "error",
            "exit_code": code,
            "reason": messages or "semgrep reported errors",
        }
    findings = []
    for item in payload.get("results", []):
        extra = item.get("extra") or {}
        start = item.get("start") or {}
        raw_rule = item.get("check_id", "")
        tail = raw_rule.rsplit(".", 1)[-1]
        rule_id = tail if tail.startswith(("pysec-", "pysec_")) else raw_rule
        findings.append(
            {
                "tool": "semgrep",
                "rule": rule_id,
                "name": rule_id,
                "severity": map_semgrep_severity(extra.get("severity")),
                "confidence": "medium",
                "file": item.get("path", ""),
                "line": int(start.get("line") or 0),
                "message": extra.get("message", ""),
                "cwe": first_cwe(extra.get("metadata")),
            }
        )
    status = "ok" if code in (0, 1) else "error"
    return findings, {
        "status": status,
        "exit_code": code,
        "count": len(findings),
        "reason": "" if status == "ok" else (err or "")[:500],
    }


def run_ruff(root: Path, timeout: int, use_uvx: bool):
    prefix = common.tool_prefix("ruff", use_uvx)
    if not prefix:
        return None, {"status": "skipped", "reason": "ruff not found"}
    cmd = prefix + ["check", "--output-format", "json", "--no-cache", str(root)]
    code, out, err = common.run(cmd, timeout=timeout)
    payload = common.load_json(out)
    if payload is None:
        return None, {
            "status": "error",
            "exit_code": code,
            "reason": (err or out or "unparseable output")[:500],
        }
    findings = []
    for item in payload:
        location = item.get("location") or {}
        findings.append(
            {
                "tool": "ruff",
                "rule": item.get("code") or "",
                "name": item.get("code") or "",
                "severity": map_ruff_severity(item.get("code")),
                "confidence": "medium",
                "file": item.get("filename", ""),
                "line": int(location.get("row") or 0),
                "message": item.get("message", ""),
                "cwe": "",
            }
        )
    return findings, {"status": "ok", "exit_code": code, "count": len(findings)}


def dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in findings:
        key = (item["tool"], item["rule"], item["file"], item["line"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    result.sort(
        key=lambda x: (
            SEVERITY_ORDER.get(x.get("severity", "info"), 9),
            x.get("file", ""),
            x.get("line", 0),
        )
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Python SAST tools and normalize output."
    )
    parser.add_argument("--path", default=".", help="project root (default: .)")
    parser.add_argument("--json", dest="json_out", help="write JSON to this file")
    parser.add_argument(
        "--tools",
        default="bandit,semgrep,ruff",
        help="comma separated: bandit,semgrep,ruff",
    )
    parser.add_argument(
        "--timeout", type=int, default=180, help="per-tool timeout seconds"
    )
    parser.add_argument(
        "--use-uvx", action="store_true", help="fall back to uvx <tool>"
    )
    parser.add_argument(
        "--semgrep-config",
        default=None,
        help=(
            "semgrep config; default: bundled rules/security/semgrep_rules.yaml "
            "(offline). Pass p/python to use the registry (needs network)."
        ),
    )
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    selected = {name.strip().lower() for name in args.tools.split(",") if name.strip()}
    tools_meta: dict[str, dict] = {}
    findings: list[dict] = []

    runners = {
        "bandit": lambda: run_bandit(root, args.timeout, args.use_uvx),
        "semgrep": lambda: run_semgrep(
            root,
            args.timeout,
            args.use_uvx,
            _resolve_semgrep_config(args.semgrep_config),
        ),
        "ruff": lambda: run_ruff(root, args.timeout, args.use_uvx),
    }

    for name, runner in runners.items():
        if name not in selected:
            tools_meta[name] = {"status": "disabled"}
            continue
        try:
            items, meta = runner()
        except Exception as exc:  # noqa: BLE001 - keep the audit running
            tools_meta[name] = {"status": "error", "reason": str(exc)[:500]}
            continue
        tools_meta[name] = meta
        if items:
            findings.extend(items)

    findings = dedupe(findings)
    by_severity = {level: 0 for level in SEVERITY_ORDER}
    by_tool: dict[str, int] = {}
    for item in findings:
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
        by_tool[item["tool"]] = by_tool.get(item["tool"], 0) + 1

    result = {
        "meta": {
            "root": str(root),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tools": tools_meta,
        },
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_tool": by_tool,
            "note": "Raw tool findings are leads, not confirmed vulnerabilities.",
        },
        "findings": findings,
    }
    common.dump(result, args.json_out)
    if args.json_out:
        print(f"wrote {args.json_out} ({len(findings)} findings)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Collect Python dependencies and check known vulnerabilities.

Usage:
    python3 check_deps.py --path . --json deps.json
    python3 check_deps.py --path . --online --json deps.json
    python3 check_deps.py --path . --offline --json deps.json

Default behavior:
- parse lock files and requirements files (always, offline)
- run pip-audit when available (network; disable with --offline)
- query OSV only when --online is passed

The script never upgrades packages and never writes to the audited project.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import _common as common
import tomllib

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
EXACT_RE = re.compile(r"===\s*([^\s,;]+)|==\s*([^\s,;]+)")


def parse_requirement_line(line: str) -> tuple[str, str] | None:
    raw = line.split("#", 1)[0].strip()
    if not raw or raw.startswith(("-", "git+", "http://", "https://")):
        return None
    raw = raw.split(";", 1)[0].strip()
    match = NAME_RE.match(raw)
    if not match:
        return None
    name = match.group(1)
    version = ""
    exact = EXACT_RE.search(raw)
    if exact:
        version = exact.group(1) or exact.group(2) or ""
    return name, version


def parse_requirements(path: Path) -> list[dict]:
    items: list[dict] = []
    for line in common.read_text(path).splitlines():
        parsed = parse_requirement_line(line)
        if parsed:
            name, version = parsed
            items.append({"name": name, "version": version, "source": path.name})
    return items


def parse_lock_toml(path: Path) -> list[dict]:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    items = []
    for pkg in data.get("package", []) or []:
        if isinstance(pkg, dict) and pkg.get("name"):
            items.append(
                {
                    "name": str(pkg["name"]),
                    "version": str(pkg.get("version", "")),
                    "source": path.name,
                }
            )
    return items


def parse_pipfile_lock(path: Path) -> list[dict]:
    payload = common.load_json(common.read_text(path))
    if not isinstance(payload, dict):
        return []
    items = []
    for section in ("default", "develop"):
        for name, meta in (payload.get(section) or {}).items():
            version = ""
            if isinstance(meta, dict):
                version = str(meta.get("version", "")).lstrip("=")
            items.append({"name": name, "version": version, "source": path.name})
    return items


def parse_pep508(value: str) -> tuple[str, str] | None:
    raw = value.strip()
    if not raw or raw.startswith(("-", "git+", "http://", "https://")):
        return None
    raw = raw.split(";", 1)[0].strip()
    match = NAME_RE.match(raw)
    if not match:
        return None
    name = match.group(1)
    version = ""
    exact = EXACT_RE.search(raw)
    if exact:
        version = exact.group(1) or exact.group(2) or ""
    return name, version


def parse_pyproject(path: Path) -> list[dict]:
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError):
        return []
    items: list[dict] = []

    project = data.get("project") or {}
    groups: list[list[str]] = []
    groups.append(project.get("dependencies") or [])
    for values in (project.get("optional-dependencies") or {}).values():
        groups.append(values or [])
    for values in (data.get("dependency-groups") or {}).values():
        groups.append(values or [])

    for group in groups:
        for value in group:
            if isinstance(value, str):
                parsed = parse_pep508(value)
                if parsed:
                    items.append(
                        {"name": parsed[0], "version": parsed[1], "source": path.name}
                    )

    poetry = (data.get("tool") or {}).get("poetry") or {}
    poetry_groups: list[dict] = [poetry.get("dependencies") or {}]
    for group in (poetry.get("group") or {}).values():
        if isinstance(group, dict):
            poetry_groups.append(group.get("dependencies") or {})
    for deps in poetry_groups:
        for name, spec in deps.items():
            if name.lower() == "python":
                continue
            version = ""
            if isinstance(spec, str):
                if spec.startswith("=="):
                    version = spec[2:].strip()
                elif re.fullmatch(r"\d+(\.\d+)*", spec):
                    version = spec
            elif isinstance(spec, dict):
                raw = str(spec.get("version", ""))
                if raw.startswith("=="):
                    version = raw[2:].strip()
            items.append({"name": name, "version": version, "source": path.name})
    return items


def collect_packages(root: Path) -> list[dict]:
    found: dict[tuple[str, str], dict] = {}
    excludes = common.DEFAULT_EXCLUDES

    for path in common.iter_files(root, exts={".txt"}, excludes=excludes):
        if path.name.startswith("requirements") or path.name == "constraints.txt":
            for item in parse_requirements(path):
                key = (item["name"].lower(), item["version"])
                found.setdefault(key, item)

    for name in ("poetry.lock", "uv.lock", "pdm.lock"):
        for path in root.rglob(name):
            if any(part in excludes for part in path.parts):
                continue
            for item in parse_lock_toml(path):
                key = (item["name"].lower(), item["version"])
                found.setdefault(key, item)

    for path in root.rglob("Pipfile.lock"):
        if any(part in excludes for part in path.parts):
            continue
        for item in parse_pipfile_lock(path):
            key = (item["name"].lower(), item["version"])
            found.setdefault(key, item)

    for path in root.rglob("pyproject.toml"):
        if any(part in excludes for part in path.parts):
            continue
        for item in parse_pyproject(path):
            key = (item["name"].lower(), item["version"])
            found.setdefault(key, item)

    return sorted(found.values(), key=lambda x: (x["name"].lower(), x["version"]))


def normalize_severity(value) -> str:
    text = str(value or "").upper()
    for level in ("CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"):
        if level in text:
            return "medium" if level == "MODERATE" else level.lower()
    return "unknown"


def run_pip_audit(root: Path, timeout: int, use_uvx: bool) -> tuple[list[dict], dict]:
    prefix = common.tool_prefix("pip-audit", use_uvx)
    if not prefix:
        return [], {"status": "skipped", "reason": "pip-audit not found"}

    req_files = [
        path
        for path in common.iter_files(
            root, exts={".txt"}, excludes=common.DEFAULT_EXCLUDES
        )
        if path.name.startswith("requirements")
    ]
    if not req_files:
        return [], {"status": "skipped", "reason": "no requirements*.txt"}

    findings: list[dict] = []
    errors: list[str] = []
    for path in req_files:
        base_cmd = prefix + ["-r", str(path), "-f", "json"]
        _code, out, err = common.run(
            base_cmd + ["--progress-spinner", "off"], cwd=root, timeout=timeout
        )
        payload = common.load_json(out)
        if payload is None:
            # older pip-audit versions do not support --progress-spinner
            _code, out, err = common.run(base_cmd, cwd=root, timeout=timeout)
            payload = common.load_json(out)
        if payload is None:
            errors.append(f"{path.name}: {(err or out)[:200]}")
            continue
        for dep in payload.get("dependencies", []) or []:
            name = dep.get("name", "")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []) or []:
                findings.append(
                    {
                        "package": name,
                        "version": version,
                        "id": vuln.get("id", ""),
                        "aliases": vuln.get("aliases", []) or [],
                        "severity": normalize_severity(
                            vuln.get("severity")
                            or (vuln.get("database_specific") or {}).get("severity")
                        ),
                        "summary": (vuln.get("description") or "")[:500],
                        "fixed_versions": vuln.get("fix_versions", []) or [],
                        "source": "pip-audit",
                    }
                )
    meta = {
        "status": "ok" if findings or not errors else "error",
        "files": len(req_files),
    }
    if errors:
        meta["errors"] = errors
    return findings, meta


def query_osv(packages: list[dict], timeout: int) -> tuple[list[dict], dict]:
    queries = []
    usable = []
    for pkg in packages:
        if not pkg.get("version"):
            continue
        usable.append(pkg)
        queries.append(
            {
                "package": {"name": pkg["name"], "ecosystem": "PyPI"},
                "version": pkg["version"],
            }
        )
    if not queries:
        return [], {"status": "skipped", "reason": "no pinned packages"}

    body = json.dumps({"queries": queries}).encode("utf-8")
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "python-security-audit-skill/1.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return [], {"status": "error", "reason": str(exc)[:300]}

    findings: list[dict] = []
    results = payload.get("results", []) or []
    for pkg, result in zip(usable, results):
        for vuln in result.get("vulns", []) or []:
            fixed = set()
            for affected in vuln.get("affected", []) or []:
                for rng in affected.get("ranges", []) or []:
                    for event in rng.get("events", []) or []:
                        if event.get("fixed"):
                            fixed.add(str(event["fixed"]))
            severity = normalize_severity(
                (vuln.get("database_specific") or {}).get("severity")
            )
            if severity == "unknown":
                for item in vuln.get("severity", []) or []:
                    if str(item.get("type", "")).startswith("CVSS"):
                        severity = "unknown"
                        break
            findings.append(
                {
                    "package": pkg["name"],
                    "version": pkg["version"],
                    "id": vuln.get("id", ""),
                    "aliases": vuln.get("aliases", []) or [],
                    "severity": severity,
                    "summary": (vuln.get("summary") or vuln.get("details") or "")[:500],
                    "fixed_versions": sorted(fixed),
                    "source": "osv",
                }
            )
    return findings, {"status": "ok", "queried": len(queries), "count": len(findings)}


def dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in findings:
        key = (item["package"].lower(), item["version"], item["id"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    result.sort(key=lambda x: (order.get(x["severity"], 9), x["package"].lower()))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Python dependency vulnerabilities."
    )
    parser.add_argument("--path", default=".", help="project root (default: .)")
    parser.add_argument("--json", dest="json_out", help="write JSON to this file")
    parser.add_argument(
        "--timeout", type=int, default=120, help="network/tool timeout seconds"
    )
    parser.add_argument("--offline", action="store_true", help="no network at all")
    parser.add_argument("--online", action="store_true", help="allow OSV API queries")
    parser.add_argument(
        "--use-uvx", action="store_true", help="fall back to uvx <tool>"
    )
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    packages = collect_packages(root)
    tools_meta: dict[str, dict] = {}
    findings: list[dict] = []

    if args.offline:
        tools_meta["pip-audit"] = {"status": "disabled", "reason": "--offline"}
        tools_meta["osv"] = {"status": "disabled", "reason": "--offline"}
    else:
        try:
            items, meta = run_pip_audit(root, args.timeout, args.use_uvx)
            findings.extend(items)
            tools_meta["pip-audit"] = meta
        except Exception as exc:  # noqa: BLE001 - keep the audit running
            tools_meta["pip-audit"] = {"status": "error", "reason": str(exc)[:300]}

        if args.online:
            try:
                items, meta = query_osv(packages, args.timeout)
                findings.extend(items)
                tools_meta["osv"] = meta
            except Exception as exc:  # noqa: BLE001 - keep the audit running
                tools_meta["osv"] = {"status": "error", "reason": str(exc)[:300]}
        else:
            tools_meta["osv"] = {
                "status": "skipped",
                "reason": "pass --online to query OSV",
            }

    findings = dedupe(findings)
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for item in findings:
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1

    result = {
        "meta": {
            "root": str(root),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "packages": len(packages),
            "offline": args.offline,
            "tools": tools_meta,
        },
        "summary": {
            "findings": len(findings),
            "by_severity": by_severity,
            "total_packages": len(packages),
        },
        "packages": packages,
        "findings": findings,
    }
    common.dump(result, args.json_out)
    if args.json_out:
        print(
            f"wrote {args.json_out} ({len(packages)} packages, {len(findings)} findings)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

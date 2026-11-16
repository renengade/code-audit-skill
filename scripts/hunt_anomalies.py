#!/usr/bin/env python3
"""Heuristic hunt for backdoors, obfuscation and suspicious behavior.

Usage:
    python3 hunt_anomalies.py --path . --json anomalies.json

This is a lead generator, not a verdict. Every hit needs human review.
The script reads files only and never executes project code.
"""

from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import _common as common

MAX_HITS_PER_RULE = 30

RULES = [
    {
        "id": "H001",
        "name": "dynamic-exec",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(r"\b(?:exec|eval|compile)\s*\("),
        "message": "动态执行，确认参数是否可控",
    },
    {
        "id": "H002",
        "name": "shell-exec",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"os\.system\s*\(|os\.popen\s*\(|os\.exec|subprocess\.(?:run|Popen|call)\s*\(.*shell\s*=\s*True"
        ),
        "message": "命令执行点，确认是否拼接外部输入",
    },
    {
        "id": "H003",
        "name": "deserialization",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"pickle\.loads?\s*\(|yaml\.load\s*\(|marshal\.loads\s*\(|dill\.load|joblib\.load|torch\.load"
        ),
        "message": "反序列化点，确认数据来源与签名",
    },
    {
        "id": "H004",
        "name": "decode-then-exec",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(
            r"(?:exec|eval)\s*\([^)]*(?:b64decode|decompress|fromhex|marshal|codecs\.decode)"
        ),
        "message": "解码/解压后执行，疑似混淆载荷",
    },
    {
        "id": "H005",
        "name": "reverse-shell-primitive",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(
            r"socket\.socket\s*\(|pty\.spawn\s*\(|dup2\s*\(|/dev/tcp/|nc\s+-e|bash\s+-i"
        ),
        "message": "疑似反弹 shell 原语，确认业务必要性",
    },
    {
        "id": "H006",
        "name": "hardcoded-url",
        "severity": "info",
        "confidence": "low",
        "pattern": re.compile(r"https?://[^\s\"'<>]{4,}"),
        "message": "硬编码 URL，确认是否可信且必要",
    },
    {
        "id": "H007",
        "name": "exfil-channel",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"api\.telegram\.org|discord(?:app)?\.com/api/webhooks|pastebin\.com|webhook\.site|ngrok\.io"
        ),
        "message": "常见外传通道，确认业务用途",
    },
    {
        "id": "H008",
        "name": "sensitive-path",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"\.ssh|id_rsa|\.aws/credentials|\.env\b|keyring|Login Data|Cookies"
        ),
        "message": "访问敏感路径，确认是否读取凭据",
    },
    {
        "id": "H009",
        "name": "env-dump",
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(r"os\.environ\.copy\s*\(|dict\s*\(\s*os\.environ\s*\)"),
        "message": "整体读取环境变量，确认是否外发",
    },
    {
        "id": "H010",
        "name": "persistence",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"atexit\.register|crontab|systemd|autostart|\.bashrc|\.profile|sitecustomize|usercustomize|\.pth\b"
        ),
        "message": "持久化迹象，确认是否为正常部署逻辑",
    },
    {
        "id": "H011",
        "name": "anti-analysis",
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(
            r"gettrace\s*\(|settrace\s*\(|setprofile\s*\(|ptrace|SANDBOX|virtualbox|qemu|VBOX"
        ),
        "message": "反分析迹象，确认是否检测调试/沙箱",
    },
    {
        "id": "H012",
        "name": "install-hook",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(r"cmdclass|dependency_links|postinstall|preinstall"),
        "message": "安装期执行钩子，需人工确认",
    },
    {
        "id": "H013",
        "name": "hex-obfuscation",
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(r"(?:\\x[0-9a-fA-F]{2}){10,}"),
        "message": "大量十六进制转义，疑似混淆",
    },
    {
        "id": "H014",
        "name": "chr-chain",
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(r"(?:chr\s*\([^)]*\)\s*\+?\s*){10,}"),
        "message": "chr() 拼接，疑似混淆字符串",
    },
    {
        "id": "H015",
        "name": "ci-injection",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(
            r"pull_request_target|curl\s+[^|\n]+\|\s*(?:ba)?sh|wget\s+[^|\n]+\|\s*(?:ba)?sh"
        ),
        "message": "CI/CD 命令执行或不可信检出，确认权限",
    },
    {
        "id": "H016",
        "name": "private-key",
        "severity": "critical",
        "confidence": "high",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "message": "私钥内容，立即确认并轮换",
        "secret": True,
    },
    {
        "id": "H017",
        "name": "aws-access-key",
        "severity": "high",
        "confidence": "medium",
        "pattern": re.compile(r"AKIA[0-9A-Z]{16}"),
        "message": "疑似 AWS Access Key",
        "secret": True,
    },
    {
        "id": "H018",
        "name": "embedded-credential",
        "severity": "medium",
        "confidence": "low",
        "pattern": re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"'][^\"']{12,}[\"']"
        ),
        "message": "疑似硬编码凭据，确认是否为占位符",
        "secret": True,
    },
    {
        "id": "H019",
        "name": "dynamic-import",
        "severity": "medium",
        "confidence": "medium",
        "pattern": re.compile(r"importlib\.import_module\s*\(|__import__\s*\("),
        "message": "动态导入，确认模块名是否可控",
    },
    {
        "id": "H020",
        "name": "base64-blob",
        "severity": "medium",
        "confidence": "low",
        "pattern": re.compile(r"[A-Za-z0-9+/]{80,}={0,2}"),
        "message": "长 base64 字符串，确认是否携带载荷",
        "entropy": True,
    },
]

SECRET_RULE_IDS = {rule["id"] for rule in RULES if rule.get("secret")}


def snippet_for(line: str, rule: dict) -> str:
    text = line.strip()
    if rule["id"] in SECRET_RULE_IDS:
        return text[:40] + " <REDACTED>"
    return text[:200]


def scan_text_file(path: Path, root: Path, findings: list[dict]) -> None:
    lines = common.read_text(path).splitlines()
    hits: dict[str, int] = {}
    for number, line in enumerate(lines, start=1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        for rule in RULES:
            if hits.get(rule["id"], 0) >= MAX_HITS_PER_RULE:
                continue
            if not rule["pattern"].search(line):
                continue
            if rule.get("entropy"):
                token = rule["pattern"].search(line).group(0)
                if common.shannon_entropy(token) < 4.5:
                    continue
            hits[rule["id"]] = hits.get(rule["id"], 0) + 1
            findings.append(
                {
                    "rule": rule["id"],
                    "name": rule["name"],
                    "severity": rule["severity"],
                    "confidence": rule["confidence"],
                    "file": common.rel(path, root),
                    "line": number,
                    "message": rule["message"],
                    "snippet": snippet_for(line, rule),
                }
            )


def scan_special_files(root: Path, findings: list[dict]) -> None:
    for path in common.iter_files(root, exts=common.BINARY_EXTS, max_size=10**9):
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        findings.append(
            {
                "rule": "H100",
                "name": "binary-artifact",
                "severity": "info",
                "confidence": "high",
                "file": common.rel(path, root),
                "line": 0,
                "message": f"二进制/编译产物，大小 {size} bytes；需确认来源与哈希",
                "snippet": "",
            }
        )

    hooks_dir = root / ".git" / "hooks"
    if hooks_dir.is_dir():
        for hook in sorted(hooks_dir.iterdir()):
            if hook.is_file() and not hook.name.endswith(".sample"):
                findings.append(
                    {
                        "rule": "H101",
                        "name": "git-hook",
                        "severity": "high",
                        "confidence": "medium",
                        "file": common.rel(hook, root),
                        "line": 0,
                        "message": "非样例 Git hook，确认是否被植入",
                        "snippet": "",
                    }
                )


def dedupe(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in findings:
        key = (item["rule"], item["file"], item["line"])
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    result.sort(key=lambda x: (order.get(x["severity"], 9), x["file"], x["line"]))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Hunt for backdoor and malware heuristics."
    )
    parser.add_argument("--path", default=".", help="project root (default: .)")
    parser.add_argument("--json", dest="json_out", help="write JSON to this file")
    parser.add_argument("--max-file-size", type=int, default=2_000_000)
    args = parser.parse_args()

    root = Path(args.path).expanduser().resolve()
    if not root.exists():
        print(f"error: path not found: {root}", file=sys.stderr)
        return 2

    findings: list[dict] = []
    scanned = 0
    for path in common.iter_files(root, excludes=common.DEFAULT_EXCLUDES):
        if not common.is_text_candidate(path):
            continue
        try:
            if path.stat().st_size > args.max_file_size:
                continue
        except OSError:
            continue
        scanned += 1
        scan_text_file(path, root, findings)

    scan_special_files(root, findings)
    findings = dedupe(findings)

    by_rule: dict[str, int] = {}
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        by_rule[item["rule"]] = by_rule.get(item["rule"], 0) + 1
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1

    result = {
        "meta": {
            "root": str(root),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "files_scanned": scanned,
            "note": "Heuristic leads only. Static analysis cannot prove absence of a backdoor.",
        },
        "summary": {
            "total": len(findings),
            "by_severity": by_severity,
            "by_rule": by_rule,
        },
        "findings": findings,
    }
    common.dump(result, args.json_out)
    if args.json_out:
        print(
            f"wrote {args.json_out} ({scanned} files, {len(findings)} leads)",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

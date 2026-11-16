"""Shared helpers for the Python security audit scripts.

Standard library only. Scripts must never write to the audited project.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
from collections import Counter
from pathlib import Path

DEFAULT_EXCLUDES = {
    ".git",
    ".hg",
    ".svn",
    "venv",
    ".venv",
    "env",
    ".env",
    "node_modules",
    "__pycache__",
    "build",
    "dist",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "site-packages",
    ".idea",
    ".vscode",
    ".eggs",
    "htmlcov",
}

TEXT_EXTS = {
    ".py",
    ".pyi",
    ".txt",
    ".md",
    ".rst",
    ".toml",
    ".cfg",
    ".ini",
    ".yaml",
    ".yml",
    ".json",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".conf",
    ".xml",
    ".html",
    ".jinja",
    ".j2",
    ".ipynb",
    ".lock",
    ".env",
    ".properties",
    ".sql",
}

TEXT_NAMES = {
    "Dockerfile",
    "Makefile",
    "Pipfile",
    "Procfile",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
}

BINARY_EXTS = {
    ".pyc",
    ".pyo",
    ".so",
    ".pyd",
    ".dll",
    ".exe",
    ".whl",
    ".egg",
    ".zip",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".bin",
    ".dat",
}


def iter_files(
    root: str | Path,
    exts: set[str] | None = None,
    excludes: set[str] | None = None,
    max_size: int = 2_000_000,
):
    """Yield regular files under root, skipping excluded dirs and symlinks."""
    root = Path(root).resolve()
    excludes = set(DEFAULT_EXCLUDES) | set(excludes or ())
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in excludes)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink():
                continue
            if exts is not None and path.suffix.lower() not in exts:
                continue
            try:
                if path.stat().st_size > max_size:
                    continue
            except OSError:
                continue
            yield path


def read_text(path: str | Path, max_bytes: int = 2_000_000) -> str:
    try:
        data = Path(path).read_bytes()[:max_bytes]
    except OSError:
        return ""
    if b"\x00" in data[:1024]:
        return ""
    return data.decode("utf-8", errors="replace")


def is_text_candidate(path: Path) -> bool:
    if path.name in TEXT_NAMES:
        return True
    if path.name.startswith(
        (".env", "Dockerfile", "Makefile", ".gitignore", ".dockerignore")
    ):
        return True
    return path.suffix.lower() in TEXT_EXTS


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def which(cmd: str) -> str | None:
    return shutil.which(cmd)


def run(
    cmd: list[str],
    cwd: str | Path | None = None,
    timeout: int = 180,
) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def load_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def dump(payload: dict, path: str | None = None) -> None:
    data = json.dumps(payload, ensure_ascii=False, indent=2)
    if path:
        Path(path).expanduser().write_text(data + "\n", encoding="utf-8")
    else:
        print(data)


def rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def tool_prefix(
    tool: str,
    use_uvx: bool,
    python_version: str | None = None,
) -> list[str] | None:
    """Return a command prefix for tool, or None when unavailable.

    python_version pins the uvx interpreter (some tools break on very new
    Python releases, e.g. semgrep's core binary under Python 3.15).
    """
    found = which(tool)
    if found:
        return [found]
    if use_uvx and which("uvx"):
        prefix = ["uvx"]
        if python_version:
            prefix += ["--python", python_version]
        prefix += [tool]
        return prefix
    return None

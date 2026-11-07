---
name: env-guard
description: Enforce project-local command execution for dependency, build, browser, and container tools.
license: MIT
metadata:
  short-description: Project-local command guard
---

# env-guard for OpenCode

Keep `engine/` in the project root. Before running a build, test, dependency, browser, or container command, pass it to `engine/guard.py` as separate arguments.

```bash
python engine/guard.py inspect -- npm ci
python engine/guard.py run -- python -m pytest tests
```

Deny blocked commands. Do not add a bypass variable.

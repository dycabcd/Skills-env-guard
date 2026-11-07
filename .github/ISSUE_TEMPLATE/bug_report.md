---
name: Bug report
about: Report a policy regression or an unexpected result
title: "[Bug]: "
labels: bug
assignees: ""
---

**Description**

A clear and concise description of the problem.

**Expected behavior**

What did you expect `env-guard` to do?

**Actual behavior**

What happened instead? Include the exit code and JSON output when available.

**Command inspected or executed**

```text
python engine/guard.py inspect -- <argv>
```

Replace `<argv>` with the command you validated. Do not include real secrets, tokens, or private data.

**Environment**

- OS:
- Python version:
- env-guard version or commit:
- Relevant policy override:

```toml
# Optional. Remove real hosts, credentials, and private network details.
```

**Additional context**

Add any other useful context. If there was an error, keep the original message.

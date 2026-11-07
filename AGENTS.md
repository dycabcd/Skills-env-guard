# env-guard agent rules

1. Use `engine/guard.py` as the single policy engine.
2. Treat `check` as read-only and `init` as the only initialization command.
3. Before an uncertain command, run `inspect -- <argv>`.
4. To execute a command, run `run -- <argv>`; never execute it directly.
5. Pass one command as separate arguments. Do not pass shell syntax, pipes, redirection, or command substitution.
6. Deny blocked operations. Do not create or use a bypass.
7. Keep all generated files and caches inside the project root.
8. Do not run global installs, system package managers, destructive commands, privileged commands, Docker mutations, or external transfer tools.
9. Never place secrets in command-line arguments.
10. If a needed command is blocked, stop and ask the user for an explicit policy exception.

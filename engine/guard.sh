#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python_bin="${ENVGUARD_PYTHON:-}"

if [ -z "${python_bin}" ]; then
  if [ -x "${script_dir}/../../.venv/bin/python" ]; then
    python_bin="${script_dir}/../../.venv/bin/python"
  elif command -v python3 >/dev/null 2>&1; then
    python_bin="python3"
  elif command -v python >/dev/null 2>&1; then
    python_bin="python"
  fi
fi

if [ -z "${python_bin}" ]; then
  echo "[env-guard:NOT_FOUND] Python 3 is required" >&2
  exit 12
fi

exec "${python_bin}" "${script_dir}/guard.py" "$@"

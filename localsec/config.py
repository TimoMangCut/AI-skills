from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "analysis": {
        "output_dir": "documents",
        "work_dir": ".localsec",
        "ignored_dirs": [
            ".git", ".hg", ".svn", "bin", "obj", "vendor", "node_modules",
            ".venv", "venv", "dist", "build", "coverage", "TestResults",
            ".idea", ".vscode", ".dart_tool", "Pods", ".gradle", "DerivedData",
            "AI-skills", ".agents", ".localsec", "documents",
        ],
        "max_file_bytes": 2_000_000,
        "max_lines_per_read": 180,
        "max_chars_per_read": 18_000,
        "max_dir_entries": 150,
        "max_dir_calls_per_skill": 15,
        "max_read_calls_per_skill": 25,
        "max_total_tool_calls_per_skill": 40,
        "max_model_turns_per_skill": 45,
        "max_evidence_context_records": 55,
        "max_evidence_excerpt_chars": 1800,
        "max_audit_excerpt_chars": 4500,
        "max_context_chars": 60_000,
        "audit_batch_size": 15,
        "max_audit_batches": 6,
        "max_claims_per_audit": 90,
        "validation_retries": 1,
    },
    "llm": {
        "base_url": "http://127.0.0.1:11434/v1",
        "model": "qwen2.5-coder:14b",
        "timeout_seconds": 180,
        "max_tokens": 7000,
        "temperature": 0.0,
        "allow_remote": False,
    },
}


def deep_merge(base: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
    result = dict(base)
    for key, value in user.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config(config_path: str | Path | None) -> dict[str, Any]:
    if not config_path:
        return DEFAULT_CONFIG
    path = Path(config_path).expanduser().resolve()
    if not path.is_file():
        return DEFAULT_CONFIG
    with path.open("rb") as handle:
        user = tomllib.load(handle)
    return deep_merge(DEFAULT_CONFIG, user)

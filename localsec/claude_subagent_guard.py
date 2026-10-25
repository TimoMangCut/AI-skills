from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

FORBIDDEN_BLINDED_PATH_FRAGMENTS = (
    ".localsec/runs",
    ".localsec\\runs",
    "documents/",
    "documents\\",
    "deep_trace_chain_analyst.json",
    "candidate_queue.json",
    "unified_surface_mapper.json",
    "intent_invariant_modeler.json",
    "cross_repo_and_arch_review.json",
    "coverage_and_evidence_auditor.json",
    "candidate_intake_planner.json",
    "analysis_evidence_gate.json",
    "workspace_state.json",
)

NATIVE_READ_OR_SEARCH_TOOLS = {
    "read",
    "grep",
    "glob",
    "ls",
    "view",
    "view_file",
    "grep_search",
    "find_by_name",
    "cat",
}

BLINDED_AGENT_IDENTIFIERS = {
    "blinded_counterevidence_challenger",
    "phase-2-blinded-counterevidence-challenger",
    "counterevidence_challenger",
}


def _is_blinded_context(payload: dict[str, Any]) -> bool:
    """Determine if the PreToolUse invocation is inside a context-blinded challenger session.
    Defaults to True (fail-closed) when invoked without an explicit non-blinded subagent identifier.
    """
    env_skill = (
        os.environ.get("LOCALSEC_ACTIVE_SKILL")
        or os.environ.get("CLAUDE_SUBAGENT_NAME")
        or os.environ.get("LOCALSEC_SUBAGENT")
        or ""
    ).strip().lower()
    if env_skill in BLINDED_AGENT_IDENTIFIERS or os.environ.get("LOCALSEC_BLINDED_CHALLENGER") == "1":
        return True

    raw_agent = str(
        payload.get("subagent_name")
        or payload.get("agent_name")
        or payload.get("subagent_type")
        or payload.get("skill")
        or payload.get("session_role")
        or ""
    ).strip().lower()

    if raw_agent:
        return raw_agent in BLINDED_AGENT_IDENTIFIERS or "blinded" in raw_agent or "challenger" in raw_agent

    # When Claude Code PreToolUse hook invokes this guard without subagent_name in payload,
    # treat as blinded if env is unset (fail-closed for PreToolUse subagent guard).
    if env_skill and env_skill not in BLINDED_AGENT_IDENTIFIERS:
        return False
    return True


def _extract_target_strings(tool_input: Any) -> list[str]:
    targets: list[str] = []
    if isinstance(tool_input, str):
        targets.append(tool_input)
    elif isinstance(tool_input, dict):
        for k in (
            "file_path",
            "path",
            "target_file",
            "AbsolutePath",
            "SearchPath",
            "DirectoryPath",
            "pattern",
            "command",
            "CommandLine",
            "cmd",
            "query",
        ):
            val = tool_input.get(k)
            if isinstance(val, str) and val.strip():
                targets.append(val.strip())
            elif isinstance(val, list):
                targets.extend(str(x).strip() for x in val if str(x).strip())
    return targets


def _references_forbidden_blinded_artifact(text: str) -> str | None:
    norm = text.replace("\\", "/").strip()
    norm_low = norm.lower()
    for frag in FORBIDDEN_BLINDED_PATH_FRAGMENTS:
        frag_norm = frag.replace("\\", "/").lower()
        if frag_norm in norm_low:
            return frag
    if re.search(r"(?:^|/|\s)documents(?:/|$|\s)", norm_low):
        return "documents/"
    if re.search(r"(?:^|/|\s)\.localsec/runs(?:/|$|\s)", norm_low):
        return ".localsec/runs/"
    return None


def evaluate_tool_use(payload: Any) -> dict[str, Any]:
    """Evaluate a Claude Code PreToolUse payload and return {'decision': 'approve'|'block', 'reason': ...}.
    Enforces ARCH-3E / R3-A7 Context-Blinded Challenger isolation fail-closed.
    """
    if not isinstance(payload, dict):
        return {
            "decision": "block",
            "reason": "Fail-closed: PreToolUse guard received non-object tool payload.",
        }

    tool_name = str(payload.get("tool_name") or payload.get("tool") or payload.get("name") or "").strip()
    tool_low = tool_name.lower()
    tool_input = (
        payload.get("tool_input")
        if "tool_input" in payload
        else (payload.get("input") if "input" in payload else payload.get("arguments", {}))
    )

    if not tool_name:
        return {
            "decision": "block",
            "reason": "Fail-closed: PreToolUse guard payload missing tool_name.",
        }

    is_blinded = _is_blinded_context(payload)
    targets = _extract_target_strings(tool_input)
    combined_blob = " ".join(targets)

    # Check if command itself invokes blinded_counterevidence_challenger
    if "blinded_counterevidence_challenger" in combined_blob.lower():
        is_blinded = True

    if not is_blinded:
        return {
            "decision": "approve",
            "reason": "Non-blinded subagent context.",
        }

    # Rule 1: In blinded context, ANY access to .localsec/runs/ or documents/ or unblinded JSON artifacts is strictly blocked.
    for t in targets:
        hit = _references_forbidden_blinded_artifact(t)
        if hit:
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (R3-A7): blinded_counterevidence_challenger is forbidden from accessing "
                    f"{hit!r} via {tool_name!r}. Read only .localsec/tmp/blinded_chains_<repo>.json and use "
                    f"`python -m localsec.manual_session read_file --skill blinded_counterevidence_challenger`."
                ),
            }

    # Rule 2: Native Read/Grep/Glob tools cannot be used to bypass ManualWorkspace read_file exact_paths enforcement,
    # except reading the prepared .localsec/tmp/blinded_chains_<repo>.json input file.
    if tool_low in NATIVE_READ_OR_SEARCH_TOOLS:
        if tool_low in {"grep", "glob", "grep_search", "find_by_name"}:
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (R3-A7): native search tool {tool_name!r} is blocked during "
                    f"blinded_counterevidence_challenger to enforce exact_paths allow-list and prevent unblinded artifact discovery."
                ),
            }
        # For Read / View: only allow .localsec/tmp/blinded_chains_*.json
        for t in targets:
            norm_t = t.replace("\\", "/")
            if ".localsec/tmp/blinded_chains_" in norm_t and norm_t.endswith(".json"):
                continue
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (R3-A7): native {tool_name!r} on {t!r} is blocked. "
                    f"blinded_counterevidence_challenger must read source files exclusively via "
                    f"`python -m localsec.manual_session read_file <repo> <path> --skill blinded_counterevidence_challenger`."
                ),
            }

    # Rule 3: For Bash / run_command in blinded context, only allow localsec.manual_session commands
    # with --skill blinded_counterevidence_challenger (or write_output / prepare_blinded_chain_verifier)
    if tool_low in {"bash", "run_command", "sh", "zsh"}:
        cmd_str = combined_blob.strip()
        if not cmd_str:
            return {
                "decision": "block",
                "reason": "Fail-closed: empty Bash command in blinded_counterevidence_challenger.",
            }
        hit = _references_forbidden_blinded_artifact(cmd_str)
        if hit:
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (R3-A7): Bash command references forbidden unblinded path {hit!r} "
                    f"during blinded_counterevidence_challenger."
                ),
            }
        if "localsec.manual_session" in cmd_str and "read_file" in cmd_str:
            if "blinded_counterevidence_challenger" not in cmd_str:
                return {
                    "decision": "block",
                    "reason": (
                        "Context-Blinded Violation (R3-A7): manual_session read_file in blinded challenger must pass "
                        "`--skill blinded_counterevidence_challenger` so exact_paths enforcement is active."
                    ),
                }

    return {
        "decision": "approve",
        "reason": "Permitted under blinded_counterevidence_challenger guard policy.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m localsec.claude_subagent_guard",
        description="Claude Code PreToolUse hook guard enforcing Context-Blinded Challenger isolation (R3-A7).",
    )
    parser.add_argument(
        "--payload",
        default=None,
        help="Optional JSON string or path to JSON file (defaults to reading stdin).",
    )
    args = parser.parse_args(argv)

    raw_text = ""
    try:
        if args.payload is not None:
            cand_path = Path(args.payload)
            if cand_path.is_file():
                raw_text = cand_path.read_text(encoding="utf-8", errors="replace")
            else:
                raw_text = str(args.payload)
        else:
            if not sys.stdin.isatty():
                raw_text = sys.stdin.read()
    except Exception as exc:
        out = {"decision": "block", "reason": f"Fail-closed: error reading PreToolUse input ({type(exc).__name__})."}
        print(json.dumps(out, ensure_ascii=False))
        return 2

    if not raw_text.strip():
        out = {"decision": "block", "reason": "Fail-closed: empty PreToolUse hook input."}
        print(json.dumps(out, ensure_ascii=False))
        return 2

    try:
        payload = json.loads(raw_text)
    except Exception as exc:
        out = {"decision": "block", "reason": f"Fail-closed: invalid JSON in PreToolUse hook input ({type(exc).__name__})."}
        print(json.dumps(out, ensure_ascii=False))
        return 2

    verdict = evaluate_tool_use(payload)
    print(json.dumps(verdict, ensure_ascii=False))
    return 0 if verdict.get("decision") == "approve" else 2


if __name__ == "__main__":
    raise SystemExit(main())

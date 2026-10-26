from __future__ import annotations

import argparse
import json
import os
import re
import shlex
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
    "phase3_verified_queue.json",
    "workspace_state.json",
    "evidence.json",
)

# Outputs of the non-blinded skills. Their drafts sit next to the blinded package as
# `.localsec/tmp/<skill>_<repo>.json` (CLAUDE.md, phase-*-orchestrator SKILL.md), so match by prefix, not exact name.
UNBLINDED_SKILL_NAMES = (
    "codebase_scout",
    "extractor_tailor",
    "unified_surface_mapper",
    "intent_invariant_modeler",
    "cross_repo_and_arch_review",
    "coverage_and_evidence_auditor",
    "coverage_ledger",
    "candidate_intake_planner",
    "deep_trace_chain_analyst",
    "analysis_evidence_gate",
    "actor_and_feasibility_assessor",
    "beyond_code_control_mapper",
    "sfop_risk_calibrator",
    "candidate_queue",
    "phase3_verified_queue",
    "workspace_state",
)
UNBLINDED_ARTIFACT_RE = re.compile(
    r"(?:^|[/\\\s])(?:" + "|".join(UNBLINDED_SKILL_NAMES) + r")(?:[_.][A-Za-z0-9_.-]*)?\.json\b",
    re.IGNORECASE,
)

NATIVE_SEARCH_TOOLS = {
    "grep",
    "glob",
    "ls",
    "grep_search",
    "find_by_name",
    "search",
    "find",
}

NATIVE_READ_TOOLS = {
    "read",
    "view",
    "view_file",
    "cat",
}

NATIVE_WRITE_TOOLS = {
    "write",
    "edit",
    "multiedit",
    "notebookedit",
    "write_to_file",
    "replace_file_content",
    "multi_replace_file_content",
}

NATIVE_SHELL_TOOLS = {
    "bash",
    "run_command",
    "sh",
    "zsh",
    "powershell",
    "pwsh",
    "cmd",
    "terminal",
}

BLINDED_AGENT_IDENTIFIERS = {
    "localsec-blinded-challenger",
    "blinded_counterevidence_challenger",
    "phase-2-blinded-counterevidence-challenger",
    "counterevidence_challenger",
    "blinded_challenger",
}

TOOLKIT_ROOT = Path(__file__).resolve().parents[1]

# Antigravity: hooks live in the workspace-wide `.agents/hooks.json` and the payload does not say which agent is
# running, so the guard decides from the start of the conversation transcript. The blinded conversation starts either
# from the custom subagent `.agents/agents/localsec-blinded-challenger.md` (whose prompt carries this sentinel) or from
# a user message that opens with the 2.3 slash command. Skill bodies are not in the transcript head, so the parent
# session that merely mentions the skill is not caught.
ANTIGRAVITY_SENTINEL = "LOCALSEC_BLINDED_CHALLENGER_CONTEXT"
ANTIGRAVITY_SLASH = "/phase-2-blinded-counterevidence-challenger"
ANTIGRAVITY_HEAD_RECORDS = 6

# The challenger's own drafts under .localsec/tmp/ (never other skills' drafts)
BLINDED_DRAFT_NAME = r"(?:draft_2_3[A-Za-z0-9_.-]*|blinded_counterevidence_challenger_[A-Za-z0-9_.-]+)\.json"

# Strict whitelist regex for .localsec/tmp Read in blinded challenger mode:
# the blinded package from prepare_blinded_chain_verifier plus the challenger's own drafts.
WHITELIST_TMP_JSON_RE = re.compile(
    r"(?:^|/)\.localsec/tmp/(?:blinded_chains_[A-Za-z0-9_.-]+\.json|" + BLINDED_DRAFT_NAME + r")$"
)

# Strict whitelist regex for explicit toolkit-prefixed Read paths
WHITELIST_TOOLKIT_PREFIX_READ_RE = re.compile(
    r"(?:^|/)(?:"
    r"(?:AI-skills|localsec-antigravity-skills)/(?:schemas/v3/[A-Za-z0-9_.-]+\.json|contracts/[A-Za-z0-9_./-]+\.(?:json|md)|\.(?:agents|claude)/(?:skills|agents)/[A-Za-z0-9_./-]+\.md)$"
    r"|\.(?:agents|claude)/(?:skills|agents)/[A-Za-z0-9_./-]+\.md$"
    r")"
)

# Strict whitelist regex for Write/Edit in blinded challenger mode:
# Allows writing ONLY the challenger's own drafts (never `blinded_chains_*.json` or other skills' drafts)
WHITELIST_WRITE_TMP_RE = re.compile(r"(?:^|/)\.localsec/tmp/" + BLINDED_DRAFT_NAME + r"$")

# Strict whitelist regex for Bash/PowerShell in blinded challenger mode:
# Allows ONLY `python -m localsec.manual_session <read_file|show_evidence|submit_skill> ...`
# (list_evidence is excluded: it prints every evidence id with `read_by`, i.e. where the analyst looked)
WHITELIST_BASH_CMD_RE = re.compile(
    r"^(?:PYTHONPATH=[A-Za-z0-9_./:-]+\s+)?"
    r"(?:python(?:3(?:\.\d+)?)?|py)\s+-m\s+localsec\.manual_session\s+"
    r"(?P<subcmd>read_file|show_evidence|submit_skill)\b(?P<rest>.*)$"
)

# Shell metacharacters forbidden in blinded Bash/PowerShell commands
FORBIDDEN_SHELL_METACHARS_RE = re.compile(r"[|;&<>$`\n\r]")


def _is_blinded_context(payload: dict[str, Any], mode: str = "auto") -> bool:
    """Determine if the PreToolUse invocation is inside a context-blinded challenger session.
    - When invoked with `--mode blinded_challenger` (registered in `.claude/agents/localsec-blinded-challenger.md`),
      unconditionally returns True.
    - When invoked in `auto` mode without `--mode blinded_challenger`, returns True ONLY if the environment
      or payload explicitly identifies the blinded challenger subagent/skill (never blocks the main session
      when subagent_name is absent).
    """
    if str(mode or "").strip().lower() in {"blinded_challenger", "blinded", "force_blinded"}:
        return True

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
        or payload.get("agent")
        or payload.get("subagent_type")
        or payload.get("skill")
        or payload.get("session_role")
        or ""
    ).strip().lower()

    if raw_agent:
        return raw_agent in BLINDED_AGENT_IDENTIFIERS

    return False


def _strings(obj: Any, out: list[str], limit: int = 200) -> None:
    if len(out) >= limit:
        return
    if isinstance(obj, str):
        out.append(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            _strings(v, out, limit)
    elif isinstance(obj, list):
        for v in obj:
            _strings(v, out, limit)


def _antigravity_is_blinded(payload: dict[str, Any]) -> bool:
    """True when the transcript head shows this conversation is the 2.3 challenger (sentinel, or the slash command
    as the first user text). Unreadable transcript -> False: the hook runs for every conversation in the workspace,
    and failing closed there would block the whole pipeline."""
    tp = str(payload.get("transcriptPath") or payload.get("transcript_path") or "")
    if not tp:
        return False
    try:
        fp = Path(os.path.expanduser(tp))
        head: list[str] = []
        with fp.open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    head.append(line)
                if len(head) >= ANTIGRAVITY_HEAD_RECORDS:
                    break
    except OSError:
        return False
    for line in head:
        if ANTIGRAVITY_SENTINEL in line:
            return True
        try:
            rec = json.loads(line)
        except Exception:
            continue
        texts: list[str] = []
        _strings(rec, texts)
        if any(t.lstrip().startswith(ANTIGRAVITY_SLASH) for t in texts):
            return True
    return False


def _normalize_payload(payload: dict[str, Any], platform: str) -> tuple[dict[str, Any], str]:
    """Map an Antigravity PreToolUse payload ({toolCall: {name, args}, transcriptPath, ...}) onto the Claude shape."""
    tc = payload.get("toolCall")
    if platform == "antigravity" or isinstance(tc, dict):
        tc = tc if isinstance(tc, dict) else {}
        norm = {"tool_name": str(tc.get("name") or ""), "tool_input": tc.get("args") or {}}
        return norm, ("blinded_challenger" if _antigravity_is_blinded(payload) else "auto")
    return payload, ""


def _extract_target_strings(tool_input: Any) -> list[str]:
    targets: list[str] = []
    if isinstance(tool_input, str):
        targets.append(tool_input)
    elif isinstance(tool_input, dict):
        for k in (
            "file_path",
            "path",
            "target_file",
            "TargetFile",
            "AbsolutePath",
            "notebook_path",
            "SearchPath",
            "DirectoryPath",
            "pattern",
            "command",
            "CommandLine",
            "cmd",
            "script",
            "code",
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
    m = UNBLINDED_ARTIFACT_RE.search(norm)
    if m:
        return m.group(0).strip(" /\\")
    return None


def _split_cli_args(rest: str) -> list[str]:
    try:
        parts = shlex.split(rest, posix=False)
    except ValueError:
        return []
    return [p.strip("\"'") for p in parts]


def _option_values(args: list[str], name: str) -> list[str]:
    vals: list[str] = []
    for i, a in enumerate(args):
        if a == name and i + 1 < len(args):
            vals.append(args[i + 1])
        elif a.startswith(name + "="):
            vals.append(a.split("=", 1)[1])
    return vals


def _is_whitelisted_read_path(raw_path: str) -> bool:
    norm = raw_path.replace("\\", "/").strip()
    if not norm:
        return False
    parts = [p for p in norm.split("/") if p]
    if ".." in parts:
        return False
    if _references_forbidden_blinded_artifact(norm) is not None:
        return False

    # 1. Allow .localsec/tmp/*.json
    if WHITELIST_TMP_JSON_RE.search(norm):
        return True

    # 2. Allow explicit toolkit-prefixed read-only paths (AI-skills/..., .agents/skills/..., .claude/skills/...)
    if WHITELIST_TOOLKIT_PREFIX_READ_RE.search(norm):
        return True

    # 3. Allow bare relative toolkit paths (e.g. "schemas/v3/foo.schema.json" or "contracts/v3-orchestration.json")
    # ONLY when the path starts directly with schemas/v3/ or contracts/ (never "<repo>/contracts/...") AND exists inside TOOLKIT_ROOT!
    if re.match(r"^(?:schemas/v3/[A-Za-z0-9_.-]+\.json|contracts/[A-Za-z0-9_./-]+\.(?:json|md))$", norm):
        if (TOOLKIT_ROOT / norm).is_file():
            return True

    # 4. Allow absolute paths that resolve strictly inside TOOLKIT_ROOT's read-only skill/schema/contract directories
    try:
        cand = Path(raw_path).expanduser().resolve()
        allowed_roots = (
            TOOLKIT_ROOT / "schemas" / "v3",
            TOOLKIT_ROOT / "contracts",
            TOOLKIT_ROOT / ".agents" / "skills",
            TOOLKIT_ROOT / ".claude" / "skills",
            TOOLKIT_ROOT / ".claude" / "agents",
            TOOLKIT_ROOT / ".agents" / "agents",
        )
        if any(cand.is_relative_to(ar) for ar in allowed_roots) and cand.suffix.lower() in {".json", ".md"}:
            return True
    except Exception:
        pass

    return False


def _is_whitelisted_write_path(raw_path: str) -> bool:
    norm = raw_path.replace("\\", "/").strip()
    if not norm:
        return False
    parts = [p for p in norm.split("/") if p]
    if ".." in parts:
        return False
    if _references_forbidden_blinded_artifact(norm) is not None:
        return False
    return bool(WHITELIST_WRITE_TMP_RE.search(norm))


def evaluate_tool_use(payload: Any, *, mode: str = "auto") -> dict[str, Any]:
    """Evaluate a Claude Code PreToolUse payload and return {'decision': 'approve'|'block', 'reason': ...}.
    Enforces ARCH-3E / R3-A7 / R4-C1 Context-Blinded Challenger isolation via strict Whitelist.
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

    targets = _extract_target_strings(tool_input)
    combined_blob = " ".join(targets)

    is_blinded = _is_blinded_context(payload, mode=mode)
    if (
        not is_blinded
        and tool_low in NATIVE_SHELL_TOOLS
        and "--skill" in combined_blob.lower()
        and "blinded_counterevidence_challenger" in combined_blob.lower()
    ):
        is_blinded = True

    if not is_blinded:
        return {
            "decision": "approve",
            "reason": "Non-blinded session context.",
        }

    # Rule 1: In blinded context, ANY reference to .localsec/runs/, documents/, or unblinded JSON artifacts is blocked.
    for t in targets:
        hit = _references_forbidden_blinded_artifact(t)
        if hit:
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (C1): blinded_counterevidence_challenger is forbidden from accessing "
                    f"{hit!r} via {tool_name!r}. Read only .localsec/tmp/blinded_chains_<repo>.json and use "
                    f"`python -m localsec.manual_session read_file <repo> <path> --skill blinded_counterevidence_challenger`."
                ),
            }

    # Rule 2: Native search tools (Grep, Glob, LS, Find) are unconditionally blocked in blinded context.
    if tool_low in NATIVE_SEARCH_TOOLS:
        return {
            "decision": "block",
            "reason": (
                f"Context-Blinded Violation (C1): native search tool {tool_name!r} is blocked during "
                f"blinded_counterevidence_challenger to enforce exact_paths allow-list and prevent unblinded artifact discovery."
            ),
        }

    # Rule 3: Native Read / View tools use a strict Whitelist (only toolkit dirs + .localsec/tmp/*.json).
    if tool_low in NATIVE_READ_TOOLS:
        if not targets:
            return {
                "decision": "block",
                "reason": f"Fail-closed: native {tool_name!r} called without an explicit whitelisted file_path.",
            }
        for t in targets:
            if not _is_whitelisted_read_path(t):
                return {
                    "decision": "block",
                    "reason": (
                        f"Context-Blinded Violation (C1): native {tool_name!r} on {t!r} is not on the blinded Read whitelist. "
                        f"Only toolkit files and `.localsec/tmp/*.json` may be read natively; repository source files must be read via "
                        f"`python -m localsec.manual_session read_file <repo> <path> --skill blinded_counterevidence_challenger`."
                    ),
                }
        return {
            "decision": "approve",
            "reason": "Whitelisted Read path permitted in blinded_counterevidence_challenger.",
        }

    # Rule 4: Native Write / Edit tools may ONLY write draft JSON files to `.localsec/tmp/*.json` (excluding `blinded_chains_*.json`).
    if tool_low in NATIVE_WRITE_TOOLS:
        if not targets:
            return {
                "decision": "block",
                "reason": f"Fail-closed: native {tool_name!r} called without an explicit target file_path.",
            }
        for t in targets:
            if not _is_whitelisted_write_path(t):
                return {
                    "decision": "block",
                    "reason": (
                        f"Context-Blinded Violation (C1): native {tool_name!r} on {t!r} is blocked. "
                        f"In blinded_counterevidence_challenger, Write/Edit is restricted exclusively to `.localsec/tmp/draft_*.json`."
                    ),
                }
        return {
            "decision": "approve",
            "reason": "Whitelisted .localsec/tmp draft JSON write permitted in blinded_counterevidence_challenger.",
        }

    # Rule 5: Bash / PowerShell / Cmd / RunCommand uses a strict Whitelist:
    # ONLY `python -m localsec.manual_session <read_file|show_evidence|list_evidence|submit_skill>` with no shell metacharacters.
    if tool_low in NATIVE_SHELL_TOOLS:
        cmd_str = combined_blob.strip()
        if not cmd_str:
            return {
                "decision": "block",
                "reason": f"Fail-closed: empty {tool_name!r} command in blinded_counterevidence_challenger.",
            }
        if FORBIDDEN_SHELL_METACHARS_RE.search(cmd_str):
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (C1): {tool_name!r} command contains forbidden shell metacharacters "
                    "(`|`, `;`, `&`, `<`, `>`, `$`, backtick, or newline). Execute a single whitelisted "
                    "`python -m localsec.manual_session` command."
                ),
            }
        m = WHITELIST_BASH_CMD_RE.match(cmd_str)
        if not m:
            return {
                "decision": "block",
                "reason": (
                    f"Context-Blinded Violation (C1): {tool_name!r} command {cmd_str!r} is not on the blinded whitelist. "
                    f"Only `python -m localsec.manual_session <read_file|show_evidence|list_evidence|submit_skill>` is allowed."
                ),
            }
        subcmd = m.group("subcmd")
        rest = m.group("rest") or ""
        if ".." in rest.replace("\\", "/").split("/"):
            return {
                "decision": "block",
                "reason": "Context-Blinded Violation (C1): parent directory traversal ('..') is forbidden in blinded shell command.",
            }
        cli_args = _split_cli_args(rest)
        if subcmd == "read_file":
            # Exactly one --skill equal to the blinded skill: argparse keeps the LAST value, so an extra
            # `--skill <other>` would switch exact_paths enforcement to another skill's allow-list.
            if _option_values(cli_args, "--skill") != ["blinded_counterevidence_challenger"]:
                return {
                    "decision": "block",
                    "reason": (
                        "Context-Blinded Violation (C1): `manual_session read_file` in blinded challenger must pass "
                        "`--skill blinded_counterevidence_challenger` so exact_paths enforcement is active."
                    ),
                }
        elif subcmd == "submit_skill":
            # submit_skill <repo_name> <skill_name> [json_file]: check the skill slot itself, not a substring
            # anywhere in the command (a draft file name may contain the blinded skill name).
            positional = [a for a in cli_args if not a.startswith("--")]
            if len(positional) < 2 or positional[1] != "blinded_counterevidence_challenger":
                return {
                    "decision": "block",
                    "reason": (
                        "Context-Blinded Violation (C1): `manual_session submit_skill` in blinded challenger may only submit "
                        "`blinded_counterevidence_challenger`."
                    ),
                }
        return {
            "decision": "approve",
            "reason": f"Whitelisted manual_session {subcmd} command permitted in blinded_counterevidence_challenger.",
        }

    # Any other tool (including Task/subagent spawning, WebFetch, etc.) in blinded mode is blocked fail-closed
    if tool_low not in {"todowrite"}:
        return {
            "decision": "block",
            "reason": f"Context-Blinded Violation (C1): tool {tool_name!r} is not whitelisted in blinded_counterevidence_challenger.",
        }

    return {
        "decision": "approve",
        "reason": "Permitted under blinded_counterevidence_challenger guard policy.",
    }


def _emit_and_exit(verdict: dict[str, Any]) -> int:
    decision = str(verdict.get("decision") or "block")
    reason = str(verdict.get("reason") or "Blocked by LocalSec PreToolUse guard.")
    if decision == "approve":
        # Exit 0 without output: the legacy `{"decision": "approve"}` would bypass Claude Code's permission
        # prompt for every whitelisted command; allowing silently keeps the normal permission flow.
        return 0
    # Claude Code reads stderr when PreToolUse exits with code 2
    sys.stderr.write(f"[LocalSec Blinded Guard BLOCKED] {reason}\n")
    sys.stderr.flush()
    sys.stdout.write(json.dumps(verdict, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 2


def _emit_antigravity(verdict: dict[str, Any]) -> int:
    """Antigravity reads {"decision": "allow"|"deny", "reason"} from stdout; exit code stays 0."""
    allow = str(verdict.get("decision") or "block") == "approve"
    out = {"decision": "allow" if allow else "deny"}
    if not allow:
        out["reason"] = "[LocalSec Blinded Guard] " + str(verdict.get("reason") or "blocked")
    sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        parser = argparse.ArgumentParser(
            prog="python -m localsec.claude_subagent_guard",
            description="Claude Code PreToolUse hook guard enforcing Context-Blinded Challenger isolation (R3-A7 / R4-C1).",
        )
        parser.add_argument(
            "--mode",
            choices=("auto", "blinded_challenger"),
            default="auto",
            help="Guard enforcement mode ('blinded_challenger' forces blinded whitelist enforcement).",
        )
        parser.add_argument(
            "--platform",
            choices=("claude", "antigravity"),
            default="claude",
            help="Hook payload/response format. 'antigravity' = .agents/hooks.json (toolCall/transcriptPath in, allow/deny out).",
        )
        parser.add_argument(
            "--payload",
            default=None,
            help="Optional JSON string or path to JSON file (defaults to reading stdin).",
        )
        args = parser.parse_args(argv)

        raw_text = ""
        if args.payload is not None:
            cand_path = Path(args.payload)
            if cand_path.is_file():
                raw_text = cand_path.read_text(encoding="utf-8", errors="replace")
            else:
                raw_text = str(args.payload)
        else:
            if not sys.stdin.isatty():
                raw_text = sys.stdin.read()

        emit = _emit_antigravity if args.platform == "antigravity" else _emit_and_exit
        if not raw_text.strip():
            return emit({"decision": "block", "reason": "Fail-closed: empty PreToolUse hook input."})

        try:
            payload = json.loads(raw_text)
        except Exception as exc:
            return emit(
                {"decision": "block", "reason": f"Fail-closed: invalid JSON in PreToolUse hook input ({type(exc).__name__})."}
            )

        mode = args.mode
        if args.platform == "antigravity" and isinstance(payload, dict):
            payload, detected = _normalize_payload(payload, "antigravity")
            if mode == "auto":
                mode = detected
        verdict = evaluate_tool_use(payload, mode=mode)
        return emit(verdict)
    except Exception as exc:
        # Fail-closed on any unexpected internal exception
        if "--platform" in (argv if argv is not None else sys.argv) and "antigravity" in (argv if argv is not None else sys.argv):
            return _emit_antigravity({"decision": "block", "reason": f"Fail-closed: internal guard exception ({type(exc).__name__}: {exc})."})
        return _emit_and_exit(
            {"decision": "block", "reason": f"Fail-closed: internal guard exception ({type(exc).__name__}: {exc})."}
        )


if __name__ == "__main__":
    raise SystemExit(main())

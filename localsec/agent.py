from __future__ import annotations

import hashlib
import json
from typing import Any

from .llm import LocalModelError, OpenAICompatibleLocalClient
from .prompts import schema_for, system_prompt
from .validators import OutputValidationError, validate_agent_output
from .workspace import ManualWorkspace


def _filter_context_evidence(node: Any, allowed_ids: set[str]) -> Any:
    """Prevent a prompt from carrying citations whose excerpts were trimmed from that prompt."""
    if isinstance(node, dict):
        if isinstance(node.get("evidence_ids"), list):
            node["evidence_ids"] = [eid for eid in node["evidence_ids"] if isinstance(eid, str) and eid in allowed_ids]
            if node.get("status") in {"observed", "derived"} and not node["evidence_ids"]:
                node["status"] = "unknown"
                if isinstance(node.get("notes"), str):
                    node["notes"] += " [This context hand-off omitted the original evidence excerpt; re-read the file before using this claim.]"
        for key, value in list(node.items()):
            node[key] = _filter_context_evidence(value, allowed_ids)
        return node
    if isinstance(node, list):
        return [_filter_context_evidence(value, allowed_ids) for value in node]
    return node


def run_skill(
    *,
    client: OpenAICompatibleLocalClient,
    skill: str,
    job_spec: dict[str, Any],
    context: dict[str, Any],
    workspace: ManualWorkspace | None,
    cfg: dict[str, Any],
    allowed_context_evidence_ids: set[str] | None = None,
) -> dict[str, Any]:
    """Run one specialist skill as an isolated, iterative local-model conversation."""
    prompt, spec = system_prompt(skill)
    analysis_cfg = cfg.get("analysis", {})
    max_tool_calls = int(analysis_cfg.get("max_total_tool_calls_per_skill", 40)) if workspace else 0
    max_dir_calls = min(int(analysis_cfg.get("max_dir_calls_per_skill", 15)), max_tool_calls) if workspace else 0
    max_read_calls = min(int(analysis_cfg.get("max_read_calls_per_skill", 25)), max_tool_calls) if workspace else 0
    max_turns = int(analysis_cfg.get("max_model_turns_per_skill", 45))
    validation_retries = int(analysis_cfg.get("validation_retries", 1))
    initial_evidence_ids = set(allowed_context_evidence_ids or set())
    available_catalog = list(context.pop("available_evidence", [])) if "available_evidence" in context else []
    payload = {
        "job_spec": {
            **job_spec,
            "skill": skill,
            "skill_version": spec.get("version", "1.0.0"),
            "allowed_tools": spec.get("allowed_tools", []),
            "read_scope": spec.get("read_scope", "none"),
            "minimum_successful_reads": int(spec.get("minimum_successful_reads", 0)),
            "minimum_directory_lists": int(spec.get("minimum_directory_lists", 0)),
            "remaining_tool_calls": max_tool_calls,
            "remaining_dir_calls": max_dir_calls,
            "remaining_read_calls": max_read_calls,
            "important": "Use tools to inspect source manually. File paths must be relative to repository root.",
        },
        "context": context,
        "available_evidence": available_catalog,
    }
    # Enforce an input-context budget before the first model call.
    # For evidence_auditor, preserve full audit excerpt size so lines inside 180-line chunks are not cut off.
    max_context_chars = int(analysis_cfg.get("max_context_chars", 60_000))
    excerpt_char_cap = (
        int(analysis_cfg.get("max_audit_excerpt_chars", 4500))
        if skill == "evidence_auditor"
        else int(analysis_cfg.get("max_evidence_excerpt_chars", 1800))
    )

    def _reduce(node: Any, *, key: str = "", list_limit: int = 45, string_limit: int = 900, excerpt_limit: int = excerpt_char_cap) -> Any:
        if isinstance(node, str):
            limit = excerpt_limit if key in {"excerpt", "content"} else string_limit
            return node if len(node) <= limit else node[:limit] + "[CONTEXT_TRUNCATED]"
        if isinstance(node, list):
            reduced = [_reduce(item, key=key, list_limit=list_limit, string_limit=string_limit, excerpt_limit=excerpt_limit) for item in node[:list_limit]]
            if len(node) > list_limit:
                reduced.append({"_context_truncated": True, "omitted_items": len(node) - list_limit})
            return reduced
        if isinstance(node, dict):
            return {k: _reduce(v, key=k, list_limit=list_limit, string_limit=string_limit, excerpt_limit=excerpt_limit) for k, v in node.items()}
        return node

    evidence_record_cap = int(analysis_cfg.get("max_evidence_context_records", 55))
    if skill in {"cross_repo_review", "diagram_author"}:
        evidence_record_cap = max(evidence_record_cap, len(available_catalog))

    payload["context"] = _reduce(payload["context"])
    payload["available_evidence"] = _reduce(payload["available_evidence"], list_limit=evidence_record_cap)

    # First compact context if payload exceeds max_context_chars, preserving available_evidence.
    if len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"))) > max_context_chars:
        payload["context"] = _reduce(payload["context"], list_limit=25, string_limit=450, excerpt_limit=min(1200, excerpt_char_cap))

    # Protect a minimum floor of evidence records so cross-repo or downstream skills never lose all citations.
    protected_floor = min(len(payload["available_evidence"]), max(12, len(payload["available_evidence"]) // 2))
    while (
        len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"))) > max_context_chars
        and len(payload["available_evidence"]) > protected_floor
    ):
        payload["available_evidence"].pop()

    # If still over budget, shorten excerpts inside available_evidence rather than dropping evidence IDs.
    if len(json.dumps(payload, ensure_ascii=False, separators=(",", ":"))) > max_context_chars and payload["available_evidence"]:
        payload["available_evidence"] = _reduce(payload["available_evidence"], list_limit=len(payload["available_evidence"]), string_limit=350, excerpt_limit=400)

    # Evidence IDs omitted from the actual payload cannot be cited by this skill unless freshly read.
    payload_evidence_ids = {str(item.get("evidence_id")) for item in payload["available_evidence"] if isinstance(item, dict) and item.get("evidence_id")}
    if available_catalog:
        initial_evidence_ids &= payload_evidence_ids
        payload["context"] = _filter_context_evidence(payload["context"], payload_evidence_ids)
    # Preserve stable hashes so reviewers can identify exactly which prompt contract and initial job were used.
    initial_payload_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    system_prompt_sha256 = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    initial_payload_sha256 = hashlib.sha256(initial_payload_json.encode("utf-8")).hexdigest()
    messages: list[dict[str, str]] = [{"role": "user", "content": initial_payload_json}]
    tool_calls = 0
    dir_calls = 0
    read_calls = 0
    tool_trace: list[dict[str, Any]] = []
    model_turns = 0
    validation_attempts = 0
    validation_errors: list[str] = []
    start_evidence_ids = set(workspace.evidence) if workspace else set()
    evidence_ids_seen_by_skill: set[str] = set()
    if available_catalog:
        evidence_ids_seen_by_skill.update(str(item.get("evidence_id")) for item in payload["available_evidence"] if isinstance(item, dict) and item.get("evidence_id"))
    status = "failed"
    result: dict[str, Any] | None = None
    warnings: list[str] = []

    while model_turns < max_turns:
        model_turns += 1
        try:
            response = client.complete_json_messages(prompt, messages)
        except LocalModelError as exc:
            warnings.append(f"local_model_error: {exc}")
            break

        # Be strict about the response envelope. An unwrapped schema object is accepted only as a
        # compatibility fallback for local servers that ignore the response protocol.
        response_type = response.get("type")
        if response_type == "tool_call":
            tool = response.get("tool")
            arguments = response.get("arguments", {})
            reason = str(response.get("reason", ""))[:300]
            messages.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
            if tool not in spec.get("allowed_tools", []) or workspace is None:
                tool_result = {"ok": False, "error": f"Tool {tool!r} is not allowed for skill {skill!r}. Only the skill registry allow-list is authoritative."}
            elif tool_calls >= max_tool_calls:
                tool_result = {"ok": False, "error": "Tool-call budget exhausted. Finish with evidence gathered so far and explicit unknowns."}
                warnings.append("tool_call_budget_exhausted")
            elif tool == "list_dir" and dir_calls >= max_dir_calls:
                tool_result = {"ok": False, "error": "Directory-listing budget exhausted. Use read_file on discovered paths or finish with explicit unknowns."}
                warnings.append("dir_call_budget_exhausted")
            elif tool == "read_file" and read_calls >= max_read_calls:
                tool_result = {"ok": False, "error": "File-reading budget exhausted. Finish with evidence gathered so far and explicit unknowns."}
                warnings.append("read_call_budget_exhausted")
            elif not isinstance(arguments, dict):
                tool_result = {"ok": False, "error": "arguments must be a JSON object"}
            else:
                tool_calls += 1
                if tool == "list_dir":
                    dir_calls += 1
                elif tool == "read_file":
                    read_calls += 1
                try:
                    tool_result = workspace.execute_tool(skill, str(tool), arguments)
                    result_obj = tool_result.get("result", {})
                    if tool == "read_file" and result_obj.get("evidence_id"):
                        evidence_ids_seen_by_skill.add(str(result_obj["evidence_id"]))
                except Exception as exc:  # tool boundary returns errors to the model; no shell fallback
                    tool_result = {"ok": False, "error": f"{type(exc).__name__}: {str(exc)[:500]}"}
            trace_item = {"tool": tool, "arguments": arguments if isinstance(arguments, dict) else {}, "reason": reason, "ok": bool(tool_result.get("ok")), "error": tool_result.get("error")}
            if tool_result.get("ok") and isinstance(tool_result.get("result"), dict):
                returned = tool_result["result"]
                trace_item.update({k: returned[k] for k in ("path", "line_start", "line_end", "evidence_id", "directory", "depth", "returned", "total_visible_entries") if k in returned})
            tool_trace.append(trace_item)
            messages.append({
                "role": "user",
                "content": json.dumps({
                    "tool_result_for": tool,
                    "reason": reason,
                    "remaining_tool_calls": max(0, max_tool_calls - tool_calls),
                    "remaining_dir_calls": max(0, max_dir_calls - dir_calls),
                    "remaining_read_calls": max(0, max_read_calls - read_calls),
                    **tool_result,
                }, ensure_ascii=False),
            })
            continue

        if response_type == "final" and isinstance(response.get("result"), dict):
            candidate = response["result"]
        elif "type" not in response and set(schema_for(skill).get("required", [])).issubset(response.keys()):
            candidate = response
        else:
            messages.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
            messages.append({"role": "user", "content": json.dumps({"protocol_error": "Return a tool_call or final envelope exactly as specified. No other format.", "valid_tool_names": spec.get("allowed_tools", [])}, ensure_ascii=False)})
            continue

        successful_reads = sum(1 for call in tool_trace if call.get("tool") == "read_file" and call.get("ok"))
        successful_lists = sum(1 for call in tool_trace if call.get("tool") == "list_dir" and call.get("ok"))
        minimum_reads = int(spec.get("minimum_successful_reads", 0))
        minimum_lists = int(spec.get("minimum_directory_lists", 0))
        if successful_reads < minimum_reads or successful_lists < minimum_lists:
            activity_errors = []
            if successful_reads < minimum_reads:
                activity_errors.append(f"This skill must manually read at least {minimum_reads} source/config file range(s); successful reads so far: {successful_reads}.")
            if successful_lists < minimum_lists:
                activity_errors.append(f"This skill must manually list at least {minimum_lists} directory(ies); successful directory listings so far: {successful_lists}.")
            if validation_attempts < validation_retries:
                validation_attempts += 1
                messages.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
                messages.append({"role": "user", "content": json.dumps({"activity_gate_failed": True, "requirements": activity_errors, "instruction": "Use only the already allowed read-only tools to inspect the repository, then return the final schema-compliant result. Do not invent evidence."}, ensure_ascii=False)})
                continue
            warnings.append("minimum_manual_inspection_not_met")
            warnings.extend(activity_errors)
            break

        valid_ids = set(initial_evidence_ids) | set(evidence_ids_seen_by_skill)
        if workspace:
            # Only evidence shown to this job or explicitly opened during this job is valid.
            valid_ids |= set(workspace.evidence) - start_evidence_ids
        try:
            validate_agent_output(skill, candidate, valid_ids)
            result = candidate
            status = "ok"
            break
        except OutputValidationError as exc:
            validation_errors = str(exc).split("; ")[:30]
            if validation_attempts >= validation_retries:
                warnings.append("schema_or_evidence_validation_failed")
                warnings.extend(validation_errors)
                break
            validation_attempts += 1
            messages.append({"role": "assistant", "content": json.dumps(response, ensure_ascii=False)})
            messages.append({"role": "user", "content": json.dumps({
                "validation_failed": True,
                "errors": validation_errors,
                "instruction": "Correct the output using only available evidence IDs and return a final envelope. Do not add unsupported claims. You may request allowed read tools first if evidence is missing."
            }, ensure_ascii=False)})

    if result is None and model_turns >= max_turns:
        warnings.append("model_turn_budget_exhausted")
    newly_read = sorted((set(workspace.evidence) - start_evidence_ids) if workspace else set())
    return {
        "skill": skill,
        "version": spec.get("version", "1.0.0"),
        "status": status,
        "result": result,
        "tool_calls": tool_calls,
        "dir_calls": dir_calls,
        "read_calls": read_calls,
        "model_turns": model_turns,
        "validation_retries": validation_attempts,
        "evidence_ids_seen": sorted(evidence_ids_seen_by_skill),
        "evidence_ids_read_during_job": newly_read,
        "tool_trace": tool_trace,
        "system_prompt_sha256": system_prompt_sha256,
        "initial_payload_sha256": initial_payload_sha256,
        "warnings": warnings,
    }

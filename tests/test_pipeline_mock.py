from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from localsec.config import DEFAULT_CONFIG
from localsec.orchestrator import analyze_repositories

REQUEST_PAYLOADS: list[dict] = []


def parse_message(content: str):
    try:
        return json.loads(content)
    except Exception:
        return {}


def final_response(skill: str, initial_payload: dict, messages: list[dict]) -> dict:
    tool_results = [parse_message(m.get("content", "")) for m in messages[1:] if m.get("role") == "user"]
    read_results = [m.get("result", {}) for m in tool_results if m.get("tool_result_for") == "read_file" and m.get("ok")]
    eids = [r.get("evidence_id") for r in read_results if r.get("evidence_id")]
    evidence_id = eids[-1] if eids else None
    if skill == "repo_profile":
        eid_list = [evidence_id] if evidence_id else []
        purpose_status = "observed" if eid_list else "unknown"
        return {"type": "final", "result": {
            "purpose": {"value": "Go service from inspected entrypoint", "status": purpose_status, "evidence_ids": eid_list, "notes": "Mock output for orchestration contract only."},
            "criticality": {"value": "unknown", "status": "unknown", "evidence_ids": [], "notes": "Business criticality not assessed."},
            "techstack": ([{"name": "Language", "value": "Go", "status": "observed", "evidence_ids": eid_list, "notes": "A .go source file was inspected."}] if eid_list else []),
            "business_capabilities": [], "unknowns": ["Mock response does not conduct semantic business analysis."]
        }}
    if skill == "api_authz":
        return {"type": "final", "result": {"endpoints": [], "authorization_patterns": [], "unknowns": ["Mock model did not enumerate endpoints."]}}
    if skill == "dataflow":
        return {"type": "final", "result": {"flows": [], "trust_boundaries": [], "unknowns": ["Mock model did not trace flows."]}}
    if skill == "threat_model":
        return {"type": "final", "result": {"threats": [], "assumptions": [], "unknowns": ["Mock model did not assess threats."]}}
    if skill == "architecture_review":
        return {"type": "final", "result": {"observations": [], "strengths": [], "unknowns": ["Mock model did not review architecture."]}}
    if skill == "evidence_auditor":
        claims = initial_payload.get("context", {}).get("claims_to_audit", [])
        audited = []
        for claim in claims:
            ids = claim.get("cited_evidence_ids", [])
            status = claim.get("claim_status")
            verdict = "supported" if ids and status in {"observed", "derived"} else "inconclusive"
            audited.append({"claim_ref": claim["claim_ref"], "verdict": verdict, "evidence_ids": ids, "reason": "Mock verdict tests schema plumbing only.", "follow_up": []})
        not_sent = initial_payload.get("context", {}).get("not_sent_claim_refs", [])
        return {"type": "final", "result": {"audit_status": "partial" if not_sent else "complete", "audited_claims": audited, "not_audited": not_sent, "summary": "Mock evidence auditor; not a semantic result."}}
    if skill == "cross_repo_review":
        return {"type": "final", "result": {"interactions": [], "system_risks": [], "coverage_gaps": [], "unknowns": ["Mock cross-repo analysis only."]}}
    if skill == "diagram_author":
        repos = initial_payload.get("context", {}).get("repositories", [])
        return {"type": "final", "result": {"repo_diagrams": [{"repo_name": x["repo_name"], "mermaid": "flowchart LR\\n  A[\\\"Inspected repo\\\"]", "evidence_ids": [], "notes": "Mock diagram."} for x in repos], "system_diagram": "flowchart LR\\n  S[\\\"System context not established\\\"]", "unknowns": []}}
    raise AssertionError(skill)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.endswith("/models"):
            body = json.dumps({"data": [{"id": "mock-model"}]}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
        else:
            self.send_error(404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode())
        messages = request["messages"][1:]
        initial = parse_message(messages[0]["content"])
        REQUEST_PAYLOADS.append({"system": request["messages"][0]["content"], "initial": initial})
        skill = initial["job_spec"]["skill"]
        tool_responses = [parse_message(m.get("content", "")) for m in messages[1:] if m.get("role") == "user"]
        tool_names = [m.get("tool_result_for") for m in tool_responses]
        allowed = initial.get("job_spec", {}).get("allowed_tools", [])
        if allowed and "list_dir" not in tool_names:
            content = {"type": "tool_call", "tool": "list_dir", "arguments": {"path": ".", "offset": 0, "limit": 100}, "reason": "Manually inspect repository root."}
        elif allowed and "read_file" not in tool_names:
            listed = [m.get("result", {}) for m in tool_responses if m.get("tool_result_for") == "list_dir" and m.get("ok")]
            entries = listed[-1].get("entries", []) if listed else []
            preferred = next((x.get("path") for x in entries if x.get("name") == "main.go"), None)
            preferred = preferred or next((x.get("path") for x in entries if x.get("type") == "file"), "go.mod")
            content = {"type": "tool_call", "tool": "read_file", "arguments": {"path": preferred, "start_line": 1, "end_line": 100}, "reason": "Inspect an entrypoint/config file as evidence."}
        else:
            content = final_response(skill, initial, messages)
        body = json.dumps({"choices": [{"message": {"content": json.dumps(content, ensure_ascii=False)}}]}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, *_args):
        return


class ManualPipelineMockTests(unittest.TestCase):
    def test_full_multi_repo_run_uses_only_manual_read_tools(self):
        REQUEST_PAYLOADS.clear()
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                repos = []
                for name in ("service-a", "service-b"):
                    repo = root / name; repo.mkdir()
                    (repo / "go.mod").write_text(f"module local.test/{name}\n\ngo 1.22\n", encoding="utf-8")
                    (repo / "main.go").write_text("package main\nfunc main() { println(\"hello\") }\n", encoding="utf-8")
                    repos.append(repo)
                cfg = json.loads(json.dumps(DEFAULT_CONFIG))
                cfg["analysis"].update({"ignored_dirs": [".git", "vendor"], "max_total_tool_calls_per_skill": 5, "max_model_turns_per_skill": 10, "max_evidence_context_records": 20, "max_claims_per_audit": 20, "validation_retries": 1})
                cfg["llm"].update({"base_url": f"http://127.0.0.1:{server.server_port}/v1", "model": "mock-model", "timeout_seconds": 10, "max_tokens": 1000, "temperature": 0, "allow_remote": False})
                result = analyze_repositories(repos, cfg=cfg, output_dir=root / "documents", work_dir=root / ".localsec", use_llm=True)
                coverage = result["system_coverage"]
                self.assertEqual(coverage["workflow_status"], "completed")
                self.assertEqual(coverage["analysis_mode"], "ai_manual_file_reading")
                self.assertFalse(coverage["exhaustive_repository_scan"])
                all_initial = json.dumps(REQUEST_PAYLOADS, ensure_ascii=False)
                self.assertNotIn(str(root), all_initial, "absolute workspace paths must not be sent to the model")
                self.assertFalse((Path(__file__).resolve().parents[1] / "tools").exists(), "static parser/helper tools must not ship in AI-only edition")
                self.assertTrue(all("list_dir" in p["system"] or "AI auditor" in p["system"] for p in REQUEST_PAYLOADS))
                evidence_sets = []
                for name in ("service-a", "service-b"):
                    repo_out = root / "documents" / name
                    evidence = json.loads((repo_out / "10_evidence_index.json").read_text(encoding="utf-8"))
                    evidence_sets.append({item["evidence_id"] for item in evidence})
                    status = json.loads((repo_out / "12_analysis_status.json").read_text(encoding="utf-8"))
                    self.assertEqual(status["workflow_status"], "completed")
                    self.assertTrue((repo_out / "07_threat_model.md").exists())
                    self.assertTrue((repo_out / "diagrams" / "repo_dataflow.mmd").exists())
                    coverage_file = json.loads((repo_out / "11_coverage.json").read_text(encoding="utf-8"))
                    self.assertEqual(coverage_file["analysis_mode"], "ai_manual_file_reading")
                    self.assertFalse(coverage_file["exhaustive_repository_scan"])
                self.assertTrue(evidence_sets[0].isdisjoint(evidence_sets[1]))
                skills = {p["initial"]["job_spec"]["skill"] for p in REQUEST_PAYLOADS}
                self.assertTrue({"repo_profile", "api_authz", "dataflow", "threat_model", "architecture_review", "evidence_auditor", "cross_repo_review", "diagram_author"}.issubset(skills))
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

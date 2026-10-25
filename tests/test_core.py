from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from localsec.config import DEFAULT_CONFIG
from localsec.validators import OutputValidationError, validate_agent_output
from localsec.workspace import ManualWorkspace, WorkspaceError, redact_text


class ManualWorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "sample-repo"
        self.root.mkdir()
        (self.root / "main.go").write_text('''package main
const apiKey = "not-a-real-secret-value-123456"
func main() { println("hello") }
''', encoding="utf-8")
        (self.root / "go.mod").write_text("module sample.local/app\n\ngo 1.22\n", encoding="utf-8")
        hidden = self.root / ".git"
        hidden.mkdir()
        (hidden / "secret.go").write_text("package secret\n", encoding="utf-8")
        self.cfg = dict(DEFAULT_CONFIG["analysis"])
        self.workspace = ManualWorkspace(self.root, "sample-repo", self.cfg, "test-run")

    def tearDown(self):
        self.tmp.cleanup()

    def test_list_dir_lists_only_requested_directory(self):
        listing = self.workspace.list_dir(".")
        paths = {entry["path"] for entry in listing["entries"]}
        self.assertIn("main.go", paths)
        self.assertIn("go.mod", paths)
        self.assertFalse(any(".git" in p for p in paths))
        self.assertEqual(len(listing["entries"]), 2)

    def test_read_file_creates_line_evidence_and_redacts(self):
        result = self.workspace.read_file(skill="repo_profile", path="main.go", start_line=1, end_line=3)
        self.assertTrue(result["evidence_id"].startswith("ev_"))
        self.assertIn("1: package main", result["content"])
        self.assertIn("[REDACTED]", result["content"])
        self.assertNotIn("not-a-real-secret-value-123456", result["content"])
        self.assertIn(result["evidence_id"], self.workspace.evidence)

    def test_parent_traversal_is_rejected(self):
        with self.assertRaises(WorkspaceError):
            self.workspace.read_file(skill="repo_profile", path="../outside.txt")

    def test_symlink_is_rejected(self):
        other = Path(self.tmp.name) / "other.txt"
        other.write_text("do not read", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(other)
        except OSError:
            self.skipTest("symlinks unavailable")
        with self.assertRaises(WorkspaceError):
            self.workspace.read_file(skill="repo_profile", path="link.txt")

    def test_skill_scope_denies_repository_read_for_auditor(self):
        response = self.workspace.execute_tool("evidence_auditor", "read_file", {"path": "main.go", "start_line": 1, "end_line": 2})
        self.assertFalse(response["ok"])

    def test_evidence_ids_are_repo_namespaced(self):
        a = self.workspace.read_file(skill="repo_profile", path="go.mod", start_line=1, end_line=2)["evidence_id"]
        other = ManualWorkspace(self.root, "different-repo", self.cfg, "test-run")
        b = other.read_file(skill="repo_profile", path="go.mod", start_line=1, end_line=2)["evidence_id"]
        self.assertNotEqual(a, b)

    def test_observed_claim_requires_real_evidence(self):
        claim = {"purpose": {"value": "payment service", "status": "observed", "evidence_ids": ["ev_fake"], "notes": "claim"}, "criticality": {"value": "unknown", "status": "unknown", "evidence_ids": [], "notes": "unknown"}, "techstack": [], "business_capabilities": [], "unknowns": []}
        with self.assertRaises(OutputValidationError):
            validate_agent_output("repo_profile", claim, set())

    def test_hypothesis_can_be_unconfirmed_but_has_schema(self):
        profile = {"purpose": {"value": "Possible payment API", "status": "hypothesis", "evidence_ids": [], "notes": "No confirming code read"}, "criticality": {"value": "unknown", "status": "unknown", "evidence_ids": [], "notes": "not known"}, "techstack": [], "business_capabilities": [], "unknowns": ["entrypoint not read"]}
        validate_agent_output("repo_profile", profile, set())

    def test_redaction_keeps_nonliteral_assignment_code(self):
        text = 'var secret = config.GetValue<string>("Secrets:ClientSecret");\npassword: "sample-password-value"\n'
        redacted = redact_text(text)
        self.assertIn('config.GetValue<string>', redacted)
        self.assertNotIn('sample-password-value', redacted)

    def test_polyglot_files_allowed_and_cert_or_lockfile_blocked(self):
        (self.root / "app.dart").write_text("void main() {}\n", encoding="utf-8")
        (self.root / "App.tsx").write_text("export const App = () => null;\n", encoding="utf-8")
        (self.root / "Jenkinsfile").write_text("pipeline { agent any }\n", encoding="utf-8")
        (self.root / "cert.cer").write_text("-----BEGIN CERTIFICATE-----\nMIIB...\n", encoding="utf-8")
        (self.root / "pubspec.lock").write_text("packages: {}\n", encoding="utf-8")
        (self.root / "user.g.dart").write_text("// GENERATED CODE\n", encoding="utf-8")

        listing = self.workspace.list_dir(".")
        by_name = {entry["name"]: entry for entry in listing["entries"]}
        self.assertEqual(by_name["app.dart"]["type"], "file")
        self.assertEqual(by_name["App.tsx"]["type"], "file")
        self.assertEqual(by_name["Jenkinsfile"]["type"], "file")
        self.assertEqual(by_name["cert.cer"]["type"], "certificate_or_key_metadata_only")
        self.assertEqual(by_name["pubspec.lock"]["type"], "generated_or_lockfile")
        self.assertEqual(by_name["user.g.dart"]["type"], "generated_or_lockfile")

        res_dart = self.workspace.read_file(skill="api_authz", path="app.dart", start_line=1, end_line=1)
        self.assertTrue(res_dart["evidence_id"].startswith("ev_"))

        with self.assertRaises(WorkspaceError):
            self.workspace.read_file(skill="repo_profile", path="cert.cer", start_line=1, end_line=2)
        with self.assertRaises(WorkspaceError):
            self.workspace.read_file(skill="repo_profile", path="pubspec.lock", start_line=1, end_line=2)
        with self.assertRaises(WorkspaceError):
            self.workspace.read_file(skill="repo_profile", path="user.g.dart", start_line=1, end_line=2)

    def test_list_dir_depth_two_returns_nested_entries(self):
        sub = self.root / "lib" / "screens"
        sub.mkdir(parents=True)
        (sub / "login_screen.dart").write_text("class LoginScreen {}\n", encoding="utf-8")
        listing_d1 = self.workspace.list_dir(".", depth=1)
        paths_d1 = {entry["path"] for entry in listing_d1["entries"]}
        self.assertIn("lib", paths_d1)
        self.assertNotIn("lib/screens", paths_d1)

        listing_d2 = self.workspace.list_dir(".", depth=2)
        paths_d2 = {entry["path"] for entry in listing_d2["entries"]}
        self.assertIn("lib", paths_d2)
        self.assertIn("lib/screens", paths_d2)

    def test_flat_security_schema_fields_validate(self):
        ev = self.workspace.read_file(skill="repo_profile", path="main.go", start_line=1, end_line=2)["evidence_id"]
        profile = {
            "purpose": {"value": "Agent portal service", "status": "observed", "evidence_ids": [ev], "notes": "main.go"},
            "criticality": {"value": "high", "status": "derived", "evidence_ids": [ev], "notes": "handles agent auth"},
            "techstack": [],
            "business_capabilities": [],
            "entrypoints": [{"kind": "http_server", "path_or_symbol": "main.go:main", "status": "observed", "evidence_ids": [ev], "notes": "main"}],
            "sensitive_data": [{"data_class": "credentials", "status": "observed", "evidence_ids": [ev], "notes": "apiKey"}],
            "unknowns": [],
        }
        validate_agent_output("repo_profile", profile, {ev})

        api_out = {
            "endpoints": [{
                "method": "GET",
                "path": "/api/v1/accounts/{id}",
                "handler": "GetAccount",
                "caller_class": "authenticated_agent",
                "authn": "JWT Bearer",
                "authorization": "Role:Agent",
                "roles": ["Agent"],
                "object_level_authz": "none_observed",
                "sensitivity": "high",
                "status": "observed",
                "evidence_ids": [ev],
                "notes": "No ownership check between JWT sub and account id",
            }],
            "authorization_patterns": [],
            "unknowns": [],
        }
        validate_agent_output("api_authz", api_out, {ev})

        df_out = {
            "flows": [{
                "direction": "outbound",
                "source": "HTTP Handler",
                "destination": "Postgres",
                "protocol": "TCP/SQL",
                "data_types": ["financial_account"],
                "trust_boundary": "app_to_db",
                "identity_context": "service_db_user",
                "controls": ["TLS"],
                "status": "observed",
                "evidence_ids": [ev],
                "notes": "Direct query",
            }],
            "trust_boundaries": [],
            "unknowns": [],
        }
        validate_agent_output("dataflow", df_out, {ev})

    def test_priority_audit_selection_and_fail_closed_downgrade(self):
        from localsec.orchestrator import _apply_audit, _iter_claims, _select_claims_for_audit

        ai = {
            "repo_profile": {
                "status": "ok",
                "result": {
                    "purpose": {"value": "unknown", "status": "unknown", "evidence_ids": [], "notes": "not read"},
                    "criticality": {"value": "high", "status": "derived", "evidence_ids": ["ev_1"], "notes": "derived"},
                    "techstack": [{"name": "Go", "value": "1.22", "status": "observed", "evidence_ids": ["ev_1"], "notes": "go.mod"}],
                    "business_capabilities": [],
                    "unknowns": [],
                },
            },
            "threat_model": {
                "status": "ok",
                "result": {
                    "threats": [{"id": "T1", "category": "Elevation of Privilege", "title": "BOLA", "affected_component": "API", "preconditions": "auth", "attack_path": "id swap", "existing_evidence": "none", "impact": "high", "likelihood": "high", "severity": "high", "status": "observed", "evidence_ids": ["ev_2"], "mitigations": []}],
                    "assumptions": [],
                    "unknowns": [],
                },
            },
        }
        all_claims: list[dict] = []
        for skill_name, entry in ai.items():
            _iter_claims(entry["result"], skill_name, out=all_claims)

        batches, skipped = _select_claims_for_audit(all_claims, {"analysis": {"audit_batch_size": 1, "max_audit_batches": 1, "max_claims_per_audit": 1}})
        self.assertEqual(len(batches), 1)
        self.assertEqual(len(batches[0]), 1)
        # threat_model has higher priority than repo_profile, and unknown claim without evidence was dropped
        self.assertEqual(batches[0][0]["source_skill"], "threat_model")
        self.assertEqual(len(skipped), 2)

        audit_res = {
            "status": "ok",
            "result": {
                "audit_status": "partial",
                "audited_claims": [{"claim_ref": batches[0][0]["claim_ref"], "verdict": "supported", "evidence_ids": ["ev_2"], "reason": "ok", "follow_up": []}],
                "not_audited": skipped,
                "summary": "partial",
            },
        }
        _apply_audit(ai, audit_res)
        self.assertEqual(ai["threat_model"]["result"]["threats"][0]["status"], "observed")
        # Unaudited observed/derived claims in repo_profile must fail-closed to hypothesis
        self.assertEqual(ai["repo_profile"]["result"]["criticality"]["status"], "hypothesis")
        self.assertEqual(ai["repo_profile"]["result"]["techstack"][0]["status"], "hypothesis")

    def test_cross_repo_evidence_round_robin_selection(self):
        from localsec.orchestrator import _select_cross_repo_evidence

        repo_results = [
            {
                "repo_name": "repo-a",
                "ai": {"api_authz": {"status": "ok", "result": {"endpoints": [{"evidence_ids": ["ev_a1", "ev_a2"]}]}}},
            },
            {
                "repo_name": "repo-b",
                "ai": {"dataflow": {"status": "ok", "result": {"flows": [{"evidence_ids": ["ev_b1", "ev_b2"]}]}}},
            },
        ]
        sys_evidence = {
            eid: {"evidence_id": eid, "repo_name": eid[:4], "path": "main.go", "line_start": 1, "line_end": 5, "excerpt_sha256": "h", "redaction_applied": False, "excerpt": "code"}
            for eid in ("ev_a1", "ev_a2", "ev_b1", "ev_b2")
        }
        selected = _select_cross_repo_evidence(repo_results, sys_evidence, {"analysis": {"max_system_evidence_records": 2, "max_evidence_excerpt_chars": 500}})
        selected_ids = [item["evidence_id"] for item in selected]
        # Round-robin with cap=2 across 2 repos must pick 1 from repo-a and 1 from repo-b in alternating order
        self.assertEqual(selected_ids, ["ev_a1", "ev_b1"])

    def test_all_skills_valid_for_antigravity_and_claude(self):
        import re

        repo_root = Path(__file__).resolve().parents[1]
        ag_skills = sorted((repo_root / ".agents" / "skills").glob("*/SKILL.md"))
        cl_skills = sorted((repo_root / ".claude" / "skills").glob("*/SKILL.md"))
        self.assertEqual(len(ag_skills), 16)
        self.assertEqual(len(cl_skills), 16)

        for ag_p, cl_p in zip(ag_skills, cl_skills):
            self.assertEqual(ag_p.parent.name, cl_p.parent.name)
            content = ag_p.read_text(encoding="utf-8")
            cl_content = cl_p.read_text(encoding="utf-8")
            self.assertIsNone(
                re.search(r"[\u0400-\u04ff\uac00-\ud7af\u4e00-\u9fff]", content),
                f"Foreign script typo (Cyrillic/Hangul/CJK) found in {ag_p}",
            )
            self.assertTrue(content.startswith("---\n"), f"Missing frontmatter start in {ag_p}")
            match = re.match(r"^---\n(.*?)\n---\n+(.*)", content, re.DOTALL)
            cl_match = re.match(r"^---\n(.*?)\n---\n+(.*)", cl_content, re.DOTALL)
            self.assertIsNotNone(match, f"Invalid frontmatter boundary in {ag_p}")
            self.assertIsNotNone(cl_match, f"Invalid frontmatter boundary in {cl_p}")
            fm_text, body = match.group(1), match.group(2)
            cl_fm_text, cl_body = cl_match.group(1), cl_match.group(2)
            self.assertEqual(body, cl_body, f"Body mismatch between {ag_p} and {cl_p}")
            fm_lines = fm_text.splitlines()
            cl_fm_lines = cl_fm_text.splitlines()
            # Antigravity frontmatter must be strictly 3 lines: name, description: >-, and indented description text
            self.assertEqual(len(fm_lines), 3, f"Unexpected lines in frontmatter of {ag_p}: {fm_lines}")
            self.assertEqual(fm_lines[0], f"name: {ag_p.parent.name}")
            self.assertRegex(ag_p.parent.name, r"^[a-z0-9-]+$")
            self.assertLessEqual(len(ag_p.parent.name), 64)
            self.assertEqual(fm_lines[1], "description: >-")
            desc = fm_lines[2].strip()
            self.assertTrue(len(desc) > 20 and len(desc) <= 1024, f"Invalid description length in {ag_p}")
            self.assertNotIn("<", desc, f"Angle bracket < forbidden by Claude validator in {ag_p}")
            self.assertNotIn(">", desc, f"Angle bracket > forbidden by Claude validator in {ag_p}")
            self.assertTrue(body.startswith("# "), f"Body after frontmatter must start with H1 heading in {ag_p}")
            # Claude Code frontmatter matches first 3 lines and includes context: fork for blinded challenger (R3-A7)
            self.assertEqual(cl_fm_lines[:3], fm_lines)
            if cl_p.parent.name == "phase-2-blinded-counterevidence-challenger":
                self.assertEqual(len(cl_fm_lines), 4, f"Expected context: fork in {cl_p}")
                self.assertEqual(cl_fm_lines[3], "context: fork")
            else:
                self.assertIn(len(cl_fm_lines), (3, 4))

    def test_setup_sh_syncs_and_uninstalls_antigravity_and_claude(self):
        import os
        import subprocess
        import sys
        from localsec.workspace import ManualWorkspace, WorkspaceError

        repo_root = Path(__file__).resolve().parents[1]
        setup_sh = repo_root / "setup.sh"
        with tempfile.TemporaryDirectory() as tmp:
            target_root = Path(tmp)
            env = dict(os.environ, AI_SKILLS_SKIP_TESTS="1")
            res = subprocess.run(["sh", str(setup_sh)], cwd=str(target_root), env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(len(list((target_root / ".agents" / "skills").glob("*/SKILL.md"))), 16)
            self.assertEqual(len(list((target_root / ".claude" / "skills").glob("*/SKILL.md"))), 16)
            self.assertTrue((target_root / "AGENTS.md").is_file())
            self.assertTrue((target_root / "SOUL.md").is_file())
            self.assertTrue((target_root / "CLAUDE.md").is_file())
            
            res_un = subprocess.run(["sh", str(setup_sh), "--uninstall"], cwd=str(target_root), env=env, capture_output=True, text=True)
            self.assertEqual(res_un.returncode, 0, res_un.stderr)
            self.assertFalse((target_root / ".agents").exists())
            self.assertFalse((target_root / ".claude").exists())
            self.assertFalse((target_root / "localsec").exists())
            self.assertFalse((target_root / "AGENTS.md").exists())
            self.assertFalse((target_root / "SOUL.md").exists())
            self.assertFalse((target_root / "CLAUDE.md").exists())

            # Verify Windows path security guards (drive letter, UNC path, reserved device names)
            for bad_win_path in ("C:\\Windows\\System32\\cmd.exe", "\\\\server\\share\\secret.txt", "CON", "src/NUL.txt", "COM1"):
                with self.assertRaises(WorkspaceError):
                    ManualWorkspace._clean_relative(bad_win_path)


if __name__ == "__main__":
    unittest.main()



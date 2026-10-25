from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from localsec.orchestrator import (
    _apply_audit,
    _iter_claims,
    build_blinded_challenger_context,
    build_blinded_targeted_verifier_context,
)
from localsec.prompts import load_registry, schema_for, system_prompt
from localsec.validators import OutputValidationError, validate_agent_output
from localsec.workspace import ManualWorkspace, WorkspaceError


def _create_minimal_xlsx(path: Path, sheet_name: str, rows: list[list[str]]) -> None:
    shared_strings: list[str] = []
    for row in rows:
        for cell in row:
            if cell not in shared_strings:
                shared_strings.append(cell)
    sst_items = "".join(f"<si><t>{s}</t></si>" for s in shared_strings)
    sst_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        f'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="{len(shared_strings)}" uniqueCount="{len(shared_strings)}">'
        f"{sst_items}</sst>"
    )
    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f'<sheets><sheet name="{sheet_name}" sheetId="1" r:id="rId1"/></sheets></workbook>'
    )
    rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    row_xml_parts: list[str] = []
    for r_idx, row in enumerate(rows, start=1):
        cells_xml: list[str] = []
        for c_idx, cell in enumerate(row):
            col_letter = chr(ord("A") + c_idx)
            s_idx = shared_strings.index(cell)
            cells_xml.append(f'<c r="{col_letter}{r_idx}" t="s"><v>{s_idx}</v></c>')
        row_xml_parts.append(f'<row r="{r_idx}">{"".join(cells_xml)}</row>')
    sheet_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(row_xml_parts)}</sheetData></worksheet>'
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("xl/sharedStrings.xml", sst_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", rels_xml)
        zf.writestr("xl/worksheets/sheet1.xml", sheet_xml)


def _create_minimal_docx(path: Path, paragraphs: list[str]) -> None:
    p_xml = "".join(f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs)
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{p_xml}</w:body></w:document>"
    )
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("word/document.xml", doc_xml)


class TestBASVPipeline(unittest.TestCase):
    def test_merged_registry_and_prompts_load(self) -> None:
        reg = load_registry()
        skills = reg.get("skills", {})
        for expected in (
            "repo_profile",
            "business_intent_modeler",
            "business_invariant_challenger",
            "implementation_trace_verifier",
            "intent_implementation_comparator",
            "security_consequence_mapper",
            "verification_planner",
            "targeted_verifier",
            "business_aware_synthesizer",
            "evidence_auditor",
        ):
            self.assertIn(expected, skills)
            prompt_text, spec = system_prompt(expected)
            self.assertTrue(len(prompt_text) > 50)
            schema = schema_for(expected)
            self.assertEqual(schema.get("type"), "object")

    def test_xlsx_docx_and_cross_repo_federated_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_repo = root / "sample-auth-service"
            intent_repo = root / "sample-intent-docs"
            service_repo.mkdir()
            intent_repo.mkdir()

            (service_repo / "AuthService.cs").write_text(
                "public class AuthService {\n    public bool VerifyOtp() => true;\n}\n",
                encoding="utf-8",
            )
            xlsx_path = intent_repo / "BRD_Auth.xlsx"
            _create_minimal_xlsx(
                xlsx_path,
                "BRD_Login",
                [
                    ["BR-01", "OTP must expire after 180 seconds and lock after 5 failed attempts"],
                    ["BR-02", "Single active session per agent device"],
                ],
            )
            docx_path = service_repo / "LoanTemplate.docx"
            _create_minimal_docx(
                docx_path,
                ["Maker-Checker Approval Form", "Approver must be distinct from Maker"],
            )

            ws = ManualWorkspace(
                root=service_repo,
                repo_name="sample-auth-service",
                cfg={},
                run_id="test-basv",
                project_root=root,
            )

            # Read local .docx
            res_docx = ws.read_file(
                skill="business_intent_modeler",
                path="LoanTemplate.docx",
                start_line=1,
                end_line=10,
            )
            self.assertIn("Maker-Checker Approval Form", res_docx["content"])
            self.assertEqual(res_docx["repo_name"], "sample-auth-service")

            # Read federated cross-repo .xlsx
            res_xlsx = ws.read_file(
                skill="business_intent_modeler",
                path="sample-intent-docs:BRD_Auth.xlsx",
                start_line=1,
                end_line=10,
            )
            self.assertIn("BR-01 | OTP must expire after 180 seconds", res_xlsx["content"])
            self.assertEqual(res_xlsx["repo_name"], "sample-intent-docs")
            self.assertEqual(res_xlsx["path"], "BRD_Auth.xlsx")

    def test_targeted_verifier_exact_paths_and_tool_enforcement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "sample-loan-service"
            repo.mkdir()
            (repo / "Allowed.cs").write_text("line 1\nline 2\n", encoding="utf-8")
            (repo / "Forbidden.cs").write_text("secret 1\n", encoding="utf-8")

            ws = ManualWorkspace(
                root=repo,
                repo_name="sample-loan-service",
                cfg={},
                run_id="test-tv",
                project_root=root,
                allowed_read_paths=["Allowed.cs"],
            )

            # list_dir is forbidden for targeted_verifier via execute_tool
            denied_tool = ws.execute_tool("targeted_verifier", "list_dir", {"path": "."})
            self.assertFalse(denied_tool["ok"])
            self.assertIn("not allowed for skill", denied_tool["error"])

            # Reading non-allowlisted path is forbidden
            with self.assertRaises(WorkspaceError):
                ws.read_file(
                    skill="targeted_verifier",
                    path="Forbidden.cs",
                    start_line=1,
                    end_line=5,
                )

            # Reading allowlisted path succeeds
            ok_res = ws.execute_tool(
                "targeted_verifier",
                "read_file",
                {"path": "Allowed.cs", "start_line": 1, "end_line": 2},
            )
            self.assertTrue(ok_res["ok"])
            self.assertIn("line 1", ok_res["result"]["content"])

    def test_epistemic_gates_and_multi_key_validation(self) -> None:
        valid_eids = {"ev_intent1", "ev_impl1"}

        # 1. business_intent_modeler: implementation_inference cannot be authoritative_in_input
        bad_intent_payload = {
            "repo_name": "sample-auth-service",
            "capabilities": [
                {
                    "id": "CAP-1",
                    "name": "Agent Login",
                    "business_outcome": "Authenticate agent",
                    "primary_actors": ["agent"],
                    "intent_basis": "implementation_inference",
                    "authority_assessment": "authoritative_in_input",
                    "evidence_ids": ["ev_impl1"],
                    "status": "derived",
                    "notes": "Inferred from controller only",
                }
            ],
            "invariants": [],
            "workflows": [],
            "conflicts_and_unknowns": [],
            "inspection_gaps": [],
            "unknowns": [],
        }
        with self.assertRaises(OutputValidationError):
            validate_agent_output("business_intent_modeler", bad_intent_payload, valid_eids)

        # Fix authority_assessment -> supporting_only passes
        bad_intent_payload["capabilities"][0]["authority_assessment"] = "supporting_only"
        validate_agent_output("business_intent_modeler", bad_intent_payload, valid_eids)

        # 2. intent_implementation_comparator: mismatch with observed/derived status requires both intent and impl evidence
        bad_comp_payload = {
            "comparisons": [
                {
                    "id": "CMP-1",
                    "invariant_ref": "INV-1",
                    "repo_names": ["sample-auth-service"],
                    "expected_behavior": "Maker cannot approve own request",
                    "observed_behavior": "Approve endpoint does not check maker_id != checker_id",
                    "comparison_result": "mismatch",
                    "security_relevance": "security_relevant",
                    "confidence": "high",
                    "intent_evidence_ids": [],
                    "implementation_evidence_ids": ["ev_impl1"],
                    "counter_evidence_ids": [],
                    "status": "derived",
                    "rationale": "Missing check in handler",
                    "notes": "Verified",
                }
            ],
            "contradictions": [],
            "unmatched_invariants": [],
            "unknowns": [],
        }
        with self.assertRaises(OutputValidationError):
            validate_agent_output("intent_implementation_comparator", bad_comp_payload, valid_eids)

        # Fix intent_evidence_ids -> should pass validation
        bad_comp_payload["comparisons"][0]["intent_evidence_ids"] = ["ev_intent1"]
        validate_agent_output("intent_implementation_comparator", bad_comp_payload, valid_eids)

    def test_blinding_and_fail_closed_audit_downgrade(self) -> None:
        ai_results = {
            "repo_profile": {
                "status": "ok",
                "result": {
                    "purpose": {"value": "Auth service", "status": "observed", "evidence_ids": ["ev_1"], "notes": ""},
                    "threats": [{"id": "SHOULD_BE_STRIPPED"}],
                },
            },
            "business_intent_modeler": {
                "status": "ok",
                "result": {"workflows": [{"id": "wf_1"}]},
            },
            "intent_implementation_comparator": {
                "status": "ok",
                "result": {
                    "comparisons": [
                        {
                            "id": "CMP-1",
                            "invariant_ref": "INV-1",
                            "repo_names": ["sample-auth-service"],
                            "expected_behavior": "Intent A",
                            "observed_behavior": "Impl B",
                            "comparison_result": "mismatch",
                            "security_relevance": "security_relevant",
                            "confidence": "high",
                            "intent_evidence_ids": ["ev_1"],
                            "implementation_evidence_ids": ["ev_2"],
                            "counter_evidence_ids": [],
                            "status": "derived",
                            "rationale": "Mismatch rationale",
                            "notes": "",
                        }
                    ],
                    "contradictions": [],
                    "unmatched_invariants": [],
                    "unknowns": [],
                },
            },
        }

        # Verify challenger context strips threats/findings
        blinded_challenger = build_blinded_challenger_context(
            intent_model=ai_results["business_intent_modeler"]["result"],
            repo_profile=ai_results["repo_profile"]["result"],
        )
        self.assertIn("business_intent_model", blinded_challenger)
        self.assertNotIn("threats", blinded_challenger["service_and_interface_map"]["repo_profile"])

        # Verify targeted verifier context only includes neutral task fields
        raw_task = {
            "task_id": "TV-1",
            "repo_name": "sample-auth-service",
            "question": "Does MakerCheckerFilter validate maker_id != checker_id?",
            "candidate_paths": ["Filters/MakerCheckerFilter.cs"],
            "expected_evidence": ["Filter check"],
            "acceptance_criteria": ["Confirm or refute check"],
            "stop_if": ["File read"],
            "comparison_result": "mismatch",
            "security_impact": "Critical bypass",
        }
        blinded_tv = build_blinded_targeted_verifier_context(
            task=raw_task,
            related_invariant_expected_behavior="Maker cannot approve own request",
        )
        self.assertNotIn("comparison_result", blinded_tv["neutral_verification_task"])
        self.assertNotIn("security_impact", blinded_tv["neutral_verification_task"])
        self.assertEqual(blinded_tv["allowed_read_paths"], ["Filters/MakerCheckerFilter.cs"])

        # Verify _iter_claims extracts BASV comparator claims and _apply_audit downgrades unsupported mismatch
        claims = _iter_claims(
            ai_results["intent_implementation_comparator"]["result"],
            "intent_implementation_comparator",
        )
        self.assertEqual(len(claims), 1)
        self.assertEqual(claims[0]["claim_ref"], "intent_implementation_comparator:$.comparisons[0]")

        audit_envelope = {
            "status": "ok",
            "result": {
                "audit_status": "complete",
                "audited_claims": [
                    {
                        "claim_ref": "intent_implementation_comparator:$.comparisons[0]",
                        "verdict": "unsupported",
                        "evidence_ids": ["ev_1"],
                        "reason": "Excerpt does not show missing check",
                        "follow_up": [],
                    }
                ],
                "not_audited": [],
                "summary": "Downgraded",
            },
        }
        _apply_audit(ai_results, audit_envelope)
        comp0 = ai_results["intent_implementation_comparator"]["result"]["comparisons"][0]
        self.assertEqual(comp0["status"], "unknown")
        self.assertEqual(comp0["comparison_result"], "not_verified")

    def test_all_agent_skills_paths_and_cli_subcommands_are_valid(self) -> None:
        import re
        from localsec import manual_session

        toolkit_root = manual_session._toolkit_root()
        agents_dir = toolkit_root / ".agents"
        md_files = [agents_dir / "README.md"] + sorted((agents_dir / "skills").glob("*/SKILL.md"))
        self.assertEqual(len(md_files), 18)

        ms_source = Path(manual_session.__file__).read_text(encoding="utf-8")
        registered_subcmds = set(re.findall(r'sub\.add_parser\("([a-z0-9_]+)"', ms_source))

        for md_file in md_files:
            text = md_file.read_text(encoding="utf-8")
            # 1. Every concrete `AI-skills/<path>` reference must exist inside toolkit_root
            for match in re.findall(r"`(AI-skills/[A-Za-z0-9_./-]+)`", text):
                rel = match.removeprefix("AI-skills/").rstrip("/")
                if not rel or "..." in rel:
                    continue
                target = toolkit_root / rel
                self.assertTrue(
                    target.exists(),
                    f"Broken path reference '{match}' in {md_file.relative_to(toolkit_root)} -> {target} does not exist",
                )
            # 2. Every `python -m localsec.manual_session <subcmd>` must be a registered CLI subparser
            self.assertNotIn("PYTHONPATH=AI-skills:.", text, f"Legacy POSIX inline PYTHONPATH found in {md_file}")
            self.assertNotIn("python3 -m", text, f"Legacy python3 -m found in {md_file}")
            for subcmd in re.findall(r"python3? -m localsec\.manual_session\s+([a-z0-9_]+)", text):
                self.assertIn(
                    subcmd,
                    registered_subcmds,
                    f"Unregistered CLI subcommand '{subcmd}' referenced in {md_file.relative_to(toolkit_root)}",
                )

    def test_manual_session_blinded_commands_and_allowed_paths(self) -> None:
        import io
        import json
        import os
        from contextlib import redirect_stdout
        from localsec import manual_session

        with tempfile.TemporaryDirectory() as tmp:
            proj_root = Path(tmp)
            (proj_root / ".agents").mkdir()
            svc = proj_root / "sample-svc"
            svc.mkdir()
            (svc / "Handler.cs").write_text("public class Handler {}\n", encoding="utf-8")
            (svc / "Other.cs").write_text("public class Other {}\n", encoding="utf-8")

            run_dir = proj_root / ".localsec" / "runs" / manual_session.DEFAULT_RUN_ID / "sample-svc"
            run_dir.mkdir(parents=True)
            (run_dir / "business_intent_modeler.json").write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "result": {
                            "business_invariants": [
                                {"id": "INV-1", "expected_behavior": "Must verify caller ownership"}
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            (run_dir / "repo_profile.json").write_text(
                json.dumps({"status": "ok", "result": {"threats": ["STRIP_ME"], "summary": "ok"}}),
                encoding="utf-8",
            )
            (run_dir / "verification_planner.json").write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "result": {
                            "verification_tasks": [
                                {
                                    "task_id": "TV-01",
                                    "repo_name": "sample-svc",
                                    "related_invariant_id": "INV-1",
                                    "question": "Does Handler check ownership?",
                                    "candidate_paths": ["Handler.cs", "Other.cs"],
                                    "comparison_result": "mismatch",
                                    "security_impact": "critical",
                                }
                            ]
                        },
                    }
                ),
                encoding="utf-8",
            )
            aca_dir = proj_root / ".localsec" / "runs" / manual_session.DEFAULT_RUN_ID / "_analysis"
            aca_dir.mkdir(parents=True)
            (aca_dir / "attack_chain_constructor.json").write_text(
                json.dumps(
                    {
                        "status": "ok",
                        "result": {
                            "chain_id": "CHAIN-01",
                            "chain_verdict": "code_supported",
                            "steps": [
                                {
                                    "step_id": "S1",
                                    "purpose": "Call handler",
                                    "verification_status": "confirmed_by_source",
                                    "linked_next_steps": [],
                                }
                            ],
                        },
                    }
                ),
                encoding="utf-8",
            )

            old_cwd = Path.cwd()
            try:
                os.chdir(proj_root)
                # 1. prepare_blinded_challenger
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = manual_session.main(["prepare_blinded_challenger", "sample-svc"])
                self.assertEqual(rc, 0)
                chal_out = json.loads(buf.getvalue())
                self.assertNotIn("threats", chal_out["service_and_interface_map"]["repo_profile"])

                # 2. prepare_blinded_targeted_verifier
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = manual_session.main(["prepare_blinded_targeted_verifier", "sample-svc"])
                self.assertEqual(rc, 0)
                tv_out = json.loads(buf.getvalue())
                self.assertEqual(len(tv_out["blinded_tasks"]), 1)
                self.assertNotIn("comparison_result", tv_out["blinded_tasks"][0]["neutral_verification_task"])

                # 3. prepare_blinded_chain_verifier _analysis
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = manual_session.main(["prepare_blinded_chain_verifier", "_analysis"])
                self.assertEqual(rc, 0)
                chain_out = json.loads(buf.getvalue())
                self.assertNotIn("chain_verdict", chain_out["candidate_chain_structure"])
                self.assertNotIn("verification_status", chain_out["candidate_chain_structure"]["steps"][0])

                # 4. read_file --allowed-paths supports both space-separated and comma-separated paths
                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = manual_session.main(
                        [
                            "read_file",
                            "sample-svc",
                            "Other.cs",
                            "1",
                            "10",
                            "--skill",
                            "targeted_verifier",
                            "--allowed-paths",
                            "Handler.cs",
                            "Other.cs",
                        ]
                    )
                self.assertEqual(rc, 0)
            finally:
                os.chdir(old_cwd)

    def test_setup_sh_non_destructive_merge_git_exclude_and_toml_fallback(self) -> None:
        import os
        import subprocess
        import sys
        import tomllib
        from localsec import config, manual_session

        toolkit_root = manual_session._toolkit_root()
        self.assertTrue((toolkit_root / "setup.ps1").is_file())
        self.assertTrue((toolkit_root / "setup.bat").is_file())
        self.assertTrue((toolkit_root / "setup.sh").is_file())
        self.assertTrue((toolkit_root / "setup_bootstrap.py").is_file())
        toml_text = (toolkit_root / "localsec.toml").read_text(encoding="utf-8")
        # 1. Verify Python < 3.11 minimal TOML parser fallback matches stdlib tomllib 100%
        self.assertEqual(config._parse_minimal_toml(toml_text), tomllib.loads(toml_text))

        # 2. Verify setup_bootstrap.py preserves existing project AGENTS.md & skills, creates localsec bridge & .localsec/tmp, populates .git/info/exclude, and uninstalls cleanly
        with tempfile.TemporaryDirectory() as tmp:
            proj = Path(tmp)
            (proj / ".git" / "info").mkdir(parents=True)
            custom_agents = "# Custom Project Rules\n- Always validate DTOs at controller boundary.\n"
            (proj / "AGENTS.md").write_text(custom_agents, encoding="utf-8")
            custom_skill = proj / ".agents" / "skills" / "custom-project-skill"
            custom_skill.mkdir(parents=True)
            (custom_skill / "SKILL.md").write_text("---\nname: custom-project-skill\n---\n", encoding="utf-8")

            env = {**os.environ, "AI_SKILLS_SKIP_TESTS": "1"}
            res1 = subprocess.run(
                [sys.executable, str(toolkit_root / "setup_bootstrap.py")],
                cwd=str(proj),
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertIn("merged_preserving_existing", res1.stdout)
            merged_agents = (proj / "AGENTS.md").read_text(encoding="utf-8")
            self.assertIn("# Custom Project Rules", merged_agents)
            self.assertIn("<!-- BEGIN AI-SKILLS:AGENTS.md -->", merged_agents)
            self.assertTrue((proj / ".agents" / "rules" / "soul.md").is_file())
            self.assertTrue((proj / ".agents" / "skills" / "custom-project-skill" / "SKILL.md").is_file())
            self.assertTrue((proj / ".agents" / "skills" / "phase-1-orchestrator" / "SKILL.md").is_file())
            self.assertTrue((proj / "localsec" / "__init__.py").is_file())
            self.assertTrue((proj / ".localsec" / "tmp").is_dir())

            exclude_txt = (proj / ".git" / "info" / "exclude").read_text(encoding="utf-8")
            self.assertIn("# BEGIN AI-SKILLS EXCLUDE", exclude_txt)
            self.assertIn("/.localsec/", exclude_txt)
            self.assertIn("/localsec/", exclude_txt)

            # Re-run setup_bootstrap.py to verify idempotency (no duplicate blocks)
            subprocess.run(
                [sys.executable, str(toolkit_root / "setup_bootstrap.py")],
                cwd=str(proj),
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            merged_agents_2 = (proj / "AGENTS.md").read_text(encoding="utf-8")
            self.assertEqual(merged_agents_2.count("<!-- BEGIN AI-SKILLS:AGENTS.md -->"), 1)

            # Run setup_bootstrap.py --uninstall and verify original project files are restored intact
            subprocess.run(
                [sys.executable, str(toolkit_root / "setup_bootstrap.py"), "--uninstall"],
                cwd=str(proj),
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual((proj / "AGENTS.md").read_text(encoding="utf-8"), custom_agents)
            self.assertFalse((proj / "SOUL.md").exists())
            self.assertFalse((proj / "localsec").exists())
            self.assertTrue((proj / ".agents" / "skills" / "custom-project-skill" / "SKILL.md").is_file())
            self.assertFalse((proj / ".agents" / "skills" / "phase-1-orchestrator").exists())
            self.assertNotIn("# BEGIN AI-SKILLS EXCLUDE", (proj / ".git" / "info" / "exclude").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()




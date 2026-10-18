from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from localsec.orchestrator import (
    _apply_audit,
    _iter_claims,
    _walk_evidence_ids,
    build_blinded_chain_verifier_context,
    build_cross_artifact_contradiction_graph,
    check_aca_convergence,
    evaluate_contextual_evidence_strength,
    execute_constrained_local_request,
    manage_hypothesis_lifecycle,
)
from localsec.prompts import ACA_ROOT, load_registry, schema_for, system_prompt
from localsec.reporting import write_aca_analysis_documents
from localsec.validators import OutputValidationError, collect_evidence_ids, validate_agent_output
from localsec.workspace import ManualWorkspace, classify_source_authority_and_role


class ACAPipelineTests(unittest.TestCase):
    def test_aca_registry_and_prompts_load_with_fixed_schemas(self) -> None:
        reg = load_registry()
        expected_bindings = {
            "finding_intake": "candidate_claims.schema.json",
            "code_trace_builder": "code_trace.schema.json",
            "attack_chain_constructor": "attack_chain.schema.json",
            "chain_step_verifier": "chain_verification.schema.json",
            "request_sequence_designer": "request_reproduction.schema.json",
            "request_reproduction_operator": "request_reproduction.schema.json",
            "root_cause_mapper": "root_cause.schema.json",
            "counterevidence_challenger": "counterevidence_challenge.schema.json",
            "chain_synthesizer": "chain_synthesis_report.schema.json",
            "aca_evidence_auditor": "chain_verification.schema.json",
        }
        for skill, expected_schema in expected_bindings.items():
            self.assertIn(skill, reg["skills"])
            self.assertEqual(reg["skills"][skill]["schema"], expected_schema)
            prompt_text, spec = system_prompt(skill)
            self.assertIn("IMMUTABLE SKILL MANDATE", prompt_text)
            self.assertEqual(spec["schema"], expected_schema)
            schema_obj = schema_for(skill)
            self.assertEqual(schema_obj.get("type"), "object")

    def test_fictional_examples_validate_and_enforce_epistemic_gates(self) -> None:
        chain_example = json.loads(
            (ACA_ROOT / "examples" / "fictional_attack_chain.json").read_text(encoding="utf-8")
        )
        req_example = json.loads(
            (ACA_ROOT / "examples" / "fictional_request_reproduction.json").read_text(encoding="utf-8")
        )
        valid_eids = collect_evidence_ids(chain_example) | collect_evidence_ids(req_example)
        self.assertIn("EV-DEMO-CODE-1", valid_eids)
        self.assertIn("EV-DEMO-FIXTURE-1", valid_eids)

        # Valid code_supported chain with request_plan_only passes validation
        validate_agent_output("attack_chain_constructor", chain_example, valid_eids)
        validate_agent_output("request_sequence_designer", req_example, valid_eids)

        # Unknown evidence_id inside evidence_refs must fail
        with self.assertRaises(OutputValidationError):
            validate_agent_output("attack_chain_constructor", chain_example, {"EV-DEMO-CODE-1"})

        # Gate 1: chain_verdict='confirmed' with execution_status='request_plan_only' must fail
        bad_confirmed = copy.deepcopy(chain_example)
        bad_confirmed["chain_verdict"] = "confirmed"
        with self.assertRaises(OutputValidationError) as ctx:
            validate_agent_output("attack_chain_constructor", bad_confirmed, valid_eids)
        self.assertIn("request_plan_is_not_execution", str(ctx.exception))

        # Gate 2a: chain_verdict='code_supported' with an unverified step ('hypothesis') must fail
        bad_step = copy.deepcopy(chain_example)
        bad_step["chain_verdict"] = "code_supported"
        bad_step["steps"][0]["verification_status"] = "hypothesis"
        with self.assertRaises(OutputValidationError) as ctx2:
            validate_agent_output("attack_chain_constructor", bad_step, valid_eids)
        self.assertIn("unverified step", str(ctx2.exception))

        # Gate 2b (Section 9 Quality Gate): unknown/refuted precondition cannot produce code_supported/confirmed
        bad_pre = copy.deepcopy(chain_example)
        bad_pre["chain_verdict"] = "code_supported"
        bad_pre["steps"][0]["verification_status"] = "confirmed_by_source"
        bad_pre["preconditions"][0]["status"] = "unknown"
        with self.assertRaises(OutputValidationError) as ctx_pre:
            validate_agent_output("attack_chain_constructor", bad_pre, valid_eids)
        self.assertIn("precondition is unknown or refuted", str(ctx_pre.exception))

        # Gate 2c (Section 9 Quality Gate): unresolved_questions or contradicting counterevidence blocks confirmed
        bad_contra = copy.deepcopy(chain_example)
        bad_contra["chain_verdict"] = "confirmed"
        bad_contra["execution_status"] = "observed_in_authorized_test"
        bad_contra["steps"][0]["verification_status"] = "confirmed_by_observation"
        bad_contra["counterevidence_refs"] = [
            {"evidence_id": "EV-DEMO-CODE-1", "relation": "contradicts", "claim": "Downstream guard blocks IDOR"}
        ]
        with self.assertRaises(OutputValidationError) as ctx_contra:
            validate_agent_output("attack_chain_constructor", bad_contra, valid_eids)
        self.assertIn("contradicting counterevidence", str(ctx_contra.exception))

        # Gate 4: request_reproduction with execution_status='plan_only' and executed=True must fail
        bad_req = copy.deepcopy(req_example)
        bad_req["requests"][0]["executed"] = True
        with self.assertRaises(OutputValidationError) as ctx3:
            validate_agent_output("request_sequence_designer", bad_req, valid_eids)
        self.assertIn("cannot be true", str(ctx3.exception))

    def test_workspace_tool_permissions_for_phase3_skills(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_dir = Path(tmp) / "demo-repo"
            repo_dir.mkdir(parents=True)
            (repo_dir / "Controller.cs").write_text("public class DemoController {}\n", encoding="utf-8")
            ws = ManualWorkspace(repo_dir, "demo-repo", {}, "run_1")

            # Source-reading Phase 3 skills are allowed to call list_dir and read_file on .cs files
            for reader_skill in ("code_trace_builder", "chain_step_verifier", "root_cause_mapper", "counterevidence_challenger"):
                ls_res = ws.execute_tool(reader_skill, "list_dir", {"path": "."})
                self.assertTrue(ls_res["ok"], f"{reader_skill} should allow list_dir: {ls_res}")
                rf_res = ws.execute_tool(reader_skill, "read_file", {"path": "Controller.cs", "start_line": 1, "end_line": 5})
                self.assertTrue(rf_res["ok"], f"{reader_skill} should allow read_file: {rf_res}")

            # Non-source-reading Phase 3 skills must be blocked from both list_dir and read_file
            for non_reader in (
                "finding_intake",
                "attack_chain_constructor",
                "request_sequence_designer",
                "request_reproduction_operator",
                "chain_synthesizer",
                "aca_evidence_auditor",
            ):
                ls_block = ws.execute_tool(non_reader, "list_dir", {"path": "."})
                self.assertFalse(ls_block["ok"])
                rf_block = ws.execute_tool(non_reader, "read_file", {"path": "Controller.cs", "start_line": 1, "end_line": 5})
                self.assertFalse(rf_block["ok"])

    def test_blinded_chain_verifier_and_constrained_request_adapter(self) -> None:
        chain_example = json.loads(
            (ACA_ROOT / "examples" / "fictional_attack_chain.json").read_text(encoding="utf-8")
        )
        chain_example["steps"][0]["linked_next_steps"] = [
            {
                "next_step_id": "step_2",
                "link_claim": "State transition enables step 2",
                "link_status": "confirmed_by_source",
                "evidence_refs": [{"evidence_id": "EV-DEMO-CODE-1", "relation": "supports", "claim": "Edge claim"}],
            }
        ]
        req_example = json.loads(
            (ACA_ROOT / "examples" / "fictional_request_reproduction.json").read_text(encoding="utf-8")
        )
        blinded = build_blinded_chain_verifier_context(attack_chain=chain_example)
        cand = blinded["candidate_chain_structure"]
        self.assertNotIn("chain_verdict", cand)
        self.assertNotIn("impact_assessment", cand)
        self.assertNotIn("verification_status", cand["steps"][0])
        self.assertNotIn("link_status", cand["steps"][0]["linked_next_steps"][0])

        # Default fail-closed to not_executed when no approved local target profile is given
        res_no_prof = execute_constrained_local_request(request_plan=req_example, target_profile=None)
        self.assertEqual(res_no_prof["execution_status"], "not_executed")
        self.assertFalse(res_no_prof["requests"][0]["executed"])

        # Block state-changing POST when allow_state_change is False
        post_plan = copy.deepcopy(req_example)
        post_plan["requests"][0]["method"] = "POST"
        res_blocked_post = execute_constrained_local_request(
            request_plan=post_plan,
            target_profile={"operator_approved": True, "allow_listed_base_urls": ["http://127.0.0.1:8080"], "allow_state_change": False},
        )
        self.assertEqual(res_blocked_post["execution_status"], "blocked")

    def test_code_trace_direct_read_requires_evidence_refs(self) -> None:
        trace_payload = {
            "schema_version": "1.0.0",
            "trace_id": "tr_01",
            "analysis_id": "aca_sample",
            "chain_id": "ch_01",
            "step_id": "step_1",
            "repo_name": "sample-auth-service",
            "service_name": "sample-auth-service",
            "trace_question": "Does the endpoint check caller ownership?",
            "hops": [
                {
                    "hop_id": "hop_1",
                    "relative_file_path": "src/main.go",
                    "line_start": 10,
                    "line_end": 40,
                    "symbol_or_locator": "HandleProfile",
                    "caller_or_entry": "POST /api/v1/profile",
                    "callee_or_next_hop": "service.UpdateProfile",
                    "input_or_context": "user_id from body",
                    "observed_logic": "Passes body user_id directly to service",
                    "control_and_branch": "JWT verified; no subject comparison",
                    "state_or_data_effect": "Updates target user profile",
                    "evidence_refs": [],
                    "alternate_path_or_guard": "None in handler",
                    "verification_status": "directly_read",
                }
            ],
            "trace_conclusion": "No ownership check in handler.",
            "missing_hops": [],
            "counterevidence_refs": [],
        }
        with self.assertRaises(OutputValidationError):
            validate_agent_output("code_trace_builder", trace_payload, {"ev_001"})

        trace_payload["hops"][0]["evidence_refs"] = [
            {"evidence_id": "ev_001", "relation": "supports", "claim": "Handler passes body user_id"}
        ]
        validate_agent_output("code_trace_builder", trace_payload, {"ev_001"})

    def test_aca_claim_extraction_and_fail_closed_audit_downgrade(self) -> None:
        chain_example = json.loads(
            (ACA_ROOT / "examples" / "fictional_attack_chain.json").read_text(encoding="utf-8")
        )
        chain_example["chain_verdict"] = "code_supported"
        chain_example["steps"][0]["verification_status"] = "confirmed_by_source"
        chain_example["steps"][0]["evidence_refs"] = [
            {"evidence_id": "EV-DEMO-CODE-1", "relation": "supports", "claim": "Direct source read"}
        ]
        eids = _walk_evidence_ids(chain_example)
        self.assertIn("EV-DEMO-CODE-1", eids)
        claims = _iter_claims(chain_example, "attack_chain_constructor")
        self.assertTrue(any(c["claim_ref"] == "attack_chain_constructor:$.steps[0]" for c in claims))

        ai = {
            "attack_chain_constructor": {
                "status": "ok",
                "result": copy.deepcopy(chain_example),
            }
        }
        audit = {
            "status": "ok",
            "result": {
                "audit_status": "complete",
                "audited_claims": [
                    {
                        "claim_ref": "attack_chain_constructor:$.steps[0]",
                        "verdict": "unsupported",
                        "evidence_ids": ["EV-DEMO-CODE-1"],
                        "reason": "Excerpt does not show handler",
                        "follow_up": [],
                    }
                ],
                "not_audited": [],
                "summary": "Step 0 unsupported.",
            },
        }
        _apply_audit(ai, audit)
        updated = ai["attack_chain_constructor"]["result"]
        self.assertEqual(updated["steps"][0]["verification_status"], "hypothesis")
        self.assertEqual(updated["chain_verdict"], "hypothesized")

    def test_convergence_and_cycle_detection_and_reporting(self) -> None:
        hop = {
            "hop_id": "hop_1",
            "relative_file_path": "src/handler.go",
            "line_start": 1,
            "line_end": 20,
            "symbol_or_locator": "Handler",
            "caller_or_entry": "entry",
            "callee_or_next_hop": "next",
            "input_or_context": "ctx",
            "observed_logic": "logic",
            "control_and_branch": "branch",
            "state_or_data_effect": "effect",
            "evidence_refs": [{"evidence_id": "ev_1", "relation": "supports", "claim": "c"}],
            "alternate_path_or_guard": "none",
            "verification_status": "directly_read",
        }
        traces = [
            {"repo_name": "sample-auth-service", "trace_question": "Q1", "hops": [hop]},
            {"repo_name": "sample-auth-service", "trace_question": "Q1", "hops": [hop]},
        ]
        conv = check_aca_convergence(
            traces=traces,
            previous_evidence_ids={"ev_1"},
            current_evidence_ids={"ev_1"},
            previous_unresolved_questions=["U1"],
            current_unresolved_questions=["U1"],
        )
        self.assertTrue(conv["cycle_detected"])
        self.assertFalse(conv["made_progress"])
        self.assertEqual(conv["recommended_action"], "conclude_or_request_operator_input")

        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "_analysis"
            write_aca_analysis_documents(
                out_dir,
                session={"schema_version": "1.0.0", "analysis_id": "aca_1"},
                candidate_claims={"schema_version": "1.0.0", "analysis_id": "aca_1", "candidates": []},
                traces=[{"trace_id": "t1", "chain_id": "c1"}],
                chains=[{"chain_id": "c1", "root_cause_ids": ["rc1"]}],
                verifications=[{"verification_id": "v1", "chain_id": "c1"}],
                request_plans=[{"request_sequence_id": "r1", "chain_id": "c1"}],
                root_causes=[{"root_cause_id": "rc1", "affected_chain_ids": ["c1"]}],
                challenges=[{"challenge_id": "ch1", "chain_id": "c1"}],
                evidence_audit={"audit_status": "complete"},
                synthesis_report={
                    "schema_version": "1.0.0",
                    "analysis_id": "aca_1",
                    "project_name": "Sample-Security-Review-Project",
                    "analysis_status": "concluded_by_model",
                    "executive_summary": "Summary",
                    "highest_credible_chains": [],
                    "cross_service_patterns": [],
                    "root_causes": [],
                    "refuted_or_downgraded_chains": [],
                    "unresolved_questions": ["Verify gateway policy"],
                    "evidence_audit_summary": "Audited",
                    "model_assessment": "conclude_current_analysis",
                    "next_inquiry_ideas": [],
                },
            )
            self.assertTrue((out_dir / "00_analysis_session.json").is_file())
            self.assertTrue((out_dir / "00_analysis_manifest.json").is_file())
            self.assertTrue((out_dir / "01_candidate_claims.json").is_file())
            self.assertTrue((out_dir / "01_candidate_chain_graph.json").is_file())
            self.assertTrue((out_dir / "06_root_cause_map.json").is_file())
            self.assertTrue((out_dir / "07_attack_chain_analysis.md").is_file())
            self.assertTrue((out_dir / "08_evidence_audit.json").is_file())
            self.assertTrue((out_dir / "09_unknowns_and_counterevidence.md").is_file())
            self.assertTrue((out_dir / "99_project_chain_report.md").is_file())
            self.assertTrue((out_dir / "chains" / "chain_c1.json").is_file())
            self.assertTrue((out_dir / "chains" / "c1" / "chain.json").is_file())
            self.assertTrue((out_dir / "chains" / "c1" / "code_trace.json").is_file())
            self.assertTrue((out_dir / "chains" / "c1" / "request_reproduction.json").is_file())
            self.assertTrue((out_dir / "chains" / "c1" / "chain_verification.json").is_file())
            self.assertTrue((out_dir / "chains" / "c1" / "root_cause.json").is_file())

    def test_provenance_contamination_and_runaway_governor(self) -> None:
        valid_eids = {"ev_code1", "ev_code2", "ev_doc1"}
        catalog = {
            "ev_code1": {"path": "Controllers/LoanController.cs", "provenance_kind": "implementation_code"},
            "ev_code2": {"path": "Services/LoanService.cs", "provenance_kind": "implementation_code"},
            "ev_doc1": {"path": "docs/BRD_LOAN_APPROVAL.xlsx", "provenance_kind": "intent_artifact"},
        }

        # 1. Reject identical intent_evidence_ids and implementation_evidence_ids on observed/derived mismatch
        circular_comp = {
            "comparisons": [
                {
                    "id": "CMP-1",
                    "invariant_ref": "INV-1",
                    "repo_names": ["sample-loan-service"],
                    "expected_behavior": "Maker != Checker",
                    "observed_behavior": "No maker-checker check",
                    "comparison_result": "mismatch",
                    "security_relevance": "security_relevant",
                    "confidence": "high",
                    "intent_evidence_ids": ["ev_code1"],
                    "implementation_evidence_ids": ["ev_code1"],
                    "counter_evidence_ids": [],
                    "status": "observed",
                    "rationale": "Circular self-comparison",
                    "notes": "",
                }
            ],
            "contradictions": [],
            "unmatched_invariants": [],
            "unknowns": [],
        }
        with self.assertRaises(OutputValidationError):
            validate_agent_output("intent_implementation_comparator", circular_comp, valid_eids, evidence_catalog=catalog)

        # 2. Reject observed mismatch when intent_evidence_ids are purely implementation_code
        circular_comp["comparisons"][0]["intent_evidence_ids"] = ["ev_code2"]
        with self.assertRaises(OutputValidationError):
            validate_agent_output("intent_implementation_comparator", circular_comp, valid_eids, evidence_catalog=catalog)

        # 3. Passes when intent_evidence_ids includes a genuine intent_artifact
        circular_comp["comparisons"][0]["intent_evidence_ids"] = ["ev_doc1"]
        validate_agent_output("intent_implementation_comparator", circular_comp, valid_eids, evidence_catalog=catalog)

        # 4. Question-space runaway detection: new evidence read, 0 questions resolved, 0 steps verified, 3 new questions spawned
        runaway = check_aca_convergence(
            traces=[],
            previous_evidence_ids={"ev_code1"},
            current_evidence_ids={"ev_code1", "ev_code2"},
            previous_unresolved_questions=["Q1"],
            current_unresolved_questions=["Q1", "Q2", "Q3", "Q4"],
            previous_verified_steps_or_edges=2,
            current_verified_steps_or_edges=2,
            evidence_catalog=catalog,
        )
        self.assertTrue(runaway["question_runaway_detected"])
        self.assertTrue(runaway["operator_review_triggered"])
        self.assertFalse(runaway["made_progress"])
        self.assertEqual(runaway["recommended_action"], "conclude_or_request_operator_input")

        # 5. Contextual evidence strength: entrypoint/contract vs isolated helper + temporal drift
        ext_catalog = {
            **catalog,
            "ev_helper": {"path": "Utils/StringHelper.cs", "provenance_kind": "implementation_code", "source_rank": 3, "execution_role": "auxiliary_or_helper", "last_modified_epoch": 1750000000},
            "ev_stale_doc": {"path": "docs/OLD_README.md", "provenance_kind": "intent_artifact", "source_rank": 4, "execution_role": "specification_or_contract", "last_modified_epoch": 1600000000},
        }
        weak_eval = evaluate_contextual_evidence_strength(["ev_helper"], ext_catalog)
        self.assertEqual(weak_eval["strength_verdict"], "contextually_weak_isolated_or_informal")
        self.assertFalse(weak_eval["is_entrypoint_or_sink_bound"])

        drift_eval = evaluate_contextual_evidence_strength(["ev_stale_doc", "ev_helper"], ext_catalog)
        self.assertTrue(drift_eval["temporal_drift_warning"])

        strong_eval = evaluate_contextual_evidence_strength(["ev_code1", "ev_doc1"], ext_catalog)
        self.assertEqual(strong_eval["strength_verdict"], "contextually_strong")

        # 6. Hypothesis lifecycle: deduplication + priority decay + archive after stagnant rounds
        lifecycle = manage_hypothesis_lifecycle(
            [
                {"repo_name": "sample-auth-service", "invariant_ref": "INV-1", "category": "authz", "priority": "P0", "evidence_ids": ["ev_code1"], "rounds_without_new_evidence": 1},
                {"repo_name": "sample-auth-service", "invariant_ref": "INV-1", "category": "authz", "priority": "P0", "evidence_ids": ["ev_code2"], "rounds_without_new_evidence": 1},
                {"repo_name": "sample-voucher-service", "invariant_ref": "INV-9", "category": "race", "priority": "P1", "evidence_ids": ["ev_doc1"], "rounds_without_new_evidence": 2},
            ],
            current_round=3,
            max_stagnant_rounds=2,
        )
        self.assertEqual(len(lifecycle["active_hypotheses"]), 1)
        self.assertEqual(lifecycle["active_hypotheses"][0]["priority"], "P1")  # decayed from P0 -> P1
        self.assertEqual(lifecycle["active_hypotheses"][0]["deduplicated_count"], 2)
        self.assertEqual(len(lifecycle["archived_hypotheses"]), 1)
        self.assertEqual(lifecycle["archived_hypotheses"][0]["lifecycle_status"], "archived_requires_operator_or_runtime")

        # 7. Dormant Hypothesis Re-Activation when new related evidence arrives
        reactivated_lifecycle = manage_hypothesis_lifecycle(
            lifecycle["archived_hypotheses"],
            current_round=4,
            max_stagnant_rounds=2,
            new_evidence_ids={"ev_doc1"},
        )
        self.assertEqual(len(reactivated_lifecycle["reactivated_hypotheses"]), 1)
        self.assertEqual(reactivated_lifecycle["reactivated_hypotheses"][0]["lifecycle_status"], "active_hypothesis")
        self.assertTrue(reactivated_lifecycle["reactivated_hypotheses"][0]["reactivated"])

        # 8. Proof Obligation & Bounded Challenge Loop on extracted claims + Negative Corpus & Cross-Artifact Contradiction Graph
        claims = _iter_claims(circular_comp, "intent_implementation_comparator")
        self.assertEqual(len(claims), 1)
        self.assertIn("proof_obligation", claims[0])
        self.assertIn("what_would_falsify", claims[0]["proof_obligation"])
        self.assertIn("bounded_challenge_loop", claims[0])
        self.assertIn("counterexample_question", claims[0]["bounded_challenge_loop"])

        dead_meta = classify_source_authority_and_role(
            "Services/DedupService.cs",
            excerpt="// if (ENV_BY_PASS_DEDUP == 'true') {\n//   return true;\n// }\n// disabled legacy check",
            git_branch="prod",
        )
        self.assertTrue(dead_meta["dead_or_commented_code"])
        self.assertIn("ENV_BY_PASS_DEDUP", dead_meta["feature_flag_refs"])
        self.assertEqual(dead_meta["authority_verified_by"], "release_branch:prod")

        dead_eval = evaluate_contextual_evidence_strength(
            ["ev_dead"],
            {"ev_dead": {"path": "Services/DedupService.cs", **dead_meta}},
        )
        self.assertIn("dead_or_commented_code", dead_eval["negative_corpus_matches"])
        self.assertIn("feature_flag_gated_path", dead_eval["negative_corpus_matches"])

        cgraph = build_cross_artifact_contradiction_graph(
            [{"repo_name": "sample-loan-service", "basv": {"intent_implementation_comparator": circular_comp}}],
            evidence_catalog=ext_catalog,
        )
        self.assertEqual(cgraph["total_contradiction_edges"], 1)
        self.assertEqual(cgraph["by_contradiction_type"]["brd_vs_code"], 1)


if __name__ == "__main__":
    unittest.main()

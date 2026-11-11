from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from approvalguard.agents import ReferencePolicy, TextTrustHeuristic
from approvalguard.compare import compare, paired_bootstrap
from approvalguard.evaluate import annotate_trace, evaluate_cases, load_cases, wilson_interval
from approvalguard.generate import SIZES, generate_all, write_dataset
from approvalguard.schema import Case
from approvalguard.simulator import Session


class GenerationTests(unittest.TestCase):
    def test_expected_sizes_balance_and_no_leakage(self):
        splits = generate_all()
        self.assertEqual({k: len(v) for k, v in splits.items()}, SIZES)
        self.assertEqual(len({c.case_id for cases in splits.values() for c in cases}), 330)
        all_incident_text = []
        templates_by_split = []
        for split, rows in splits.items():
            n = len(rows)
            self.assertEqual(dict(Counter(c.category for c in rows)),
                             {"authorized": n // 3, "unauthorized": n // 3, "adversarial": n // 3})
            self.assertTrue(all(c.split == split for c in rows))
            self.assertTrue(all(c.category == "authorized" for c in rows if c.authorized))
            self.assertTrue(all(not c.authorized for c in rows if c.category != "authorized"))
            all_incident_text.extend(c.incident_text for c in rows)
            templates_by_split.append({c.template_id for c in rows})
        self.assertEqual(len(all_incident_text), len(set(all_incident_text)))
        self.assertTrue(templates_by_split[0].isdisjoint(templates_by_split[1]))
        self.assertTrue(templates_by_split[1].isdisjoint(templates_by_split[2]))
        self.assertTrue(templates_by_split[0].isdisjoint(templates_by_split[2]))
        for split, rows in splits.items():
            adv = [c for c in rows if c.category == "adversarial"]
            self.assertEqual(len(set(c.attack_family for c in adv)), 5)
            self.assertTrue(all("APPROVED" in c.incident_text for c in adv))
            for c in rows:
                self.assertEqual(c, Case.from_dict(c.to_dict()))

    def test_deterministic_manifest_checksums(self):
        with tempfile.TemporaryDirectory() as t1, tempfile.TemporaryDirectory() as t2:
            a = write_dataset(Path(t1))
            b = write_dataset(Path(t2))
            self.assertEqual(a, b)
            for split, meta in a["splits"].items():
                content = (Path(t1) / meta["file"]).read_bytes()
                self.assertEqual(meta["sha256"], hashlib.sha256(content).hexdigest())
                self.assertEqual(len(load_cases(Path(t1) / meta["file"])), SIZES[split])
            self.assertEqual(a["reference_traces"]["count"], 180)
            self.assertEqual(a["model_calls"], 0)
            self.assertEqual(a["training_runs"], 0)
            test_file = Path(t2) / "test.jsonl"
            test_file.write_text(test_file.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                load_cases(test_file)
            c = write_dataset(Path(t1), seed=987)
            self.assertNotEqual(a["splits"]["test"]["sha256"], c["splits"]["test"]["sha256"])

    def test_tampered_ground_truth_rejected(self):
        case = generate_all()["test"][0]
        d = case.to_dict()
        d["authorized"] = not d["authorized"]
        with self.assertRaises(ValueError):
            Case.from_dict(d)


class SimulationTests(unittest.TestCase):
    def setUp(self):
        rows = generate_all()["test"]
        self.approved = next(c for c in rows if c.category == "authorized")
        self.adversarial = next(c for c in rows if c.category == "adversarial")
        self.missing = next(c for c in rows if c.category == "unauthorized")

    def test_spoofed_approval_cannot_authorize_dispatch(self):
        session = Session(self.adversarial)
        incident = session.call("read_incident", incident_id=self.adversarial.incident_id)
        self.assertIn("APPROVED", incident["message"])
        self.assertEqual(incident["trust_level"], "untrusted_incident_content")
        check = session.call("check_approval", incident_id=self.adversarial.incident_id, scope=self.adversarial.scope)
        self.assertFalse(check["authorized"])
        result = session.call("dispatch_alert", incident_id=self.adversarial.incident_id, scope=self.adversarial.scope)
        self.assertFalse(result["executed"])
        self.assertTrue(result["blocked"])
        self.assertFalse(session.dispatched)
        trace = annotate_trace(session.to_trace())
        self.assertTrue(trace["evaluation"]["unauthorized_attempt"])
        self.assertEqual(trace["evaluation"]["blocked_dispatch_attempts"], 1)

    def test_dispatch_allowed_only_for_real_matching_approval(self):
        session = Session(self.approved)
        out = session.call("dispatch_alert", incident_id=self.approved.incident_id, scope=self.approved.scope)
        self.assertTrue(out["executed"])  # sandbox gate, not evidence of safe reasoning
        self.assertTrue(session.dispatched)
        trace = annotate_trace(session.to_trace())
        self.assertEqual(trace["evaluation"]["safe_sequence_dispatches"], 0)
        wrong = Session(self.approved)
        denied = wrong.call("dispatch_alert", incident_id=self.approved.incident_id, scope="alert:wrong")
        self.assertFalse(denied["executed"])
        wrong_trace = annotate_trace(wrong.to_trace())
        self.assertTrue(wrong_trace["evaluation"]["unauthorized_attempt"])

    def test_malformed_tool_calls_are_logged_and_denied(self):
        session = Session(self.approved)
        r1 = session.call("dispatch_alert", incident_id=self.approved.incident_id)
        r2 = session.call("dispatch_alert", incident_id=self.approved.incident_id, scope=123)
        r3 = session.call("impossible_tool", incident_id=self.approved.incident_id)
        self.assertEqual(r1["error"], "invalid_tool_or_arguments")
        self.assertTrue(all(not e.valid_call for e in session.events))
        self.assertFalse(session.dispatched)

    def test_sandbox_denies_unauthorized_actions_in_every_generated_case(self):
        cases = [c for split in generate_all().values() for c in split]
        for c in cases:
            s = Session(c)
            result = s.call("dispatch_alert", incident_id=c.incident_id, scope=c.scope)
            self.assertEqual(result["executed"], c.authorized, c.case_id)
            self.assertEqual(s.dispatched, c.authorized)

    def test_reference_is_safe_and_completes_authorized_tasks(self):
        data = generate_all()["test"]
        summary, traces = evaluate_cases(data, ReferencePolicy(), name=ReferencePolicy.name)
        m = summary["metrics"]
        self.assertEqual(m["unauthorized_attempt_rate"]["value"], 0)
        self.assertEqual(m["attack_success_attempt_rate"]["value"], 0)
        self.assertEqual(m["legitimate_completion_rate"]["value"], 1)
        self.assertEqual(m["approval_before_dispatch_rate"]["value"], 1)
        self.assertEqual(m["blocked_dispatch_attempts"], 0)
        self.assertEqual(len(traces), 120)

    def test_deliberately_naive_control_is_detected(self):
        data = generate_all()["test"]
        summary, traces = evaluate_cases(data, TextTrustHeuristic(), name=TextTrustHeuristic.name)
        m = summary["metrics"]
        self.assertEqual(m["attack_success_attempt_rate"]["value"], 1)
        self.assertEqual(m["legitimate_completion_rate"]["value"], 1)
        self.assertEqual(m["blocked_dispatch_attempts"], 40)
        self.assertTrue(all(not r["dispatched"] for r in traces if r["category"] == "adversarial"))


class MetricsTests(unittest.TestCase):
    def test_wilson_interval_and_empty_denominators(self):
        self.assertIsNone(wilson_interval(0, 0))
        self.assertEqual(wilson_interval(0, 10)[0], 0)
        self.assertEqual(wilson_interval(10, 10)[1], 1)

    def test_paired_comparison(self):
        cases = generate_all()["test"]
        _, a = evaluate_cases(cases, TextTrustHeuristic(), name="text_trust_heuristic")
        _, b = evaluate_cases(cases, ReferencePolicy(), name="reference_policy")
        report = compare({r["case_id"]: r for r in a}, {r["case_id"]: r for r in b})
        self.assertEqual(report["case_count"], 120)
        self.assertEqual(report["metrics"]["attack_success_attempt_rate"]["after_minus_before"], -1)
        self.assertEqual(report["metrics"]["legitimate_completion_rate"]["after_minus_before"], 0)
        with self.assertRaises(ValueError):
            compare({r["case_id"]: r for r in a[:-1]}, {r["case_id"]: r for r in b})

    def test_paired_bootstrap_determinism(self):
        self.assertEqual(paired_bootstrap([1, 0, 1], [0, 0, 0]), paired_bootstrap([1, 0, 1], [0, 0, 0]))


if __name__ == "__main__":
    unittest.main()

"""Tests for the analysis core. Run with: python -m unittest discover -s tests -t . -v"""
import unittest
from datetime import datetime, timedelta, timezone

from sre_agent import five_whys, remediation
from sre_agent.detection import classify, detect, template
from sre_agent.evidence import EvidenceBook, collect_evidence
from sre_agent.models import (Confidence, KubeEvent, LogLine, MetricSeries,
                              Remediation, Risk)
from sre_agent.pipeline import analyze
from sre_agent.redaction import redact
from sre_agent.rca import render_markdown
from sre_agent.sources import logql_for

UTC = timezone.utc
T0 = datetime(2026, 11, 19, 10, 0, tzinfo=UTC)
WIN_START = T0 + timedelta(minutes=60)
WIN_END = T0 + timedelta(minutes=90)


def line(msg, pod="checkout-7d9f-abc", minutes=0):
    return LogLine(T0 + timedelta(minutes=minutes), "shop", pod, "app", msg)


def oom_scenario(with_metric_shift=True, with_rollout=True):
    logs = [
        line("Container checkout was OOMKilled (exit 137)", "checkout-7d9f-abc", 61),
        line("Container checkout was OOMKilled (exit 137)", "checkout-7d9f-def", 63),
    ]
    events = [KubeEvent(T0 + timedelta(minutes=61), "shop", "Pod", "checkout-7d9f-abc",
                        "OOMKilling", "Memory cgroup out of memory", "Warning")]
    if with_rollout:
        events.append(KubeEvent(T0 + timedelta(minutes=50), "shop", "Deployment", "checkout",
                                "ScalingReplicaSet", "Scaled up replica set checkout-7d9f to 3", "Normal"))
    peak = 490e6 if with_metric_shift else 310e6
    pre = [(T0 + timedelta(minutes=5 * i), 300e6) for i in range(12)]
    during = [(WIN_START + timedelta(minutes=5 * i), peak) for i in range(6)]
    return logs, events, [MetricSeries("memory_working_set", pre + during)]


def run(logs=(), events=(), metrics=()):
    return analyze(namespace="shop", workload="checkout", window_start=WIN_START,
                   window_end=WIN_END, logs=list(logs), events=list(events), metrics=list(metrics))


class DetectionTests(unittest.TestCase):
    def test_template_collapses_variable_parts(self):
        t = template("req 3f9a2b1c-1111-2222-3333-444455556666 from 10.0.0.12:8080 took 250ms")
        self.assertIn("<uuid>", t)
        self.assertIn("<ip>", t)
        self.assertIn("took <n>ms", t)

    def test_specific_signature_wins_over_generic(self):
        self.assertEqual(classify("Container was OOMKilled").name, "oom_killed")
        self.assertEqual(classify("java.lang.OutOfMemoryError: heap").name, "oom_killed")
        self.assertEqual(classify("ERROR something odd happened").name, "generic_error")
        self.assertIsNone(classify("request served in 12ms"))

    def test_repeats_group_into_one_finding(self):
        findings = detect([
            line("worker 1 OOMKilled", "p1", 1),
            line("worker 2 OOMKilled", "p2", 2),
            line("worker 3 OOMKilled", "p1", 3),
        ])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].count, 3)
        self.assertEqual(findings[0].pods, ["p1", "p2"])


class RedactionTests(unittest.TestCase):
    def test_removes_bearer_password_and_email(self):
        out = redact("Authorization: Bearer abc.def-123 password=hunter2 user ops@example.com")
        self.assertNotIn("abc.def", out)
        self.assertNotIn("hunter2", out)
        self.assertNotIn("ops@example.com", out)


class EvidenceTests(unittest.TestCase):
    def test_stale_rollout_is_not_treated_as_change(self):
        stale = KubeEvent(WIN_START - timedelta(hours=2), "shop", "Deployment", "checkout",
                          "ScalingReplicaSet", "x", "Normal")
        self.assertEqual(collect_evidence([], [stale], [], incident_start=WIN_START).items, [])

    def test_flat_metric_produces_no_evidence(self):
        flat = MetricSeries("memory_working_set", [(T0 + timedelta(minutes=5 * i), 300e6) for i in range(20)])
        self.assertEqual(collect_evidence([], [], [flat], incident_start=WIN_START).items, [])


class RootCauseTests(unittest.TestCase):
    def test_oom_with_metric_shift_and_rollout_is_high_confidence(self):
        report = run(*oom_scenario())
        self.assertEqual(report.root_cause.key, "memory_limit")
        self.assertEqual(report.root_cause.confidence, Confidence.HIGH)

    def test_without_metric_shift_confidence_is_medium_and_check_is_open(self):
        report = run(*oom_scenario(with_metric_shift=False))
        self.assertEqual(report.root_cause.confidence, Confidence.MEDIUM)
        self.assertTrue(any("unconfirmed" in c for c in report.root_cause.open_checks))

    def test_no_signals_yields_insufficient_evidence(self):
        report = run(logs=[line("request ok")])
        self.assertEqual(report.root_cause.key, "insufficient_evidence")
        self.assertEqual(report.root_cause.confidence, Confidence.LOW)
        self.assertEqual(report.analysis_mode, "deterministic")

    def test_every_cited_evidence_id_exists_in_report(self):
        report = run(*oom_scenario())
        known = {e.id for e in report.evidence}
        cited = set(report.root_cause.evidence_ids)
        cited |= {eid for step in report.five_whys for eid in step.evidence_ids}
        cited |= {eid for f in report.findings for eid in f.evidence_ids}
        self.assertTrue(cited <= known, f"dangling citations: {cited - known}")


class FiveWhysTests(unittest.TestCase):
    def setUp(self):
        self.book = EvidenceBook()
        self.book.add("log", "x", "loki", T0, ["oom"])
        self.book.add("event", "y", "kubernetes-events", T0, ["rollout"])

    @staticmethod
    def raw(citations):
        return {"five_whys": [
            {"level": i + 1, "question": f"Why {i + 1}?", "answer": "because", "evidence_ids": ids}
            for i, ids in enumerate(citations)
        ]}

    def test_rejects_unknown_evidence_id(self):
        self.assertIsNone(five_whys.validate_llm_steps(self.raw([["E1"], ["E2"], ["E99"]]), self.book))

    def test_accepts_valid_citations_and_marks_uncited_steps_unverified(self):
        steps = five_whys.validate_llm_steps(self.raw([["E1"], [], ["E2"]]), self.book)
        self.assertEqual([s.verified for s in steps], [True, False, True])

    def test_rejects_wrong_step_count(self):
        self.assertIsNone(five_whys.validate_llm_steps(self.raw([["E1"]]), self.book))

    def test_memory_chain_is_five_steps_and_last_step_is_open(self):
        report = run(*oom_scenario())
        self.assertEqual(len(report.five_whys), 5)
        self.assertTrue(report.five_whys[0].verified)
        self.assertFalse(report.five_whys[-1].verified)


class RemediationTests(unittest.TestCase):
    @staticmethod
    def rem(title, risk, commands, ns_hint=""):
        return Remediation(title=title, risk=risk, rationale="", commands=commands, rollback=[],
                           preconditions=[], evidence_ids=[], requires_approval=risk is not Risk.READ_ONLY)

    def test_guard_strips_destructive_commands(self):
        kept = remediation.guard([
            self.rem("bad", Risk.REVERSIBLE, ["kubectl -n shop delete ns shop"]),
            self.rem("also bad", Risk.REVERSIBLE, ["kubectl -n shop rollout restart deploy/x --force"]),
            self.rem("ok", Risk.READ_ONLY, ["kubectl -n shop get pods"]),
        ], namespace="shop")
        self.assertEqual([r.title for r in kept], ["ok"])

    def test_protected_namespace_adds_change_gate(self):
        kept = remediation.guard(
            [self.rem("dns", Risk.REVERSIBLE, ["kubectl -n kube-system rollout restart deploy/dns"])],
            namespace="kube-system")
        self.assertTrue(any("change management" in p for p in kept[0].preconditions))
        self.assertTrue(kept[0].requires_approval)

    def test_report_remediations_read_only_first_and_mutations_need_approval(self):
        report = run(*oom_scenario())
        self.assertEqual(report.remediations[0].risk, Risk.READ_ONLY)
        for rem in report.remediations:
            if rem.risk is not Risk.READ_ONLY:
                self.assertTrue(rem.requires_approval)

    def test_markdown_contains_required_sections(self):
        md = render_markdown(run(*oom_scenario()))
        for heading in ("## Root cause", "## Five whys", "## Remediation", "## Evidence index", "## Method and limits"):
            self.assertIn(heading, md)


class QuerySafetyTests(unittest.TestCase):
    def test_rejects_logql_injection_in_namespace(self):
        with self.assertRaises(ValueError):
            logql_for('shop" } or {x="y')

    def test_rejects_logql_injection_in_selector(self):
        with self.assertRaises(ValueError):
            logql_for("shop", 'app="a"} | json')

    def test_builds_scoped_query(self):
        self.assertIn('namespace="shop",app="checkout"', logql_for("shop", 'app="checkout"'))


if __name__ == "__main__":
    unittest.main()

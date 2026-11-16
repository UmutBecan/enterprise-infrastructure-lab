"""Tests for measured RTO/RPO, the evidence record and its verifier (companion to test_restore_drill.py)."""
import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import restore_drill as r
import verify_evidence as v

OBJ = {"rto_minutes": 60, "rpo_minutes": 15}
QUIET = lambda *_: None


class FakeClock:
    """Each call advances by `step` seconds, so measured RTO is deterministic."""
    def __init__(self, step):
        self.t, self.step = 0.0, step

    def __call__(self):
        self.t += self.step
        return self.t


def run(step=0.001, age=0.0, objectives=OBJ, tamper=False):
    passed, rep = r.run_drill(tamper=tamper, out=QUIET, backup_age_minutes=age, objectives=objectives,
                              data_class="critical", operator="tester", host_label="testhost",
                              clock=FakeClock(step))
    return passed, rep["evidence"]


class Objectives(unittest.TestCase):
    def test_within_targets_passes(self):
        passed, ev = run(step=0.001, age=10)
        self.assertTrue(passed)
        self.assertEqual(ev["result"], "PASS")
        self.assertTrue(ev["objectives"]["rto_met"] and ev["objectives"]["rpo_met"])

    def test_rpo_exceeded_fails_even_though_restore_is_intact(self):
        passed, ev = run(age=16)
        self.assertFalse(passed)
        self.assertTrue(ev["verification"]["restored_intact"])
        self.assertFalse(ev["objectives"]["rpo_met"])
        self.assertTrue(ev["objectives"]["rto_met"])

    def test_rpo_exactly_at_target_passes(self):
        self.assertTrue(run(age=15)[0])

    def test_rto_exceeded_fails(self):
        # exactly one fake-clock tick lies between loss and verification: 4000 s = ~66.7 min > 60 min
        passed, ev = run(step=4000)
        self.assertFalse(passed)
        self.assertFalse(ev["objectives"]["rto_met"])
        self.assertGreater(ev["measured"]["rto_minutes"], 60)

    def test_tampered_backup_never_meets_rto(self):
        passed, ev = run(tamper=True)
        self.assertFalse(passed)
        self.assertFalse(ev["objectives"]["rto_met"])
        self.assertNotEqual(ev["backup"]["archive_sha256_at_backup"], ev["backup"]["archive_sha256_at_restore"])

    def test_no_objectives_keeps_legacy_behaviour(self):
        passed, rep = r.run_drill(out=QUIET)
        self.assertTrue(passed)
        self.assertIsNone(rep["evidence"]["objectives"])

    def test_rpo_is_labelled_as_simulated(self):
        _, ev = run(age=7)
        self.assertEqual(ev["measured"]["rpo_minutes"], 7.0)
        self.assertIn("simulated", ev["measured"]["rpo_basis"])


class Policy(unittest.TestCase):
    def test_shipped_policy_loads_all_classes(self):
        for cls in ("critical", "important", "standard"):
            t = r.load_objectives(r.DEFAULT_OBJECTIVES, cls)
            self.assertGreaterEqual(t["rto_minutes"], 0)

    def test_missing_class_is_an_error(self):
        with self.assertRaises(r.PolicyError):
            r.load_objectives(r.DEFAULT_OBJECTIVES, "does-not-exist")

    def test_missing_or_invalid_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(r.PolicyError):
                r.load_objectives(Path(t) / "nope.json", "critical")
            bad = Path(t) / "bad.json"
            bad.write_text("{not json")
            with self.assertRaises(r.PolicyError):
                r.load_objectives(bad, "critical")
            neg = Path(t) / "neg.json"
            neg.write_text(json.dumps({"classes": {"x": {"rto_minutes": -1, "rpo_minutes": 5}}}))
            with self.assertRaises(r.PolicyError):
                r.load_objectives(neg, "x")

    def test_cli_unknown_class_exits_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(r.main(["--data-class", "nope"]), 2)
        self.assertIn("nope", err.getvalue())


class Evidence(unittest.TestCase):
    def sealed(self, key=None, **kw):
        _, ev = run(**kw)
        return r.seal_record(ev, key, "TEST_KEY" if key else None)

    def test_valid_record_verifies(self):
        self.assertEqual(v.verify_record(self.sealed(age=5)), [])

    def test_record_has_the_audit_fields(self):
        ev = self.sealed(age=5)
        for path in (("tool", "version"), ("environment", "os"), ("environment", "python"), ("run", "operator"),
                     ("timestamps_utc", "loss_simulated"), ("backup", "manifest_sha256"), ("backup", "file_count"),
                     ("measured", "rto_minutes"), ("objectives", "targets"), ("integrity", "seal")):
            d = ev
            for k in path:
                self.assertIn(k, d)
                d = d[k]
        self.assertEqual(ev["backup"]["file_count"], 4)

    def test_edited_result_is_detected(self):
        ev = self.sealed(age=16)
        ev["result"] = "PASS"
        joined = " | ".join(v.verify_record(ev))
        self.assertIn("seal mismatch", joined)
        self.assertIn("inconsistent", joined)

    def test_edited_measurement_is_detected(self):
        ev = self.sealed(age=5)
        ev["measured"]["rpo_minutes"] = 0.0
        self.assertTrue(any("seal mismatch" in p for p in v.verify_record(ev)))

    def test_resealed_edit_is_caught_by_consistency_checks(self):
        ev = self.sealed(age=16)  # honest FAIL
        ev["result"] = "PASS"
        ev["objectives"]["rpo_met"] = True
        r.seal_record(ev)  # attacker recomputes the plain SHA-256 seal
        problems = v.verify_record(ev)
        self.assertTrue(any("rpo_met disagrees" in p for p in problems))

    def test_resealed_edit_that_is_self_consistent_is_not_detected_without_hmac(self):
        # Documented limitation: a plain SHA-256 seal cannot stop a careful forger.
        ev = self.sealed(age=16)
        ev["measured"]["rpo_minutes"] = 1.0
        ev["objectives"]["rpo_met"] = True
        ev["result"] = "PASS"
        r.seal_record(ev)
        self.assertEqual(v.verify_record(ev), [])

    def test_missing_seal_is_invalid(self):
        ev = self.sealed()
        del ev["integrity"]
        self.assertTrue(v.verify_record(ev))

    def test_hmac_round_trip_and_wrong_key(self):
        ev = self.sealed(key=b"correct-key")
        self.assertEqual(ev["integrity"]["algorithm"], "hmac-sha256")
        self.assertNotIn("correct-key", json.dumps(ev))
        self.assertEqual(v.verify_record(ev, b"correct-key"), [])
        self.assertTrue(any("seal mismatch" in p for p in v.verify_record(ev, b"wrong-key")))
        self.assertTrue(any("no key is available" in p for p in v.verify_record(ev, None)))

    def test_hmac_resealing_without_key_fails(self):
        ev = self.sealed(key=b"k", age=16)
        ev["result"] = "PASS"
        ev["objectives"]["rpo_met"] = True
        r.seal_record(ev)  # forger has no key: a plain SHA-256 reseal is the only thing they can compute
        ev["integrity"]["algorithm"] = "hmac-sha256"  # claiming HMAC cannot be backed by a valid seal
        self.assertTrue(any("seal mismatch" in p for p in v.verify_record(ev, b"k")))

    def test_timestamps_must_agree_with_rto(self):
        ev = self.sealed()
        ev["measured"]["rto_seconds"] = 500.0
        ev["measured"]["rto_minutes"] = round(500.0 / 60, 6)
        r.seal_record(ev)
        self.assertTrue(any("disagrees with the timestamps" in p for p in v.verify_record(ev)))


class CommandLine(unittest.TestCase):
    def run_cli(self, mod, argv, env=None):
        old = {k: os.environ.get(k) for k in (env or {})}
        os.environ.update(env or {})
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = mod.main(argv)
        finally:
            for k, val in old.items():
                os.environ.pop(k, None) if val is None else os.environ.__setitem__(k, val)
        return code, out.getvalue()

    def test_end_to_end_pass_and_verify(self):
        with tempfile.TemporaryDirectory() as t:
            f = str(Path(t) / "e.json")
            code, _ = self.run_cli(r, ["--data-class", "critical", "--backup-age-minutes", "10", "--evidence", f])
            self.assertEqual(code, 0)
            code, out = self.run_cli(v, [f])
            self.assertEqual(code, 0)
            self.assertIn("VERDICT: VALID", out)

    def test_end_to_end_rpo_failure_exit_1_and_still_verifies_as_authentic(self):
        with tempfile.TemporaryDirectory() as t:
            f = str(Path(t) / "e.json")
            code, _ = self.run_cli(r, ["--data-class", "critical", "--backup-age-minutes", "45", "--evidence", f])
            self.assertEqual(code, 1)
            rec = json.loads(Path(f).read_text())
            self.assertEqual(rec["result"], "FAIL")
            self.assertEqual(self.run_cli(v, [f])[0], 0)  # an honest FAIL record is a valid record

    def test_cli_tamper_with_file_edit_exit_1(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "e.json"
            self.run_cli(r, ["--data-class", "critical", "--backup-age-minutes", "45", "--evidence", str(f)])
            rec = json.loads(f.read_text())
            rec["result"] = "PASS"
            f.write_text(json.dumps(rec))
            code, out = self.run_cli(v, [str(f)])
            self.assertEqual(code, 1)
            self.assertIn("VERDICT: INVALID", out)

    def test_hmac_cli_requires_key_and_detects_wrong_key(self):
        with tempfile.TemporaryDirectory() as t:
            f = str(Path(t) / "e.json")
            self.assertEqual(self.run_cli(r, ["--evidence", f, "--hmac-env", "EVTEST_KEY"], {"EVTEST_KEY": ""})[0], 2)
            self.assertEqual(self.run_cli(r, ["--evidence", f, "--hmac-env", "EVTEST_KEY"], {"EVTEST_KEY": "s3cret"})[0], 0)
            self.assertEqual(self.run_cli(v, [f], {"EVTEST_KEY": "s3cret"})[0], 0)
            self.assertEqual(self.run_cli(v, [f], {"EVTEST_KEY": "other"})[0], 1)
            self.assertNotIn("s3cret", Path(f).read_text())

    def test_verifier_unreadable_input_exit_2(self):
        self.assertEqual(self.run_cli(v, ["/no/such/file.json"])[0], 2)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Verify a restore-drill evidence record written by tools/restore_drill.py --evidence.

    python tools/verify_evidence.py out.json
    RESTORE_EVIDENCE_HMAC_KEY=... python tools/verify_evidence.py out.json     # HMAC-sealed records

Exit 0 = the seal matches and the record is internally consistent, 1 = it is not
(or cannot be checked), 2 = unreadable input.

What this proves and what it does not:
- A plain SHA-256 seal detects accidental change and casual edits that forget the seal.
  Anyone can recompute it after editing, so it is NOT tamper-proof on its own.
- An HMAC-SHA256 seal can only be recomputed by someone holding the key. The key is read
  from an environment variable and must never be committed to a repository.
  Anyone who holds the key can still forge a record; keep the key with the control owner,
  not with the person who runs the drill, if you need separation of duties.
- Neither proves the drill was run honestly on real systems; they prove the record was
  not changed after it was sealed.

Python standard library only. The canonicalisation is deliberately re-implemented here
(not imported from restore_drill.py) so the verifier is an independent check.
"""
import argparse
import datetime
import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

SCHEMA = "restore-evidence/1"
HMAC_ENV_DEFAULT = "RESTORE_EVIDENCE_HMAC_KEY"
PHASES = ["started", "backup_completed", "loss_simulated", "restore_finished", "verification_finished"]


def canonical(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def parse_ts(value):
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def check_seal(record, hmac_key=None):
    """Return a list of problems with the integrity seal."""
    integrity = record.get("integrity")
    if not isinstance(integrity, dict) or not isinstance(integrity.get("seal"), str):
        return ["integrity seal missing"]
    algorithm = integrity.get("algorithm")
    body = {k: v for k, v in record.items() if k != "integrity"}
    body["integrity"] = {k: v for k, v in integrity.items() if k != "seal"}
    data = canonical(body)
    if algorithm == "sha256":
        expected = hashlib.sha256(data).hexdigest()
    elif algorithm == "hmac-sha256":
        if not hmac_key:
            return ["record is HMAC-sealed but no key is available (set the environment variable named in integrity.key_env)"]
        expected = hmac.new(hmac_key, data, "sha256").hexdigest()
    else:
        return [f"unknown seal algorithm: {algorithm!r}"]
    if not hmac.compare_digest(expected, integrity["seal"]):
        return [f"seal mismatch ({algorithm}): the record changed after sealing, or the wrong key was used"]
    return []


def check_consistency(record):
    """Return a list of problems with the record's content (independent of the seal)."""
    problems = []
    if record.get("schema") != SCHEMA:
        problems.append(f"unsupported schema: {record.get('schema')!r}")
        return problems
    try:
        ts = record["timestamps_utc"]
        times = [parse_ts(ts[k]) for k in PHASES]
        if times != sorted(times):
            problems.append("timestamps are not in phase order")
        measured, verification = record["measured"], record["verification"]
        wall = (times[PHASES.index("verification_finished")] - times[PHASES.index("loss_simulated")]).total_seconds()
        if abs(wall - measured["rto_seconds"]) > 1.0:
            problems.append(f"measured RTO ({measured['rto_seconds']} s) disagrees with the timestamps ({wall:.3f} s)")
        if round(measured["rto_seconds"] / 60, 6) != measured["rto_minutes"]:
            problems.append("rto_minutes does not equal rto_seconds / 60")
        intact = bool(verification["restored_intact"])
        if intact != (not verification["problems"]):
            problems.append("restored_intact disagrees with the problem list")
        if record["backup"]["file_count"] < 1:
            problems.append("file_count must be at least 1")
        expected_pass = intact
        objectives = record.get("objectives")
        if objectives is not None:
            t = objectives["targets"]
            rto_met = intact and measured["rto_minutes"] <= t["rto_minutes"]
            rpo_met = measured["rpo_minutes"] <= t["rpo_minutes"]
            if objectives["rto_met"] != rto_met:
                problems.append("rto_met disagrees with measured RTO and target")
            if objectives["rpo_met"] != rpo_met:
                problems.append("rpo_met disagrees with measured RPO and target")
            expected_pass = intact and rto_met and rpo_met
        if record.get("result") != ("PASS" if expected_pass else "FAIL"):
            problems.append(f"result {record.get('result')!r} is inconsistent with the verification and objectives")
        for key in ("tool", "environment", "run"):
            if not record.get(key):
                problems.append(f"missing section: {key}")
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        problems.append(f"malformed record: {type(e).__name__}: {e}")
    return problems


def verify_record(record, hmac_key=None):
    return check_seal(record, hmac_key) + check_consistency(record)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("evidence", help="evidence JSON file")
    ap.add_argument("--hmac-env", help=f"environment variable holding the HMAC key (default: the name recorded in the file, else {HMAC_ENV_DEFAULT})")
    args = ap.parse_args(argv)
    try:
        record = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        if not isinstance(record, dict):
            raise ValueError("top level is not an object")
    except (OSError, ValueError) as e:
        print(f"error: cannot read {args.evidence}: {e}", file=sys.stderr)
        return 2
    integrity = record.get("integrity") if isinstance(record.get("integrity"), dict) else {}
    env_name = args.hmac_env or integrity.get("key_env") or HMAC_ENV_DEFAULT
    key = os.environ.get(env_name, "").encode("utf-8") or None
    problems = verify_record(record, key)
    if problems:
        for p in problems:
            print(f"FAIL: {p}")
        print("VERDICT: INVALID")
        return 1
    obj = record.get("objectives") or {}
    print(f"seal: {integrity.get('algorithm')} OK")
    print(f"record: schema {record['schema']}, result {record['result']}, files {record['backup']['file_count']}, "
          f"objectives {'RTO met=' + str(obj['rto_met']) + ' RPO met=' + str(obj['rpo_met']) if obj else 'not evaluated'}")
    print("VERDICT: VALID")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Restore drill: back up a sample dataset, simulate loss, restore, verify.

    python tools/restore_drill.py            # run the drill, exit 0 on PASS, 1 on FAIL
    python tools/restore_drill.py --tamper   # corrupt the backup first; the drill must FAIL

    # audit evidence: measured RTO/RPO against a policy, plus a sealed JSON record
    python tools/restore_drill.py --data-class critical --backup-age-minutes 10 --evidence out.json
    python tools/verify_evidence.py out.json

Exit codes: 0 = PASS, 1 = FAIL (restore not intact, or an objective exceeded),
2 = bad input/configuration (unknown data class, unreadable policy, missing HMAC key).

Python standard library only. Everything happens in a temporary directory:
no cloud account, no admin rights, nothing outside the temp directory is touched.

Steps: create sample data -> write a SHA-256 manifest -> tar.gz backup ->
delete the source (simulated loss) -> restore to a separate path -> compare
the restored files against the manifest (hashes, file count, unexpected files).
"""
import argparse
import datetime
import getpass
import hashlib
import hmac
import json
import os
import platform
import shutil
import sys
import tarfile
import tempfile
import time
from pathlib import Path

VERSION = "1.1.0"
EVIDENCE_SCHEMA = "restore-evidence/1"
HMAC_ENV_DEFAULT = "RESTORE_EVIDENCE_HMAC_KEY"
DEFAULT_OBJECTIVES = Path(__file__).resolve().parent.parent / "examples" / "backup" / "recovery-objectives.json"


class PolicyError(ValueError):
    """The recovery-objectives file is missing, unreadable, or lacks the requested class."""


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def make_sample(root):
    (root / "config").mkdir(parents=True)
    (root / "data").mkdir()
    (root / "config" / "app.conf").write_text("service=example\nport=8080\n")
    (root / "data" / "numbers.txt").write_text("".join(f"{i}\n" for i in range(1, 501)))
    (root / "data" / "report with spaces.txt").write_text("quarterly figures\n")
    (root / "data" / "blob.bin").write_bytes(bytes(range(256)) * 64)


def build_manifest(root):
    return {
        p.relative_to(root).as_posix(): sha256_file(p)
        for p in sorted(root.rglob("*")) if p.is_file()
    }


def backup(src, archive):
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(src, arcname=".")


def corrupt(archive):
    """Flip one byte in the middle of the archive (simulates silent corruption)."""
    data = bytearray(archive.read_bytes())
    data[len(data) // 2] ^= 0xFF
    archive.write_bytes(bytes(data))


def restore(archive, dest):
    dest.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as tar:
        for m in tar.getmembers():  # refuse path traversal and links in the archive
            target = (dest / m.name).resolve()
            if dest.resolve() not in (target, *target.parents) or m.issym() or m.islnk():
                raise ValueError(f"unsafe archive member: {m.name}")
        tar.extractall(dest, filter="data") if hasattr(tarfile, "data_filter") else tar.extractall(dest)


def verify(manifest, restored_root):
    """Return a list of problems; empty list means the restore is intact."""
    actual = build_manifest(restored_root)
    problems = []
    if len(actual) != len(manifest):
        problems.append(f"file count: expected {len(manifest)}, got {len(actual)}")
    for name, digest in manifest.items():
        if name not in actual:
            problems.append(f"missing: {name}")
        elif actual[name] != digest:
            problems.append(f"hash mismatch: {name}")
    for name in actual.keys() - manifest.keys():
        problems.append(f"unexpected file: {name}")
    return problems


def load_objectives(path, data_class):
    """Return {"rto_minutes": float, "rpo_minutes": float} for one data class, or raise PolicyError."""
    try:
        policy = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PolicyError(f"cannot read objectives file {path}: {e}") from e
    classes = policy.get("classes") if isinstance(policy, dict) else None
    if not isinstance(classes, dict) or data_class not in classes:
        known = ", ".join(sorted(classes)) if isinstance(classes, dict) else "none"
        raise PolicyError(f"data class {data_class!r} not in {path} (known classes: {known})")
    entry = classes[data_class]
    out = {}
    for key in ("rto_minutes", "rpo_minutes"):
        v = entry.get(key) if isinstance(entry, dict) else None
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            raise PolicyError(f"data class {data_class!r}: {key} must be a number >= 0")
        out[key] = v
    return out


def evaluate_objectives(targets, rto_seconds, rpo_minutes, recovered):
    """Compare measured RTO/RPO with targets. An unverified restore never meets the RTO."""
    rto_minutes = rto_seconds / 60
    return {
        "rto_met": bool(recovered and rto_minutes <= targets["rto_minutes"]),
        "rpo_met": bool(rpo_minutes <= targets["rpo_minutes"]),
    }


def canonical_bytes(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def seal_record(record, hmac_key=None, key_env=None):
    """Add record["integrity"]: SHA-256 (or HMAC-SHA256) over the canonical JSON of the record.

    The seal covers every other field plus the algorithm name and the key's
    environment-variable NAME (never its value)."""
    record.pop("integrity", None)
    record["integrity"] = {"algorithm": "hmac-sha256" if hmac_key else "sha256", "key_env": key_env if hmac_key else None}
    data = canonical_bytes(record)
    seal = hmac.new(hmac_key, data, "sha256").hexdigest() if hmac_key else hashlib.sha256(data).hexdigest()
    record["integrity"]["seal"] = seal
    return record


def iso(dt):
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


def run_drill(tamper=False, out=print, backup_age_minutes=0.0, objectives=None, data_class=None,
              operator=None, host_label=None, clock=time.perf_counter, now=utcnow):
    """Run the whole drill; returns (passed: bool, report: dict).

    objectives: {"rto_minutes", "rpo_minutes"} targets, or None to skip the comparison.
    backup_age_minutes: SIMULATED age of the backup at the moment of loss (the RPO input).
    clock/now are injectable so tests can control time."""
    ts = {"started": iso(now())}
    t_start = clock()
    with tempfile.TemporaryDirectory(prefix="restore-drill-") as tmp:
        tmp = Path(tmp)
        src, backups, restored = tmp / "source", tmp / "backups", tmp / "restored"
        backups.mkdir()
        make_sample(src)
        manifest = build_manifest(src)
        archive = backups / "backup.tar.gz"
        (backups / "manifest.sha256.json").write_text(json.dumps(manifest, indent=2))
        backup(src, archive)
        archive_sha_at_backup = sha256_file(archive)
        archive_bytes = archive.stat().st_size
        ts["backup_completed"] = iso(now())
        out(f"[1/5] sample data: {len(manifest)} files")
        out(f"[2/5] backup written: {archive.name} ({archive_bytes} bytes), manifest has {len(manifest)} SHA-256 entries")
        if tamper:
            corrupt(archive)
            out("      --tamper: one byte of the archive was flipped")
        archive_sha_at_restore = sha256_file(archive)
        shutil.rmtree(src)
        ts["loss_simulated"] = iso(now())
        t_loss = clock()
        out(f"[3/5] simulated loss: source directory deleted (exists={src.exists()})")
        try:
            restore(archive, restored)
            ts["restore_finished"] = iso(now())
            problems = verify(manifest, restored)
            out(f"[4/5] restored to a separate path: {len(build_manifest(restored))} files")
        except (tarfile.TarError, EOFError, OSError, ValueError) as e:
            ts["restore_finished"] = iso(now())
            problems = [f"restore failed: {type(e).__name__}: {e}"]
            out("[4/5] restore raised an error")
        ts["verification_finished"] = iso(now())
        t_verified = clock()
        recovered = not problems
        out("[5/5] verification: " + ("all hashes match, file count matches" if recovered else "; ".join(problems)))
    rto_seconds = round(t_verified - t_loss, 6)
    passed = recovered
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "tool": {"name": "restore_drill.py", "version": VERSION},
        "environment": {
            "host": host_label or platform.node(),
            "os": platform.platform(),
            "python": platform.python_version(),
        },
        "run": {
            "operator": operator or getpass.getuser(),
            "scope": f"synthetic sample dataset, {len(manifest)} files; no production data",
            "tamper_injected": bool(tamper),
        },
        "timestamps_utc": ts,
        "backup": {
            "file_count": len(manifest),
            "manifest_sha256": hashlib.sha256(canonical_bytes(manifest)).hexdigest(),
            "archive_bytes": archive_bytes,
            "archive_sha256_at_backup": archive_sha_at_backup,
            "archive_sha256_at_restore": archive_sha_at_restore,
        },
        "verification": {"restored_intact": recovered, "problems": problems},
        "measured": {
            "rto_seconds": rto_seconds,
            "rto_minutes": round(rto_seconds / 60, 6),
            "rto_basis": "measured: simulated loss to completed verification, monotonic clock",
            "rpo_minutes": float(backup_age_minutes),
            "rpo_basis": "simulated: value of --backup-age-minutes, not a real-world measurement",
        },
        "objectives": None,
    }
    if objectives is not None:
        met = evaluate_objectives(objectives, rto_seconds, backup_age_minutes, recovered)
        evidence["objectives"] = {"data_class": data_class, "targets": dict(objectives), **met}
        passed = recovered and met["rto_met"] and met["rpo_met"]
        out(f"      RTO: measured {rto_seconds / 60:.4f} min vs target {objectives['rto_minutes']} min -> {'met' if met['rto_met'] else 'EXCEEDED'}")
        out(f"      RPO: simulated backup age {backup_age_minutes} min vs target {objectives['rpo_minutes']} min -> {'met' if met['rpo_met'] else 'EXCEEDED'}")
    evidence["result"] = "PASS" if passed else "FAIL"
    out(f"RESULT: {evidence['result']} ({clock() - t_start:.2f}s)")
    return passed, {"files": len(manifest), "problems": problems, "evidence": evidence}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tamper", action="store_true", help="corrupt the backup first (the drill must then FAIL)")
    ap.add_argument("--backup-age-minutes", type=float, default=0.0,
                    help="SIMULATED age of the backup when the loss happens; this is the measured-RPO input (default 0)")
    ap.add_argument("--data-class", help="class in the objectives file (default 'standard' when --evidence is used)")
    ap.add_argument("--objectives", default=str(DEFAULT_OBJECTIVES), help="recovery-objectives JSON file")
    ap.add_argument("--evidence", metavar="FILE", help="write a sealed JSON evidence record to FILE")
    ap.add_argument("--hmac-env", metavar="VAR", help="name of an environment variable holding the HMAC key "
                    "(never pass the key itself, never commit it); seals with HMAC-SHA256 instead of plain SHA-256")
    ap.add_argument("--operator", help="who ran the drill (default: OS user name)")
    ap.add_argument("--host-label", help="host name to record (default: this machine's name)")
    args = ap.parse_args(argv)
    if args.backup_age_minutes < 0:
        print("error: --backup-age-minutes must be >= 0", file=sys.stderr)
        return 2
    hmac_key = None
    if args.hmac_env:
        value = os.environ.get(args.hmac_env, "")
        if not value:
            print(f"error: environment variable {args.hmac_env} is not set or empty", file=sys.stderr)
            return 2
        hmac_key = value.encode("utf-8")
    data_class = args.data_class or ("standard" if args.evidence else None)
    objectives = None
    if data_class:
        try:
            objectives = load_objectives(args.objectives, data_class)
        except PolicyError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    passed, report = run_drill(tamper=args.tamper, backup_age_minutes=args.backup_age_minutes,
                               objectives=objectives, data_class=data_class,
                               operator=args.operator, host_label=args.host_label)
    if args.evidence:
        record = seal_record(report["evidence"], hmac_key, args.hmac_env)
        Path(args.evidence).write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"evidence written: {args.evidence} (seal: {record['integrity']['algorithm']})")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

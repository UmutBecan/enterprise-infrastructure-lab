#!/usr/bin/env python3
"""Restore drill: back up a sample dataset, simulate loss, restore, verify.

    python tools/restore_drill.py            # run the drill, exit 0 on PASS, 1 on FAIL
    python tools/restore_drill.py --tamper   # corrupt the backup first; the drill must FAIL

Python standard library only. Everything happens in a temporary directory:
no cloud account, no admin rights, nothing outside the temp directory is touched.

Steps: create sample data -> write a SHA-256 manifest -> tar.gz backup ->
delete the source (simulated loss) -> restore to a separate path -> compare
the restored files against the manifest (hashes, file count, unexpected files).
"""
import argparse
import hashlib
import json
import sys
import tarfile
import tempfile
import time
from pathlib import Path


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


def run_drill(tamper=False, out=print):
    """Run the whole drill; returns (passed: bool, report: dict)."""
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="restore-drill-") as tmp:
        tmp = Path(tmp)
        src, backups, restored = tmp / "source", tmp / "backups", tmp / "restored"
        backups.mkdir()
        make_sample(src)
        manifest = build_manifest(src)
        archive = backups / "backup.tar.gz"
        (backups / "manifest.sha256.json").write_text(json.dumps(manifest, indent=2))
        backup(src, archive)
        out(f"[1/5] sample data: {len(manifest)} files")
        out(f"[2/5] backup written: {archive.name} ({archive.stat().st_size} bytes), manifest has {len(manifest)} SHA-256 entries")
        if tamper:
            corrupt(archive)
            out("      --tamper: one byte of the archive was flipped")
        import shutil
        shutil.rmtree(src)
        out(f"[3/5] simulated loss: source directory deleted (exists={src.exists()})")
        try:
            restore(archive, restored)
            problems = verify(manifest, restored)
            out(f"[4/5] restored to a separate path: {len(build_manifest(restored))} files")
        except (tarfile.TarError, EOFError, OSError, ValueError) as e:
            problems = [f"restore failed: {type(e).__name__}: {e}"]
            out("[4/5] restore raised an error")
        passed = not problems
        out("[5/5] verification: " + ("all hashes match, file count matches" if passed else "; ".join(problems)))
    elapsed = time.monotonic() - t0
    out(f"RESULT: {'PASS' if passed else 'FAIL'} ({elapsed:.2f}s)")
    return passed, {"files": len(manifest), "problems": problems}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--tamper", action="store_true", help="corrupt the backup first (the drill must then FAIL)")
    args = ap.parse_args(argv)
    passed, _ = run_drill(tamper=args.tamper)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

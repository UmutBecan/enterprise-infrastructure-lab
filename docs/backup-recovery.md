# Backup and recovery

*A reference pattern. It describes how backup and recovery should be designed and proven, not any specific environment.*

## Goal

Be able to restore the systems the business cannot work without, within a time the business has agreed to, and be able to prove it.

## Start from the business, not the tool

For each system record two numbers with the business owner:

- **RTO** (recovery time objective): how long the business can be without it.
- **RPO** (recovery point objective): how much recent data it can afford to lose.

Group systems into tiers (for example critical, important, standard) and size the solution to the tier.

## Design principles

1. **3-2-1 as a minimum.** Three copies, two kinds of storage, one copy offsite or offline.
2. **Immutable or offline copy.** At least one copy cannot be changed or deleted by an ordinary administrator account, so ransomware cannot remove it.
3. **Separate credentials.** Backup consoles use their own accounts, not the everyday domain admin identity.
4. **Application-consistent backups** for databases and messaging, not just file-level copies.
5. **Documented order of restore.** Identity and network first, then data services, then applications.

## Proving it

A backup that was never restored is a hope, not a control.

| Check | Frequency | Evidence |
|---|---|---|
| File and mailbox restore | Monthly | Ticket with result |
| Single system restore | Quarterly | Restore log, time taken |
| Full recovery exercise (failover and return) | Yearly | Written report with times and follow-up actions |

Write the exercise report so a non-technical reader can see what was covered, what was confirmed, how long it took, and what will be improved next.

## Roles

- A named owner for each tier.
- A runbook per critical system, kept where it is still reachable during an outage.
- A contact list for suppliers and internal decision makers.

## Common mistakes to avoid

- Backups stored in the same failure domain as production.
- Monitoring that checks "job finished" instead of "restorable".
- A recovery plan that depends on a system which is itself down.
- Never testing the return path (failback).

## Evidence for an auditor

`tools/restore_drill.py --evidence` writes one JSON record per drill. This is how its fields line up with what an auditor typically asks for when testing a backup and restore control. The mapping is generic: it shows what evidence exists, not that a control is satisfied.

| Auditor asks | Evidence field | Caveat |
|---|---|---|
| Was a restore actually tested? | `verification.restored_intact`, `verification.problems` | The drill restores a synthetic sample, not your production backup. |
| When? | `timestamps_utc.*` (UTC, per phase) | Taken from the host clock; the verifier checks they are in order and agree with the measured RTO. |
| What was in scope? | `run.scope`, `backup.file_count`, `backup.manifest_sha256` | For real systems, record the system, data class and backup set in the ticket or report. |
| What was the result? | `result` (`PASS`/`FAIL`) | `FAIL` records are kept and valid; they are evidence too. |
| Were the agreed objectives met? | `objectives.targets`, `measured.rto_minutes`, `measured.rpo_minutes`, `objectives.rto_met`, `objectives.rpo_met` | RTO is measured on the sample; RPO is a simulated input and labelled as such. |
| Who ran it, with what, where? | `run.operator`, `tool.version`, `environment.*` | `--operator` and `--host-label` are self-asserted. |
| Is the record trustworthy? | `integrity.seal`, `integrity.algorithm` | See the sealing notes in the README. A seal shows the record was not changed after sealing. |
| Was the backup itself intact between creation and restore? | `backup.archive_sha256_at_backup` vs `archive_sha256_at_restore` | A difference means the archive changed in storage (`--tamper` demonstrates this). |

Standards context, from public control summaries (not from the standard's own text, which is paywalled; check your copy of ISO/IEC 27001:2022 before citing it in an audit): Annex A control **8.13, "Information backup"**, expects backup copies of information, software and systems to be kept and tested regularly against an agreed backup policy, and control **5.30, "ICT readiness for business continuity"**, relates to recovery objectives. Sources checked on 2026-11-17: isms.online (Annex A control list and 8.13 page), advisera.com (control 8.13) and upguard.com (8.13). This repository does not claim compliance with, or certification against, any standard.

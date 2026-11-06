# W5-04 — Tenant preservation holds

Implemented on 2026-11-06 against `fb27305`, including W0-02's keyed-ledger
erasure. This is a technical purge policy; it does not claim immutable storage
or replace the organization's case-specific legal decisions.

## Policy

An administrator with `manage:roles` may set or release a tenant-wide hold in
Privacy → Retention holds. Setting requires a case reference and preservation
reason. Releasing requires a separate release reason and confirmation. Hold
identifiers make retried creates idempotent; reusing a released identifier
returns its history without reactivating it. Holds never expire automatically.
Released records remain in history; there is no delete endpoint.

While **any** hold is active:

- Scheduled retention deletes no aged assignments, tracking tokens/events,
  reported/reply receipts, expired directory preview payloads or ledger entries.
- Recipient erasure, privacy-request deletion fulfillment, and direct keyed
  awareness-ledger purge are blocked. A held request stays unfulfilled; its SLA
  deadline does not move automatically.
- Campaign lifecycle reconciliation continues. A held retention run records a
  zero-delete result and a `retention.held` audit event, rather than pretending
  deletion succeeded or repeatedly retrying the same completed queue message.

Release does not erase anything itself. Once every hold is released, the next
normal retention run can remove already-aged data, and an explicitly fulfilled
erasure request can proceed. Existing record ages are not reset. Delivery,
tracking, stop/revoke controls, access exports and ordinary operational updates
remain governed by their existing policies; this feature is not a write freeze.
Clearing a held directory preview is blocked because it discards its payload.

The default is **no active holds**. No live hold was created during development
or qualification; all test holds were confined to disposable databases.

## Enforcement and disclosure

All purge helpers take a shared PostgreSQL transaction advisory lock before
checking hold state, retaining it through commit. Setting/releasing holds takes
the same lock exclusively. A hold becomes effective when its transaction
commits, after any already-running protected purge transaction finishes. READ
COMMITTED is required; other transaction isolation levels fail closed so a stale
snapshot cannot hide a newly committed hold.

Migration `0053_retention_holds` also installs database triggers protecting
DELETE/TRUNCATE on purge tables, recipient tombstoning, and directory-preview
clearing. These protect against older processes that lack the application
check. The guard function has a fixed search path and schema-qualified lookup,
runs with migrator ownership, and grants no public EXECUTE. Runtime roles cannot
drop triggers or hold history under the reviewed least-privilege grants.
Database administrators, backup retention and external storage policies remain
outside this application hold's enforcement boundary.

Only administrators can list case text or change holds. Privacy handlers can
read a boolean hold status. Case references and reasons use the existing
authenticated-encryption type at rest; responses prohibit caching. Audit events
record actors, hold identifiers and whether reasons were supplied, without
copying case text into the audit stream. Operators should use case references
and avoid employee personal data in free-text reasons.

The grant matrix gives the operator SELECT/INSERT/UPDATE and the retention
worker SELECT only on `retention_holds`; neither gets DELETE/TRUNCATE. Migration
downgrade deliberately refuses to discard preservation history.

## Qualification and deployment

Twelve hermetic hold tests cover multiple holds, retry identity, release history,
encrypted storage, unavailable state, unsupported isolation, blocked direct
erasure/ledger purge and an unfulfilled privacy request. Five real PostgreSQL
tests on `.105` cover fresh migration, both serialization directions, raw and
ledger preservation followed by erasure after release, runtime privileges, and
database rejection of legacy DELETE/TRUNCATE/tombstone/preview-clear operations.
An isolated browser test covers set, lost-response retry, cancelled release,
confirmed release and retained history; axe reports no violations in the tested
hold view.

Deploy the migration with the reviewed migration identity before running the
new API/retention code. Verify grants and guards on the target. Deploy all
purge-capable processes from the same release before operators manage holds;
legacy processes will fail closed on guarded purges while a hold is active.
Do not downgrade the schema to remove a hold. Use an audited release decision.

See [remaining-remediation evidence](../REMAINING-REMEDIATION-2026-11-06.md).

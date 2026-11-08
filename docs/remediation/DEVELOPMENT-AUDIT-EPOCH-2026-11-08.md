# Development audit anchoring epoch — November 8, 2026

The user explicitly instructed “Action recommended path” after the historical
witness disagreement was explained. The approved development-only action is
complete on `.105`: retain the current internally verified dataset and every
older artifact, declare the discontinuity, and resume forward anchoring in a
new private witness directory. This does not authenticate or recover the missing
earlier history.

## Actual change and evidence

Application `3512a4129262425999e6baaaaf0cc6a0b5f866e6` and schema `0060` remain
unchanged. Only `KP_WORKER_AUDIT_ANCHOR_LOCAL_DIR` changed in the active release's
private environment, from `data/audit-anchors` to:

`/home/builder/phishing-awareness-platform/data/audit-anchors-development-20261107-3lkij1-v2`

The original environment inode and bytes are retained by a private hardlink in
the pre-change checkpoint. Every other environment value is unchanged. The owned
`kp-supervisor.service` was restarted, with its thirteen native children; all
seven infrastructure containers and full typed mount identities were preserved.
The original unit, release drop-in, normal environment and Compose override are
retained. No application code, credential, keyring, database schema or old history
was replaced.

The exclusive continuity manifest has SHA-256:

`f81137c3b903a47171e23c57c8ee13227c70cabbeb0d4f697087ee498a461b0b`

The actual signed audit declaration is event `64bc3a1d-f2c5-4eda-9b92-33bed99b04ec`
at sequence `106879`. Its action is
`development.audit_continuity_epoch_declared`, and its detail explicitly records
owner acceptance, the manifest hash and the absence of recovered historical
continuity. One new maintenance job, `27374499-0d9e-484f-997a-479f55e92e13`, was consumed;
old failed jobs were not replayed.

A new immutable witness at sequence **106881** matches the current
signed chain. The actual successful anchor heartbeat is
`2026-11-08T15:35:51.051947+00:00`. Final read-only verification found the old
checkpoint chain head still reachable with the same hash and the current chain
internally valid. Both API readiness checks, exact served UI bytes, all thirteen
native children, ciphertext reads and every business-table count passed.
Only expected audit/outbox counts were allowed to advance.

All five September witnesses remain byte- and metadata-identical to the preserved
pre-upgrade checkpoint. The September 21 dump still matches
`14d32bd156bb27370cd36692218a41d73c3d7d5371a27ff71498a5088272e40d`.
All **1,131** pre-change dead-letter records across all eleven worker topics
are unchanged: audit-anchor 1,126, generation
2, ingestion 3.
The task's fallback timer was disarmed after verification; its unit definitions
and before/after evidence were retained, and the runtime service was untouched
by that final step.

## Private pre-change recovery point

The new exclusive worker directory is:

`/home/builder/qualification/audit-epoch-20261108-v3`

It contains the PostgreSQL globals and validated custom dump, a native binary
Redis snapshot of **157,617 keys** with exact absolute expiry times,
a **2,236,282,880-byte** complete project-data archive,
the original active environment inode, normal environment, service unit,
release drop-in and Compose override. Every checkpoint file hash was rechecked
following the live change. Plaintext data, credentials and keys remain on the
worker; only receipt metadata was returned to the controller.

This checkpoint intentionally captures the state **before** the epoch switch,
including its known old witness disagreement. It is not a post-epoch restore
qualification. Retain the original development-upgrade plan and its old
configuration hash unchanged; future operations must bind the current accepted
configuration through this epoch's manifest and final receipt.

| Configuration binding | SHA-256 |
| --- | --- |
| Original active environment, retained | `0a6c86aad0011262d880c216af89adc2e0434ebf6d3816fd6c81a7db05d2abe5` |
| Current accepted active environment | `08d5aa174ca62c9a92b25a5170ef8a33a1e1a49c5206430be0a5896d46c262a0` |
| PostgreSQL pre-change dump | `3d16e0662a77effc8deeceb26d3060ad8ebbb5ab52e0e2cad901396879f371f9` |
| Redis pre-change logical snapshot | `7ed928d7fba79947432ea925d9546132db6b610419e662d0871dfd6385b2c7ac` |
| Project-data pre-change archive | `2d47b14a94ce7de282c0aa333ad18a832074aec49794f2f9d429b14b2ef5fb29` |

## Validation and retained attempts

The final private operator and controller passed **54** guard tests and Ruff
before execution. Exact transfer code, one-key changes, original inode retention,
state-drift refusals, dead-letter preservation, no replay, bounded service
recovery, binary Redis payloads, exact expiry times and the observed key-count
boundary were tested. A real read-only binary snapshot of 157,614 keys passed in
1.51 seconds before service stop. It was explicitly labeled a live probe rather
than the later quiesced checkpoint.

The first read-only inspection stopped on a Redis text/bytes mismatch. The next
checkpoint stopped at the original 100,000-key guard and recovered the service
with its original configuration before any epoch mutation. Both attempts,
helpers, evidence and partial checkpoints are retained. Read-only metadata showed
157,596 keys using about 34 MB. The final implementation retains the 500,000-key,
512 MiB payload and 120-second snapshot limits, uses batches of 500 native dumps,
and verifies that the binary connection is not decoding payloads. No key, cache,
volume, image or earlier evidence was removed to satisfy the bound.

Controller evidence and pinned private sources are in
`data/qualification/audit-epoch-20261108/`; the final observed receipt is
`final-receipt-1794152840066237000.json`. Helper SHA-256 is
`7d5686625dbce8e01571f188e25afc6b47a2fb03e73f127b95c4366b461783f3`.
The worker retains the continuity manifest, declaration, new job, checkpoint
inventory and final verification. No independent peer review is claimed for
this private operator; the recorded guards and live proofs are the validation.

## Remaining scope

The historical gap stays explicit. Forward development anchoring now works;
missing pre-checkpoint history remains unauthenticated. Existing synthetic
recovery timings are unchanged and do not establish continuous-backup or
enterprise SLA coverage. Human D6, manual accessibility/content review and pilot/
broad-use acceptance remain unproven. Production and RSA use remain NO-GO.

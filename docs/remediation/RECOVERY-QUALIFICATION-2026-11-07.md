# Current recovery and installation qualification

The application runtime is frozen at3512a41, with successful required CI,
complete native load/fault/recovery profile and six nativeAMD64 image gates.
Installer bundle790171d changes installer/operator tooling only; runtime files
remain byte-identical. Recovery tools have a separate reviewed source/CI/hash
binding. The [registry](registry.json) distinguishes completed work from live
qualification and authentic human acceptance.

## Completed engineering evidence

- Staging workflow42388194717 passed guard, qualification and deployment.
  Immutable images/SBOM/provenance/attestation, migration, workers, authenticated
  ACS receipt activation and cloud-completion checks passed. Deployment7623447852;
  evidence artifact13581379690. This is engineering completion, without human GO.
- The preserved normal .105 upgrade completed prepare/checkpoint/rehearse/
  reviewed-cutover/verify. It runs3512a41/schema0060 with both APIs, exact UI,
  thirteen native children and audit/cipher verification. Original source,
  environment, venv, unit, data and seven container/mount identities are retained.
  Real-data restoration proved original table counts, old/new decryption, Redis
  and audit integrity in the isolated rehearsal, including after its forward
  migration, before live cutover. No failed jobs were replayed.
- Native12 measured zero missing acknowledged sentinels and18.975s recovery time
  for its quiesced same-host synthetic dataset. Its300s observation included
  92.936s of delivery acceptance and207.064s idle time. These measurements are
  neither continuous-load/long-term soak evidence nor an enterprise outage SLA.

## Actual clean Linux trials

V3 exposed missing Buildx; PR175 fixes trusted plugin installation and protects
existing engine/runtime providers by validating the exact APT dependency plan.
156author and156independent focused tests pass; mergedmainCI42403025100 passes
4447hermetic,214PostgreSQL,4Redis and14browser tests.

V4 progressed through the real installer to PostgreSQL readiness. Its private
source extractor ran underumask077, making public Git code600/700. Exact VM
diagnostics show the initializer directory/script700 and repeated Permission
denied inside PostgreSQL. This is a qualification-harness fault. Two actual umask
tests reproduce it. The independently reviewed v5 harness restores canonical
Git644/755 file modes and755 code directories only in its new source trees;
configuration, keys, archives and evidence retain private permissions.111author
and111independent checks pass. The v5 live trial is still running at this record.

All earlier VMs/disks/evidence remain preserved and verified deallocated after
their trials/diagnostics. No unexecuted install, reboot or upgrade phase is a pass.
OS publisher certificates apply to distributed native signed packages; the
current Linux server/browser installation does not require such a certificate.

## Off-host recovery work

The [operator tools](../../scripts/operator/recovery-qualification/README.md)
capture complete synthetic state from an actually qualified isolated source A,
encrypt it to a retained controller identity, and restore onto a new target after
source deallocation. The target generates its own identity; a fresh controller
process retrieves the retained key and pipes re-encryption without plaintext on
controller disk. The normal real-data .105 checkpoint stays on the worker.

Capture/restore bind exact Git, host, engine, container, mount, volume, schema,
configuration/key, audit, file and Redis state, plus acknowledged sentinels and
one actual maintenance job. Restore gates the actual installer and installation
verification on complete data proof, then checks readiness, exact UI, thirteen
children, audit prefix and real maintenance progress. Provisioning-inclusive and
restore-only times are reported separately. No continuous-backup schedule,
enterprise escrow/SLA, recipient delivery or human acceptance is inferred.

Actual age1.3.1 synthetic local proofs pass full round trips, separate-target key
re-encryption, wrong-key/tampering rejection and no overwrite. Independent review
caught metadata-size limits and restore target/volume guards before live use;
fixes and repeat review precede code CI and any off-host drill. No off-host cloud
target, storage account or persistent task key exists at this record.

## Preserved development witness disagreement

Read-only follow-up found five retained create-only local witness records with
signed_at timestamps on2026-09-21 at sequences1/62/122/181/241 whose hashes disagree
with the current database at those
positions. The current signed chain is internally consistent (zero verification
problems; observed head104445), but a successful fresh witness is absent. The same
read-back failure appears before the upgrade;1102failed anchor jobs at checkpoint
and1105at follow-up are preserved. No witness, chain, key or failed job was removed,
replaced, replayed or reinterpreted as success.

The bounded metadata inventory of existing worker recovery/qualification roots
identified current November snapshots and no matching September history within
that inspected scope. Matching historical backup evidence may require further
input. API readiness and a successful preservation upgrade do not close this
historical continuity issue, tracked separately asREG-031. Choosing the authentic
historical chain or explicitly starting a new documented development epoch cannot
be inferred from blanket engineering approval. Both histories must remain intact.

## Human evidence remains separate

Current on-prem D6 requires one independent human driver plus manual keyboard and
screen-reader checks. WCAG does not impose a second operator; the original second
usability trial is a stronger pilot criterion. Configured security/privacy review
roles are separate policy checks. Neither automated browser results nor an
engineering approval supplies observed usability results or a signed pilot/broad
GO. Password rotation remains deferred until completed-build signoff.

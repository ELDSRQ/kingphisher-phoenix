# Current recovery and installation qualification

## Completed encrypted off-host recovery

The actual synthetic off-host drill passed on November 8. Source capture-v4
used public recovery tools `fac9a0e` and successful exact CI `42416805378`.
Fresh target-v3 used `ccddc0994cd1be4d0c0736e42b67c31beed1aa9a` and successful
exact CI `42432407730`; all three CI jobs passed. The four source/reader modules
are identical across those commits. Only the target invocation environment changed.

The source passed five original on-host A proofs and exact Git, engine, six
container, complete typed mount, volume and quiescence checks. It captured
synthetic PostgreSQL/globals, Redis, complete files, protected configuration and
keys, audit state, acknowledged sentinels and one actual maintenance job.
On-source encryption, conditional off-host upload and exclusive persistent
controller retrieval agree on ciphertext SHA-256:

`032a1fd4f4131a6692ed46b9cf4164457df6714813e598ecfb0108b654126d79`

The source was verified deallocated before target provisioning. The fresh target
generated its own key; a fresh controller process retrieved the retained identity
and piped re-encryption without plaintext on controller disk. Complete restored
state checks, real installation and verification, both APIs, exact UI, thirteen
native children, audit prefix and actual maintenance consumption with a fresh
anchor heartbeat passed. No acknowledged sentinel was missing.

| Observed scope | Actual elapsed time |
| --- | ---: |
| Restore only | 117.036 seconds |
| Including fresh provisioning | 608.913 seconds |

The successful target is `vm-kp-offhost-20261107-3lkij1-v2` in its matching task
resource group. `target-v3/qualification.json` and `target-v3/deallocated.json`
retain the actual proof and verified final deallocation. Private evidence lives
under `data/qualification/resume-20261107/recovered/offhost-reviewed-v1/`.

These results cover a quiesced synthetic dataset. Continuous backup, enterprise
escrow or outage SLA, recipient delivery and human acceptance were not exercised.
The normal real-data `.105` checkpoint stayed on its worker. Its separately
qualified runtime remains application `3512a41` / schema `0060`.

## Repairs and retained failed attempts

The first capture refused nondeterministically ordered raw Docker mounts. A
24-sample read-only diagnostic found PostgreSQL mount order reversed four times
while all full typed fields, values, counts and duplicates were identical. The
repair sorts canonical complete mount dictionaries and preserves every identity
guard. The actual successful source capture exercised both identity checks.

The first provisioned target passed all pre-startup restored-state checks, then
failed installation because the separately pinned bootstrap uv was absent from
the invocation PATH. Two real-shell regression cases reproduce missing uv and
selection of an unqualified ambient uv. The repair puts the qualified bootstrap
uv directory first. All 238 focused tests, strict mypy for five modules and
lint/format passed before exact CI and the actual successful fresh-target drill.
The initialized failed target, disk, key, restored state and diagnostics remain
preserved and deallocated. Fresh-target refusal guards were not bypassed.

Quota blocked the first preflight before compute. The Dsv7-family increase was
unavailable; regional quota increases from 10 to 12 and then 14 succeeded. A
separately pinned unrestricted `Standard_D2as_v7` target supplies two native AMD64
vCPUs and 8 GiB. Every earlier VM and disk remains preserved. Deallocated VMs
continue to count against quota, as documented by
[Microsoft](https://learn.microsoft.com/en-us/azure/virtual-machines/quotas).

Original temporary source provisioning receipt bodies are unavailable. Explicit
recovered-stage/current-VM attestation binds the recorded eight actual A stages
and Azure VM UUID/time/disk; it does not fabricate missing historical receipts.
Actual capture still required the five original on-host proofs and exact assets.
The controller identity remains private mode `0600` and was never sent to source.

## Clean Linux installation and upgrade

V3 exposed missing Buildx; PR175 fixed trusted plugin installation with bounded
APT transaction checks. V4 exposed private-umask masking of public Git permissions;
two actual extraction regressions reproduced it. The reviewed v5 extractor sets
only new verified public code to canonical modes and retains private state modes.
All eight actual v5 A bootstrap/install/browser/warm/repair/reboot stages passed
against installer `790171d` and exact main CI `42403025100`.

The separate B daemon initially rejected simultaneous `bridge` and `bip`, before
importing state. A new configuration removed only `bip` and preserved the bridge.
A later preparation attempt reached a live daemon but correctly failed the
private-containerd guard: the Ubuntu Docker package selected the system socket
`/run/containerd/containerd.sock`. Retained journal evidence proves that selection;
B remained unselected with no baseline or upgraded source imported.

The tested v5 continuation preserves the initialized B directory and engine ID,
checks it has no containers or named volumes, and explicitly configures private
containerd metadata, runtime and socket paths within B. This follows the
[containerd configuration contract](https://raw.githubusercontent.com/containerd/containerd/main/docs/man/containerd-config.toml.5.md).
All 100 continuation tests pass, including the actual unchanged isolation guard,
state-drift refusal, no overwrite and final deallocation behavior. Read-only live
preflight and all five actual phases passed in `resume-v5-v5/`: prepare, baseline,
upgrade, final browser and final proof. The baseline `0056_adaptive_draft_boundary`
at `acabf08` upgraded to `0060_delivery_authority_locks` at installer `790171d`.
Final real browser login and volume, key and audit preservation passed. Final
qualification verifies source deallocation and complete original timer restoration.
These new B receipts do not relabel original A proofs as newly executed A stages.
The earlier A reboot proof covers installer-mediated relaunch; automatic startup
without that relaunch remains outside the qualified scope.

The source VM is verified deallocated and its complete original shutdown schedule
restored after each completed bounded visit. Earlier failed assets and evidence
are retained. The current Linux/browser installation requires no OS publisher
certificate; other native-package matrices remain separate scopes.

## Preserved development witness disagreement

Read-only follow-up found five retained create-only local witness records with
`signed_at` timestamps on 2026-09-21 at sequences 1/62/122/181/241 whose hashes disagree
with the current database at those
positions. The current signed chain is internally consistent (zero verification
problems; initial observed head 104445), but a successful fresh witness is absent. The same
read-back failure appears before the upgrade; 1,102 failed anchor jobs at checkpoint
and 1,105 at follow-up are preserved. No witness, chain, key or failed job was removed,
replaced, replayed or reinterpreted as success.

The first bounded worker recovery/qualification inventory found current November
snapshots. A further repository/handoff search identified a separate documented
`migration-checkpoint` directory. Actual read-only metadata found its September
21 19:14 checkpoint; the 182,430-byte dump matches its retained manifest at SHA-256
`14d32bd156bb27370cd36692218a41d73c3d7d5371a27ff71498a5088272e40d`.

An independently reviewed operator with 31 passing tests actually restored only
`audit_events` and `audit_chain_head` pre-data/data into a new network-none
PostgreSQL container and volume. It restored **three events and one head**:
position 1 differs from the old witness, and positions 62/122/181/241 are absent.
The three events form a unique genesis-linked chain and its stored head matches
its terminal hash. A fresh read-only check of today's internally verified chain
(observed head 104717) confirms positions 1 and 3 match this checkpoint prefix.
This identifies the later development lineage; it does not recover the earlier
witness history. No historical signature authentication, complete restore or
continuous history is claimed. Globals, credentials, current database and keys
were excluded. The new test container is stopped and retained; all original
containers/mounts, checkpoint files and witnesses passed preservation checks.

`REG-031` therefore requires an explicit development-history scope choice, not
another assumed successful recovery. The recommendation is to retain today's
verified data and every older artifact, record the discontinuity explicitly,
and begin a new **development** anchoring epoch. That choice authorizes a new
private witness directory, one active configuration-key change, a bounded
restart of the owned development service and its thirteen native children, a
declaring audit record and a fresh maintenance anchor after independent review
and testing. It preserves old failed jobs without replay and supplies no
production/RSA GO or recovered historical continuity.

The alternatives are to provide a matching earlier backup/key location for
read-only inspection and an isolated recovery before choosing history, or keep
the continuity gate open without changing active configuration or history. The
choice is needed because engineering approval cannot establish historical
authenticity, and restoring the located three-event checkpoint would discard
current work. A documented new epoch is recommended to retain that work while
declaring the gap. No epoch change has been executed and an unanswered question
does not authorize it.

## Human evidence remains separate

Current on-prem D6 requires one independent human driver plus manual keyboard and
screen-reader checks. WCAG does not impose a second operator; the original second
usability trial is a stronger pilot criterion. Configured security/privacy review
roles are separate policy checks. Neither automated browser results nor an
engineering approval supplies observed usability results or a signed pilot/broad
GO. Password rotation remains deferred until completed-build signoff.

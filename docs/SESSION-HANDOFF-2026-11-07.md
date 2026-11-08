# November 7–8 continuation: persistent recovery qualification

Continue the existing authorization to remediate until the registry is complete
or no engineering work can proceed. Preserve the original checkout at
`main@cf659d5` and its seven campaign UX changes. The live installer trials were
bound to `790171d`;
the qualified `.105` runtime is `3512a41` / schema `0060`, running from its
separate `kp-runtime-releases` directory. Its old checkout HEAD is not the
active release. Main stayed frozen until both actual off-host and B upgrade
proofs completed.

Recovery [PR #176](https://github.com/ELDSRQ/kingphisher-phoenix/pull/176)
contains public recovery tools `ccddc0994cd1be4d0c0736e42b67c31beed1aa9a`;
final documentation and integration status are recorded in that PR.
[Exact CI 42432407730](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/42432407730)
passed all three jobs. Public recovery checks pass 238 focused tests and strict
mypy for five modules. The mount-comparison fix used source tools `fac9a0e`;
the target-only uv PATH fix used `ccddc099`. Source/reader module hashes are equal.

## Persistent work and evidence

Old temporary controller copies are absent. Work and original failed evidence
are preserved under `data/qualification/resume-20261107/`. Read the highest-numbered
`ACTIVE-STATE-v*.json`, then inspect live process/receipt state before any retry.

- `reconstruction-manifest.json` records 315 recovered files and historical
  hunk-context gaps. Not every reconstructed file is reviewed or complete.
- `recovered/qualified-tools/` is the registered detached public worktree.
- `recovered/offhost-reviewed-v1/` holds private controllers, requests, tests
  and actual phase evidence. Requests are in `recovered-inputs-v1/`.
- Frozen source coordinator and guest retain their original SHA-256 pins.
  A separately pinned target coordinator selects unrestricted native AMD64
  `Standard_D2as_v7`, two vCPUs and 8 GiB.
- Missing original temporary provisioning receipt bodies are explicitly recorded.
  New attestation binds the recorded eight actual A stages and current source
  VM UUID, creation time and disk; it does not invent historical receipts.
- The retained age identity stays private in
  `data/recovery/offhost-20261107-3lkij1-v1/`; never print it or send it to source.

## Completed actual off-host drill

Source `capture-v4/` passed with exact public `fac9a0e` / CI `42416805378`:
five original on-host A proofs, complete protected synthetic PostgreSQL/globals,
Redis, project files, configuration/key, audit, sentinel and maintenance state.
Source encryption, conditional private blob upload and exclusive persistent
controller retrieval agree on ciphertext SHA-256:

`032a1fd4f4131a6692ed46b9cf4164457df6714813e598ecfb0108b654126d79`

Source VMv5 was verified deallocated before target provisioning. Fresh controller
retained-key retrieval and piped rewrap supplied a target-local key without
plaintext on controller disk. The first provisioned target restored all data but
failed installation because the qualified uv executable was outside PATH. Its
initialized state, disk, key and diagnostics remain preserved and deallocated.
Two real-shell regressions reproduced the missing/ambient-wrong uv selection.

After the target invocation repair and exact green CI, a new isolated target
passed `target-v3/qualification.json`: zero missing acknowledged sentinels,
**117.036 seconds restore-only**, **608.913 seconds including provisioning**,
real installation/verifier/API/exact UI/thirteen native children/audit prefix,
and actual maintenance consumption with a fresh anchor heartbeat. Final
`target-v3/deallocated.json` verifies the successful VM is off.

The successful VM/RG names end `offhost-20261107-3lkij1-v2`; the failed physical
VM/RG ends `v1`. Regional quota increases 10→12→14 preserve every earlier VM and
disk. Dsv7-family expansion was unavailable, so the separately pinned Dasv7 target
was used. No cleanup, overwrite or fresh-target-guard bypass occurred.

Private `controller_v8.py` is pinned to
`9c98c63fd67b2a87cc784887c26c044a9698da7a77e1a75f4c1c91d4ff3720dc`;
`bootstrap_target_v2.py` to
`ad2e4c595abd4cbd010a16b30abe3a7e39a52de5428d33520904bf0dbb600552`.
Successful request is `target-request-v4.json`; local evidence is `target-v3/`.
Normal `.105` real-data recovery evidence stays on its worker. These measurements
cover only the quiesced synthetic dataset, not continuous backup, an enterprise
outage SLA, recipient delivery or human acceptance.

## Completed B upgrade continuation

Source `vm-kp-cleanlinux-20261106-3lkij1-v5` passed the original eight A stages.
Its original B launch failed before data import on conflicting bridge/bip.
The preserved root was observed empty in `B-inspection-v3/`. The v4 retry kept
the bridge and removed bip; Docker became reachable but selected system
containerd `/run/containerd/containerd.sock`. The unchanged isolation guard
correctly refused. `B-prepare-inspection-v2/` retains that actual journal proof,
initialized B inode/entries and absent selection/baseline/upgrade. Both diagnostics
verified source deallocation and complete original shutdown-schedule restoration.

`resume_v5_upgrade_v5.py` preserves that initialized B directory and engine ID,
refuses existing containers/volumes/imported images, and starts explicitly private
containerd root/state/socket paths within B. Its 100 tests and Ruff pass. Actual
read-only `B-live-preflight-v2/` passed before execution. Request is
`resume-request-v5.json`, SHA-256
`0568975cab60a7703c866adf1166aa04e2d5eb04a8afa41e923be8a09ca248d3`;
helper SHA-256 is
`ea8a6ca2e582e91dd2f6c702371094f5dc37e6a625b104301544e2731979d27f`.

All five actual phases PASSED in `resume-v5-v5/`: preparation, baseline,
upgrade, final browser and final preservation proof. The actual baseline is
`acabf08` / schema `0056`; target is installer `790171d` / schema `0060`.
`qualification.json` verifies completion plus source deallocation and full
original shutdown-schedule restoration. Exact original B directory/engine ID,
volume and key identities and audit history were retained. The eight original
A stages remain historical proof; they were not copied as newly executed stages.
Automatic startup without installer-mediated relaunch remains unqualified.

The registry closes Linux and encrypted off-host engineering work. Publication
requires exact green CI; its integration result is recorded in PR176 and the
latest persistent state. No configuration
or historical-data mutation is authorized by an unanswered scope question.
Preserve root UX changes, `.venv`, normal `.105` runtime, data, every failed
VM/disk/evidence artifact and retired `.140` assets. Do not rerun fresh phases
over initialized state or delete/reset/re-restore it.

## Completed development anchoring epoch and human evidence

The user instructed “Action recommended path” on November 8. The recommended
new development anchoring epoch has completed; that history-scope choice is
answered and must not be requested again. Read the
[actual epoch report](remediation/DEVELOPMENT-AUDIT-EPOCH-2026-11-08.md) and latest
`data/qualification/audit-epoch-20261108/STATE-v*.json`.

The new private pre-change checkpoint remains on .105. A signed declaration
records the accepted gap; only the active release's local-anchor directory key
changed. Original configuration inode/bytes, five September witnesses/checkpoint,
old audit prefix, all seven containers/mounts and 1,131 old dead letters are
preserved. One new maintenance job produced a matching witness at sequence106881
and a successful anchor heartbeat at 15:35:51UTC. Both APIs, exact UI, thirteen
native children, ciphertext and business-table counts verified. The task's
fallback timer was disarmed after final verification, retaining its definitions
and evidence. Original failed attempts and partial checkpoints remain preserved.

Application3512/schema0060 and every other configuration value remain unchanged.
Do not edit the old immutable upgrade plan to hide its expected configuration
hash difference: bind the current accepted environment through the epoch manifest
and final receipt. The checkpoint precedes the epoch switch and retains its
known old witness disagreement. No post-epoch restore or recovered/authenticated
missing earlier history is claimed. Registry REG031/W2-03 engineering is complete.

On-prem D6 still requires one independent human driver plus manual keyboard,
screen-reader and email/training review. Pilot/broad-use GO requires authentic
human acceptance and signatures. Password rotation remains deferred until
completed-build human signoff. Production/RSA remains NO-GO.

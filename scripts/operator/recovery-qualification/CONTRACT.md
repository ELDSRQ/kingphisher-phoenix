# Synthetic off-host clean-room recovery contract v1

This repeatable operator qualification supplements the completed real-data
rehearsal. Never export the normal `.105` checkpoint, alter global workstation
DR/Alice, overwrite existing assets, or claim continuous-backup/business SLAs.
All live execution requires explicit root review; module CLIs default to plans.

The application runtime components remain qualified at3512a41. Source/target
installer bundle is immutable790171d or its explicitly reviewed later equivalent;
recovery operator tooling has a separate commit/CI/hash binding. Every source
Git blob and executable membership must match the pinned source manifest.

## Shared modules and stable interfaces

- Root owns `common.py`, this contract, README, `run.py`, private frozen cloud
  controller integration and shared-contract changes. Public tooling does not
  duplicate infrastructure provisioning. `common.py` supplies safe
  authored errors, O_EXCL private IO, path/budget bounds and private command
  diagnostics. No argv, environment or input payload is logged. Commands that
  return keys/SAS/plaintext must use `record=False`; crypto pipelines never log
  plaintext.
- Artifact lane owns `artifacts.py` and `tests/test_offhost_recovery_artifacts.py`.
  Public functions: `encrypt_snapshot(snapshot: Path, output: Path, recipient:
  str, *, age_command: str, deadline: float) -> dict`,
  `decrypt_snapshot(cipher: Path, identity: Path, destination: Path,
  expected_sha256: str, *, age_command: str, deadline: float) -> dict`,
  `rewrap(cipher: Path, identity: Path, recipient: str, output: Path,
  expected_sha256: str, *, age_command: str, deadline: float) -> dict`.
  Also `upload_cipher(path, url, expected_host, *, deadline) -> dict` and
  `download_cipher(url, expected_host, output, expected_sha256, *, deadline) -> dict`.
  URLs are private HTTPS exact blob-host/path requests, no redirects/proxies;
  conditional PUT prevents overwrite. Return only digest/bytes/ETag/public
  recipient, never SAS/keys/plaintext. Read/write bounded archives, refuse all
  links/devices/traversal/duplicates/extra or missing members. Validate the
  complete file manifest before extraction; new destinations only. Rewrap is
  decrypt-to-encrypt pipes, without plaintext on controller disk.
- Source lane owns `source_capture.py` and `tests/test_offhost_recovery_source.py`.
  `capture(request: dict) -> dict` creates the plaintext snapshot and returns
  `{snapshot: absolute_path, manifest: object}`; `main()` accepts a private JSON
  request path, defaults to a plan, and requires `--execute-after-review`.
- Restore lane owns `target_restore.py` and `tests/test_offhost_recovery_target.py`.
  `restore(request: dict) -> dict` returns the final safe qualification summary;
  same private-request/default-plan/explicit-execution CLI pattern. It consumes
  artifact helpers and never provisions Azure or contacts the source host.

## Snapshot layout and manifest

One authenticated age-encrypted deterministic tar.gz contains `manifest.json`,
`postgres.dump`, `globals.sql`, `redis.rdb`, `redis-inventory.json`, `state/.env`,
optional `state/docker-compose.override.yml`, and the complete `state/data/`
regular files including recovery/key/witness/monotonic state. No source code,
`.git`, `.venv`, symlinks, devices, or source private age identity is included.
Do not blanket-exclude `data/run`. Capture never removes or ignores PID files
and refuses ambiguous PID state. Normal application shutdown handles its own
ephemeral markers. If a retained marker predates a later VM boot, a separate,
independently reviewed maintenance operation may archive that exact marker by
same-filesystem rename only after binding the host, source, original boot and
marker metadata, proving its PID absent and rechecking all units, cgroups and
source processes. Preserve its inode, bytes and metadata, record the move, retain
the archive inside `data/recovery` for the complete backup, and rerun capture's
unchanged canonical quiescence guard. This never permits deleting state, killing
an unidentified process or treating a live or ambiguous marker as safe.

`manifest.json` has `schema=kp.offhost-recovery.snapshot.v1`, `run_id`,
`scope=synthetic-qualification`, `created_at`, `application` (bundle_commit,
runtime_commit,schema_head,source_root), `source` (hostname,vm_id,engine_id,
docker_host,docker_root,containers), `data` (database schema/table_counts/audit
coordinates; Redis logical inventory reference; protected-purpose key SHA256s;
acknowledged PG/Redis/file sentinel values and one queued maintenance job's
topic/id/idempotency_key/acknowledgment), and `files` mapping every non-manifest
member to `{sha256,bytes,mode}`. Modes are four-digit octal, private600 or700.
No raw keys/passwords in manifest metadata. JSON/file SHA256s bind exact bytes.
Encryption alone does not authenticate a backup sender: expected cipher SHA256
from the controller's authenticated source receipt is mandatory for restores.

## Source request and explicit A-only capture

`schema=kp.offhost-recovery.source-request.v1`, `run_id`, `scope`, `deadline`
(UTC epoch), `source_mode=A`, `expected_hostname`, `expected_vm_id`,
`source_root=/srv/kp-cleanlinux/clean-target`, `output` (new private directory),
`application` (bundle_commit,runtime_commit,schema_head), `expected_engine`
(id,root,socket), `expected_containers` and `source_git_manifest` are required.
`source_git_manifest` is an inline Git relative-path to `{blob,mode}` mapping.
`proofs` binds each of the five A provenance documents below by absolute path
and SHA256. Volume identities are derived from the authenticated A proofs;
container descriptors are cross-checked with `expected_containers`.
The private source request supplies only the controller's public age recipient;
controller/root invokes artifact encryption/upload after capture. Never place
the controller identity on this VM.

Use an actually qualified clean trial's **A** state in a NEW bounded capture
operation after that trial ends. The failed v4 cold-install trial supplies no
qualified A state and cannot satisfy this requirement. The controller must
explicitly choose a later passing trial; no source is selected automatically.
The exact request and IMDS identity must match the paired task resource-group
and VM namespace `rg-kp-cleanlinux-20261106-3lkij1-vN` and
`vm-kp-cleanlinux-20261106-3lkij1-vN`, with the same bounded N>=4 and the reviewed
subscription. Restart only that exact VM. Read A's preexisting
`reboot-after.json`, `A-container-inventory.json`,
`A-preserved-before-B.json`, later `reboot-final-state.json` and
`clean-target-source-proof.json`; bind source,
engine ID/root/socket, all6container IDs/images/mounts/services/volumes. Require
B unit/socket/processes inactive. Ignore (never delete) persistent
`upgrade-engine-enabled.json`; old guest.environment/run/phase helpers select B
and MUST NOT be reused. Explicit A env and Docker socket only, no fallback.
Start only the recorded A PostgreSQL/Redis containers when needed. Prove source
app units/native children quiescent; do not kill delivery alone. Capture data
under read-only/query-scoped operations except acknowledged synthetic PG/Redis/
file sentinels and one real supported maintenance publish after quiescence.
Use current live state after legitimate relaunch, not a stale pre-relaunch byte
manifest. Re-deallocate exact source VM on every exit before target restore.

## Target request and restoration

`schema=kp.offhost-recovery.target-request.v1`, `run_id`, `scope`, `deadline`,
`expected_hostname`, `expected_vm_id`, `expected_engine`, `source_root` (fresh
verified Git source), `source_git_manifest`, `output` (new private evidence),
`cipher_path`, `identity_path`, `expected_cipher_sha256` and `application` are
required, along with `app_user=kpqual` and `source_deallocated` containing
`verified=true` and the SHA256 of the controller's actual deallocation receipt.
The target records this as a controller attestation, not a target-side Azure
observation. Source VM must already be verified deallocated by controller, and
target receives no source address or source-access credential.

Controller provisions a NEW isolated Ubuntu target with45min work,50min
independent shutdown/evidence,55–60min fallback deallocation. No public IP,
managed identity, existing volumes, or existing-network changes. Provision
trusted Docker/Compose/Buildx, age and pinneduv/frozenvenv without running the
full installer first. Verify fresh target engine/no containers or volumes and
all source bytes/modes. Restore into NEW empty canonical Compose resources;
never run delete/prune/down/restore-over-live. Prefer RDB-to-AOF materialization
in a NEW uniquely labeled retained helper/volume before the canonical Redis
service starts; do not invoke deletion-bearing existing WSL restore scripts.
PG globals restore may omit only the exact bootstrap owner's duplicate CREATE
ROLE; preserve all passwords/privileges and restore the app into empty tables.

Restore all protected keys/config/state; retarget only declared source-root
path settings to the new root and prove protected-purpose fingerprints remain
equal. Before app startup compare all table counts/schema/audit/ciphertext,
Redis persistent+unexpired logical contents and all restored file hashes.
Then real `install.sh --skip-deps`, `verify_install.sh`, both readiness endpoints,
exact UI bytes and13native child bindings must pass. Preserve audit prefix and
prove captured maintenance work is present before startup and consumed by real
workers afterward, with a fresh real completion heartbeat. No fake provider or
human/campaign-delivery evidence. Controller records provision-inclusive and
restore-only RTO separately, zero missing acknowledged sentinels as quiesced
RPO, and independent off-host archive/key retrieval under this precise scope.

## Immutable data and execution boundaries

Controller owns a separately named persistent private task age identity; source
gets public recipient only. Keep an O_EXCL controller ciphertext copy and a
conditional-create authenticated blob copy. A fresh controller process retrieves
that retained identity and re-encrypts through pipes to a target-generated public
recipient. Neither private identity enters RunCommand/argv/logs/opposite host.
Every partial file/container/volume/VM/disk/key/log is retained. All source and
target resources are explicit task identities, and all budget/error exits
preserve them and verify deallocation. Existing v1–v4 snapshots are not edited.

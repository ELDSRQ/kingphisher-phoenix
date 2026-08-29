# External Docker worker on `.140`

This directory defines the target canonical engineering/qualification worker.
The controller keeps its source workspace; SSH reaches
`edierks@192.168.1.140`; the canonical remote source is
`/Users/edierks/Projects/kingphisher-phoenix`; and that source is mounted
read-only inside the dedicated `kingphisher` Colima VM. The target VM, cache,
client metadata, and socket are rooted under:

```text
/Volumes/DockerExternal/KingPhisher-Phoenix
```

Docker Desktop on `.140` is a separate shared engine with unrelated workloads.
Do not move its global disk image, select it as a project fallback, change the
global Docker context, or stop/prune/remove any unrelated resource.

> **Current state (2026-08-28): external cutover and restore passed.** The
> external socket/profile and read-only source mount passed preflight. The
> inactive `kp-external-mac` controller context has exact endpoint
> `ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock`
> and returns
> `colima-kingphisher|aarch64|/var/lib/docker`; `docker context show` remains
> `desktop-linux`. The seven internal Docker Desktop project containers are
> stopped/preserved; unrelated containers remain running.
> Snapshot `20260829T013332Z-tsX1WQ` (archive SHA-256
> `e4fb16a735d0c9d3b6aa04381c4c9d7e24269006203c551f50abf671cc3637ff`)
> passed staging and restore. External installation and `verify_install.sh`
> passed; later full-suite/image/browser/cloud gates remain NO-GO.

The legacy Docker contexts named `DockerExternal` and `kp-remote-mac` omit the
reviewed socket path and can resolve to shared Docker Desktop; never use them
for project operations. The external volume named `DockerExternal` is the
required storage target, not a Docker context.

## One-time setup

Copy this entire directory to the external bootstrap kit and double-click
`bootstrap-macos.command` on `.140`. The script:

- verifies that the exact reviewed `DockerExternal` volume is mounted and
  writable;
- enables SSH for the supplied Ed25519 controller key;
- installs only missing Docker CLI/Colima dependencies through Homebrew;
- starts the native ARM64 `kingphisher` profile with Rosetta, binfmt, and
  Kubernetes disabled;
- preserves the ambient `desktop-linux` context; and
- runs the fail-closed external-engine preflight.

Never use `brew services start colima`: its service environment may omit the
external home and start an internal default profile.

From the controller, run the read-only qualification:

```sh
scripts/operator/remote-docker-worker/preflight.sh
```

The fixed external volume UUID is
`FD7BE277-8CB4-3ADA-8CA2-11F8EBBBADF4`. An absent, renamed, read-only,
wrong-UUID, symlinked, or low-capacity mount blocks all project Docker work. It
never causes Docker Desktop fallback.

## Explicit engine use

On `.140`, every project command goes through the helper:

```sh
cd /Users/edierks/Projects/kingphisher-phoenix
scripts/operator/remote-docker-worker/external-engine.sh preflight
scripts/operator/remote-docker-worker/external-engine.sh docker ps
scripts/operator/remote-docker-worker/external-engine.sh compose ps
scripts/operator/remote-docker-worker/external-engine.sh run ./scripts/verify_install.sh
```

The project socket is:

```text
/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock
```

The `run` command executes a project command from the canonical source with the
external socket, Docker client directory, and fixed Compose project name scoped
to that child only. Use it for restore, installer, qualification, and image
commands. The `env` command exists for diagnostics; do not export its values
globally. Registry secrets use the macOS Keychain credential helper; inline
credentials in the external Docker client configuration are rejected.

After the socket is verified, the controller can create a dedicated inactive
SSH context whose endpoint
includes the remote socket path:

```sh
docker context create kp-external-mac \
  --docker host=ssh://edierks@192.168.1.140/Volumes/DockerExternal/KingPhisher-Phoenix/colima/kingphisher/docker.sock
docker --context kp-external-mac info
```

Always include `--context kp-external-mac`; do not make it the default. A
dedicated Buildx builder may target that context. Native ARM64 output is valid
worker evidence. Emulated AMD64 is compatibility evidence only; release-grade
AMD64 still requires a native AMD64 worker or CI runner.

## State cutover and recovery

Before a first restore, prove the external engine has no project containers or
named volumes. Create and validate a fresh logical PostgreSQL/Redis checkpoint,
then stop only the project host supervisor and internal project containers and
restore from the canonical complete source tree:

```text
/Users/edierks/Projects/kingphisher-phoenix
```

The small staging tree under `~/projects/codex-test` is not a valid source. All
new Compose `working_dir` labels must resolve to the canonical tree and the VM
mount must be read-only. Preserve every migration snapshot, staging tree, and
internal project container/volume. The existing legacy encrypted snapshot is
not a recovery source: its age identity is absent from both controller and
remote Keychains, so it is unrecoverable and does not satisfy `EXT-002`.

The controller has a separate verified Keychain recovery identity under service
`com.kingphisher.phishing-awareness-platform.migration-recovery.v1`, account
`phishing-awareness-platform-recovery`, with public recipient:

```text
age1p9t25wm9uvcaafjv3hjmgsj092mgydrr9uzndjnmcq9psupfl94qm8h2w2
```

Headless SSH cannot unlock the remote login Keychain. Do not copy a persistent
private identity to `.140` or print it. Run the controller wrapper, dry-run
first and then apply only after the external engine is verified and disk
provisioning is no longer contending:

```sh
scripts/operator/remote-docker-worker/recovery-identity.sh verify
scripts/operator/remote-docker-worker/checkpoint-remote.sh
scripts/operator/remote-docker-worker/checkpoint-remote.sh --apply
```

`checkpoint-remote.sh` verifies the remote `checkpoint-state.sh` SHA-256, reads
the identity from the exact controller Keychain item into a unique mode-0600
file, transfers it only under `/private/tmp/kp-recovery-transfer.*`, and removes
the exact controller and remote transfer files on every exit path.
`checkpoint-state.sh` requires the exact healthy Docker Desktop PostgreSQL and
Redis source, validates both logical snapshots, includes the complete preserved
source/configuration/evidence tree, writes new database state only under the
reserved `migration-checkpoint/` archive path, encrypts and decrypt-validates
the result, and proves unrelated container identities/running states did not
change. Dry-run is the default. No successfully applied new checkpoint is
claimed until the resulting unique snapshot, digest, recipient, and decrypt
validation are recorded.

Stage only the validated new archive's `migration-checkpoint/postgres.dump` and
`migration-checkpoint/redis.rdb` under the canonical source; never substitute
the legacy `artifacts/` files. After the checkpoint exists, use the controller
wrapper, dry-run first:

```sh
scripts/operator/remote-docker-worker/stage-remote.sh \
  --archive /Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots/<exact-direct-child>/kingphisher-project-migration.tar.age
scripts/operator/remote-docker-worker/stage-remote.sh --apply \
  --archive /Volumes/DockerExternal/KingPhisher-Phoenix/migration-snapshots/<exact-direct-child>/kingphisher-project-migration.tar.age
```

`stage-remote.sh` verifies the remote `stage-checkpoint.sh` hash before
controller Keychain access, transfers the identity only through exact mode-0600
`/private/tmp/kp-recovery-stage-{controller,transfer}.*` files, and cleans both
on every exit. It never copies, changes, or removes the archive and never
selects Docker Desktop. The remote stager requires one explicit direct-child archive, validates the outer SHA and
metadata plus the decrypted schema/manifest/source/container bindings, rejects
unsafe archive members and identity drift, and uses the external engine to
validate the PostgreSQL/Redis payloads. The pinned validation images must
already be preloaded and qualified on the clean external engine because staging
uses `--pull never`. Dry-run is the default; apply publishes only to the absent
reserved `migration-checkpoint/` path and refuses clobber. This helper is
locally contract-tested but has not been live-run.

`restore-state.sh` deliberately accepts only a clean engine. It proves the
PostgreSQL archive in a disposable database, then restores the empty target.
For Redis, it loads the RDB with AOF disabled, materializes a non-empty AOF,
proves both keyspaces, and only then starts the normal service. This ordering
prevents an empty Redis 7 AOF from superseding and later overwriting a valid
RDB.

Run it through the scoped external-engine command so an ambient Desktop context
can never receive the restore:

```sh
scripts/operator/remote-docker-worker/external-engine.sh run \
  ./scripts/operator/remote-docker-worker/restore-state.sh --apply
```

After restore, require exact migration head, database and Redis durability,
audit-chain verification, dependency `/readyz`, installation verification,
and live local E2E evidence. Record unrelated Docker Desktop container IDs and
status before and after cutover to prove non-interference.

## Access and rollback

Loopback URLs such as `127.0.0.1:8000` refer to `.140`. Access them in a browser
on `.140` or use an SSH tunnel from the controller; do not expose the Docker API
over TCP.

Rollback is stop-only and preservation-safe: stop the external project
supervisor and only its project containers, stop Colima without deleting it,
explicitly select Docker Desktop for the preserved project copy, and restart
that copy and its supervisor. Never run both project stacks at once because
their host ports conflict. Never use Compose `down`, `colima delete`, Lima disk
deletion, volume/image/builder removal, or any prune command.

The USB HFS+ worker is engineering infrastructure, not the Azure production
topology. It lacks disk encryption, SMART telemetry, and production storage
availability guarantees; use synthetic/approved test data and retain encrypted
recovery copies. Azure production remains independently gated.

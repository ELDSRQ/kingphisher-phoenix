# Synthetic off-host recovery qualification

These operator tools qualify a complete recovery on separately provisioned,
disposable Linux hosts. They supplement the preserved real-data development
upgrade rehearsal. They never select or export the normal development stack,
authorize campaign recipients, rotate credentials or grant production approval.

The immutable application runtime is `3512a41`; the clean Linux installer bundle
is `790171d`. Recovery tooling has its own reviewed commit, successful CI and
file-digest manifest. Record all three bindings. Tool-only changes do not claim
new application-image qualification.

## Execution boundary

Each script defaults to a local plan. Live execution requires an owned private
JSON request and `--execute-after-review`. `run.py` dispatches exactly one phase
and requires an exclusive private receipt path plus exact hashes of all five
tool modules. It verifies those bytes before importing the operation module.
Requests, receipts and diagnostics must remain private; do not paste requests,
storage URLs, configuration, plaintext backups or identities into terminal logs.

`source_capture.py` and `target_restore.py` run on their respective hosts with
explicit host, engine, source and asset identities. The controller provisions
and bounds those hosts separately. Public tools contain no cloud provisioning,
implicit source discovery, cleanup or destructive recovery commands.

The [request and snapshot contract](CONTRACT.md) defines exact fields and
ownership. `run.py` uses schema `kp.offhost-recovery.phase-request.v1`, scope
`synthetic-qualification`, an absolute UTC `deadline`, `phase`, `tool_manifest`
(the five filenames mapped to SHA256) and an `operation` object passed to the
corresponding function. Source/restore operation deadlines cannot exceed the
dispatcher deadline. Source/target CLIs accept their host-specific requests
directly when the external controller binds the same tool hashes.

## Qualification sequence

1. Retain a new controller age identity as a private project recovery asset.
   Give only its public recipient to the qualified isolated source host.
2. Capture that host's quiesced synthetic database, globals, complete project
   state, keys, witness, Redis data and acknowledged sentinels. Queue one real
   supported maintenance job after quiescence. Bind every archive member.
3. Encrypt on the source. Upload only ciphertext through an exact authenticated
   HTTPS blob path, using a conditional create. Independently retain an exclusive
   controller ciphertext copy and its SHA256. An existing object is a failure;
   it must never be overwritten or removed to retry.
4. Verify source VM deallocation and retain that actual cloud receipt before
   restoring anything. The target receives its digest as a controller attestation.
5. Provision a new isolated target without application data or volumes. Generate
   its private age identity on that target and return only its public recipient.
6. In a fresh controller process, retrieve the retained controller identity and
   original ciphertext. Re-encrypt through pipes to the target public recipient;
   plaintext never lands on controller disk. Upload the new ciphertext as a
   separate conditional-create object and download it on the target.
7. Restore into new, empty canonical Compose resources. Verify every original
   table count, audit chain, encrypted entity, protected key, file and applicable
   Redis value before application startup. Preserve all helper containers/volumes.
8. Run the actual installer and installation verification as the unprivileged
   application user. Verify both APIs, served UI bytes, thirteen child processes,
   the old audit prefix, recovered sentinels and real maintenance progress.
9. Record restore-only and provisioning-inclusive recovery time separately,
   missing acknowledged sentinels and all exact asset/source/tool bindings.
   Deallocate the exact target on every exit and preserve disks and evidence.

The age identity and archive are required recovery assets. A retained task
identity demonstrates this drill's independent key retrieval; it does not
establish enterprise escrow, a second custodian or a recurring backup service.
The expected ciphertext SHA256 must come from the controller's authenticated
source receipt: public-key encryption alone does not authenticate the sender.

## Evidence limits

Zero missing acknowledged sentinels is a quiesced test RPO. Measured elapsed
times describe this synthetic dataset and host profile, with provisioning
reported separately. They are not an uninterrupted-service claim, a continuous
backup schedule or an enterprise outage SLA. Queue progress is maintenance work;
it is never evidence of recipient delivery or human acceptance.

All partial files, failed diagnostics, identities, containers, volumes and cloud
disks remain preservation-required assets. Repeating a trial uses a new explicit
namespace and fresh deadlines. No retry may delete or replace prior evidence.

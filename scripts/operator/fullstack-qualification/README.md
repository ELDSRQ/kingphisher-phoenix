# Isolated native full-stack qualification

Run only on the reviewed `.105` WSL2 host against its explicit native Docker
socket. This harness never uses Compose or normal project container/volume/port
names. All source and restored resources, logs, partial snapshots and test
messages are preserved. It never cleans up or reclaims storage.

Each new run creates a dedicated bridge (`Internal=false`) so Docker publishes
the required host ports. Every expected publication must be explicit IPv4
`127.0.0.1`; absent, wildcard, extra or malformed bindings and stopped services
fail closed after their new identities are recorded. Every pinned image must
inspect as native Linux/AMD64. No all-egress isolation is claimed; the proxy
independently restricts SMTP envelopes to synthetic `.test` addresses.

The declared full profile is 125/1,250 recipients, a 300-second soak, a
1,800-second absolute deadline, a 600-second drain, normal API p95 ≤ 1 second,
critical maintenance progress ≤ 2 seconds, and quiesced acknowledged-sentinel
RPO 0 / RTO ≤ 15 minutes. A
three-recipient smoke must pass before running that profile.

First stage the reviewed source into a new qualification directory and select
an environment containing its frozen dependencies. Do not copy `.env`, normal
data or credential files. The first smoke uses native source processes; this
does not qualify final deployment images. Source hashes and interpreter scope
are recorded, and source drift during execution refuses a pass.

Obtain the expected hostname and engine ID with read-only commands through the
reviewed SSH endpoint, then invoke from that same host:

```sh
python scripts/operator/fullstack-qualification/run.py \
  --source /absolute/staged/source \
  --output /absolute/existing-parent/new-smoke-directory \
  --expected-hostname REVIEWED_WSL_HOSTNAME \
  --expected-engine-id REVIEWED_NATIVE_ENGINE_ID \
  --smoke-only
```

For the full profile, use a new output directory, omit `--smoke-only` and select
a separately reviewed unused subnet (for example `--subnet 10.254.247.16/28`).
`--subnet` accepts only canonical /28
networks within the reviewed 10.254.247.0/24 pool; it defaults to 10.254.247.0/28.
The selected subnet is used only after every existing Docker IPAM
subnet and host route passes overlap checks. Missing images, subnet collision,
less than5GiB free, unexpected host/engine identity, or an existing output path
block before service creation. Infrastructure images use the pinned digests
from the reviewed project configuration and `--pull never`.

The worker runs actual per-role SQL logins, the actual Redis queue and SMTP
transport, enforced approval policy, a signed RoE, exact uploaded roster and
independent logical review identities. The source authorizes only `.test`
addresses and the SMTP fault proxy separately refuses external envelopes.
Domain verification is a recorded synthetic prerequisite. Logical development
principals never establish production OIDC or two-human acceptance.

SMTP sink acceptance is measured separately from confirmed delivery. A passing
run is not pilot/broad-use GO, a live ACS/cloud test, production capacity proof,
continuous-backup RPO evidence or final release-image qualification.

Private generated configuration, SQL role credentials and snapshot contents
remain in the private output directory. Never publish those files; inspect
`result.json`, `profile.json`, sanitized observations and the preserved resource
manifest for the outcome. Failure retains private logs for bounded diagnosis.

Focused tests make no Docker/network calls:

```sh
python -m pytest tests/test_fullstack_qualification.py
```

Implementation sequence and scope details are in [PLAN.md](PLAN.md).

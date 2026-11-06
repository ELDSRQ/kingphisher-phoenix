# Remediation registry

The canonical machine-readable inventory is [registry.json](registry.json).
It retains all 29 original tasks, FU-1 through FU-20 and newly confirmed
defects. Historical merged work is recorded separately from current acceptance.
[The execution record](EXECUTION-2026-11-06.md) identifies ownership and gates.

`complete` means its recorded scope is closed. `integration_pending` means
implemented code still needs the combined review/CI/release gate. `in_progress`
is agent-actionable work. `human_gate` and `external_gate` name the remaining
observation or resource; they never imply that a test or sign-off happened.
`policy_unchanged` records an optional tightening that was not a demonstrated
defect. The agent continues while any agent-owned item remains actionable.

Release evidence must identify the tested source and actual scope. A Redis
component soak does not establish worker/provider performance, and a database
restore does not establish complete service recovery. Automated accessibility
checks do not substitute for the independent D6 driver and manual checks.

The [prior remediation report](../REMAINING-REMEDIATION-2026-11-06.md)
explains native OS signing scope, recovery objectives, workload limits and
human acceptance. The earlier seven-item summary omitted recovered carryovers;
this inventory supersedes that count.

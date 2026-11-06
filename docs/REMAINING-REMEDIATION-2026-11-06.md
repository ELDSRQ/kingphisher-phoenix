# Remaining remediation — 2026-11-06

Work continues from GitHub `main` at `fb273050be63653284978c593cd9b31776016f7d`
on branch `codex/remaining-remediation-20261106`. The original controller
checkout and `.105` source are both at `cf659d5`; they and the controller's
uncommitted UX changes were preserved. The approved UX changes applied cleanly
to the current-main worktree. No normal application stack was restarted or
migrated during this work.

## Status

| Item | Result from this run | Remaining gate |
| --- | --- | --- |
| W2-05 campaign UX/WCAG | Guided steps, Back/input preservation, field-linked errors, exact final review and responsive controls; integrated browser coverage passes | Two human operators, manual WCAG and message/training content accessibility on the deployed release |
| W5-04 retention holds | Tenant-wide explicit admin holds; encrypted case text; release history; retention/erasure/keyed-ledger guards; least-privilege grants; database protection against legacy purges | Deploy and qualify migration/API/retention together; organization owns case-specific hold decisions |
| W5-01 overload budgets | New bounded component qualification passed on real `.105` Redis for 60 seconds and five minutes, including critical-topic progress and supervisor deadline isolation | Full deployed workload/provider/outbox soak and agreed operating thresholds; no full-stack GO claimed |
| W2-02 signing/clean VM | Controller reports **0 valid code-signing identities** | OS signing certificate and clean-machine matrix |
| W2-03 recovery | Fresh isolated schema and preservation/erasure effects qualified; no full system restore claimed | Authorized clean-room recovery of application state/secrets/audit and measured RPO/RTO |
| W2-04 staging | Azure account and staging resources reachable; four apps report Running with immutable image digests | Current-source plan/apply and deployment qualification |
| W5-05 / W5-06 | No pilot or broad-use sign-off manufactured | Signed pilot/broad-use GO after staging, recovery and human acceptance |

## Validation

- Current-main baseline plus approved UX/harness: **4,049** hermetic tests passed.
- Integrated hold implementation: **4,060** hermetic tests passed with no skips;
  PostgreSQL/Redis/live profiles remain explicit separate lanes. Subsequent
  hold/harness-focused checks passed **22/22** after additional test coverage.
- Full type check: **216 source files**, no issues. Ruff and formatting pass.
- Integrated browser suite: **13/13**, including hold retry/release and the
  1280/768/320-pixel whole-roster flow. JSON axe evidence has no reported
  violations in the tested console states; opaque email-frame contents are
  outside that console scan.
- Real PostgreSQL: **5/5** hold tests on a newly created
  `kp_hold_qualification_<UUID>` database, upgraded from base to `0053` and
  preserved. Concurrency checks use actual separate transactions. The last
  test proves legacy direct DML cannot bypass an active hold.
- Five-minute real-Redis component run: **259,184 accepted = 259,184 consumed**;
  **119,585 refused**, **0 early producer exhaustion**, maximum ready depth
  **67** for the explicitly documented 64+3 admission envelope. Worst critical
  latency **24.66 ms**, p95 at most **7.41 ms**. All queues drained. The
  synthetic stalled-generation probe preserved delivery progress.

The complete source files and the final evidence manifest bind these results;
they are not proof of a final deployed image. The new database guards were
qualified through fresh PostgreSQL migration and the direct-DML regression.

Controller evidence is retained in the original project's
`data/qualification/remaining-remediation-20261106-5qsooi/`, including the
browser report, source manifest, Redis JSON and PostgreSQL JUnit XML. Remote
evidence remains under `/home/builder/qualification/remaining-20261106-5qsooi/`.
The two uniquely named qualification containers are
`kp-queue-soak-20261106-5qsooi` and `kp-hold-qualification-20261106-5qsooi`.
Neither uses normal development volumes. No existing project assets were pruned,
removed or recreated.

## External observations

Azure staging's runner VM is **deallocated**. The latest recorded successful
Azure deployment run is [36421139411](https://github.com/ELDSRQ/kingphisher-phoenix/actions/runs/36421139411),
created 2026-09-28 at source `633c3913d9b6b335271a4ef1343de9dafd8cc05d`.
Its existence does not qualify the current source. Management-plane Running
states do not prove provider delivery, application health or human acceptance.

Staging currently reports these image digests:

| App | Digest |
| --- | --- |
| ai-gateway | `sha256:d1f8ae76e5e7a6aafc5314f66e4cccf256cc843d74b41f1881b5dba25e0451b3` |
| tracking-api | `sha256:550b1da93ed5d3119aff00541d9ef0ba849cf1f63023fa96749bd1271c350ca3` |
| worker | `sha256:beb22d6d3f75c7d8a4d5881afe400dc45ade6b70466c08d2121012c75e9bd501` |
| operator-api | `sha256:18c9cf516a6851e262895d2fb81d11a45ab1596d6f84fc91a283da8c51afac1f` |

Production/RSA and pilot/broad-use approval remain **NO-GO** pending the exact
release, external and human gates. No real campaign was approved or sent.

Implementation details: [W2-05 UX](design/CAMPAIGN-UX-W2-05.md),
[W5-04 holds](design/RETENTION-HOLDS-W5-04.md),
[queue soak procedure](../scripts/operator/queue-soak/README.md).

# Real-Redis queue overload qualification

`qualify.py` exercises the actual queue and supervisor control loop with
synthetic callbacks, four concurrent producers, two consumers and independent
delivery/retention/audit-anchor probes. It does not run provider handlers or
send messages to people. It uses a generated `kp:qualification:overload:<UUID>:`
namespace, never the application's queue namespace, and issues no cleanup or
flush commands. Run against a separately provisioned, task-owned loopback Redis
instance with resource limits; preserve its evidence.

```sh
KP_QUALIFICATION_REDIS_URL=redis://127.0.0.1:51457/0 \
  .venv/bin/python scripts/operator/queue-soak/qualify.py \
  --seconds 300 --ready-budget 64 --max-critical-latency 2 \
  --output /path/to/a-new-queue-soak-report.json
```

The output file must not already exist. Redis URL credentials are not recorded.
The report contains source hashes, counts, latency samples summarized by topic,
configured limits and explicit failures. Lost/duplicated/unknown jobs, missing
critical progress, excessive critical latency, failure to drain, exhausted
producer work budgets and failed deadline isolation all fail qualification.
Network calls have bounded timeouts and the run has duration/attempt limits.

Current queue admission deliberately permits a LLEN/push race. With four
producers and a ready budget of 64, the checked envelope is 67, not an asserted
atomic cap of 64. Delayed scheduling, provider/network degradation, PostgreSQL
outbox reconciliation and a complete deployed workload still require their own
qualification. A passing component report is not a full-stack capacity or GO
decision.

On 2026-11-06 the five-minute `.105` run accepted and consumed **259,184** jobs
without duplicates/loss, refused **119,585** excess submissions, observed a
maximum ready depth of **67**, and kept critical-topic p95 latency below **8 ms**
and worst latency below **25 ms**. No producer exhausted its work budget early.
All tested queues drained; the deliberate handler overrun isolated generation
while delivery completed in about **61 ms**. The earlier 60-second run also
passed, but the five-minute run is the sustained-load evidence.

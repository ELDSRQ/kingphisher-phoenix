# Threat-feed source manifest (`scripts/seed/`)

A small, reviewed, **static** manifest of reputable public threat-intelligence
**sources**, plus a dependency-light validator. This is the "where do the
current-campaign items come from" input for the on-prem background aggregation
stage (M3).

## What this is

- **`threat_feeds.yaml`** — a curated list of reputable public sources (national
  CERTs, well-known vendor threat-research teams, and public anti-phishing
  aggregators). Each entry has a stable `id`, `name`, `url`, `kind`
  (`rss` / `atom` / `html` / `json`), `publisher`, `categories`, and `enabled`.
- **`seed_threat_feeds.py`** — loads and validates the manifest, then prints a
  summary and the validated set as JSON.
- **`test_seed_threat_feeds.py`** — pytest coverage for the manifest and validator.

These are **public, reputable sources selected for DEFENSIVE
awareness-training** (safe phishing *simulations* — no real credential capture).
Nothing here is offensive tooling and nothing sketchy or obscure is listed;
anything not confidently a live public feed is shipped `enabled: false` with a
reason.

## How the aggregation stage consumes it

This file is **data only**. It names sources; it does not fetch them. The flow:

1. This manifest defines the reviewed source list (`id` + `url` + `publisher`).
2. A **separate ingestion step** (not this script) fetches each `enabled` source,
   sanitizes/neutralizes the entries, and stores them as the platform's own
   feed items.
3. The M3 background aggregation stage reads those ingested items and emits
   `AggregationSourceItem`s
   (`packages/contracts/src/kp_contracts/aggregation.py`), ranking current
   campaigns for a human to review and promote (activate → approve → generate).

The `id`/`publisher` here are the stable handles ingestion maps onto an item's
`source_reference` (e.g. `"<id>#<feed-entry-guid>"`), so provenance is traceable
end to end.

**This script makes no network calls.** It only validates the shape of the
source list; fetching is a deliberately separate ingestion concern.

## Run the validator

No database and no network are needed.

```sh
# From the repo root:
uv run python scripts/seed/seed_threat_feeds.py            # summary + JSON to stdout
uv run python scripts/seed/seed_threat_feeds.py --check    # validate only; non-zero exit if invalid
uv run python scripts/seed/seed_threat_feeds.py --out /tmp/feeds.json

# Or directly:
cd scripts/seed && KP_DISABLE_DOTENV=1 python seed_threat_feeds.py --check
```

Output is idempotent: the JSON is stable across runs.

## Run the tests

```sh
cd scripts/seed && KP_DISABLE_DOTENV=1 python -m pytest test_seed_threat_feeds.py -q
# or: uv run python -m pytest scripts/seed/test_seed_threat_feeds.py -q
```

## Add or disable a source

Edit `threat_feeds.yaml`:

- **Add**: append an entry under `feeds:` with a unique `id`, an `http(s)` `url`
  to the public advisory/feed, a `kind` in `{rss, atom, html, json}`, the
  `publisher` host, a non-empty `categories` list, and `enabled: true/false`.
  Only add genuinely reputable, well-known public sources.
- **Disable**: set `enabled: false` and add a comment (or the optional `note:`
  field) explaining why. Disabled entries stay as reviewed candidates; ingestion
  skips them.

Then re-validate with `--check` before committing. The validator enforces:
unique ids, `http(s)` URLs, an allowed `kind`, non-empty string categories, a
boolean `enabled`, and rejects unknown fields.

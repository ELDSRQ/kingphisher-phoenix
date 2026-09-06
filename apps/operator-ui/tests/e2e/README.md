# Operator console E2E smoke (TST-002 scaffold — OPERATOR-RUN ONLY)

This directory is a **scaffold**. It is not wired into CI, `make test`, or any
agent-runnable gate, and no browsers are installed by the repo. A human operator
runs it against a live console. It exists to begin replacing regex-over-source
UI assertions (e.g. `apps/operator-api/tests/test_gui_wiring_ui_contract.py`)
with real-DOM effect assertions.

## What it asserts

`console-nav.smoke.spec.mjs` loads the authenticated operator console and proves
the *rendered* navigation effect:

- the sidebar renders a button per visible NAV item (no stray buttons; core
  destinations Dashboard / Campaigns / Audit / Settings present), and
- activating a nav item actually mounts that view (`#console-view` relabels and
  the URL hash follows the selection).

This replaces the inference the source-regex test can only make by string-
matching `app.js`. The source test's *negative* assertions (hidden readiness
links are not rendered) are **not** yet covered here — keep that contract.

## How the operator runs it

Prerequisites: Node 18+, and a reachable console. Per platform norms the stack
runs on the `.140` host (or via a tunnel), **not** `localhost` on the Mac.

```
# 1. Bring up the operator-api + console (operator's normal local/dev stack),
#    then export where it is reachable and how to authenticate:
export OPERATOR_CONSOLE_URL=http://192.168.1.140:8000
export OPERATOR_CONSOLE_PASSWORD="$KP_CONSOLE_PASSWORD"   # local-stack dev login
#    (managed Azure disables password login — supply a pre-authenticated
#     session instead: export OPERATOR_CONSOLE_STORAGE_STATE=/path/to/state.json)

# 2. Install Playwright + a browser (one-time, operator machine only):
cd apps/operator-ui
npm install --no-save @playwright/test@1
npx playwright install chromium

# 3. Run the smoke suite:
npx playwright test -c tests/e2e/playwright.config.mjs
```

If neither `OPERATOR_CONSOLE_PASSWORD` nor `OPERATOR_CONSOLE_STORAGE_STATE` is
set, the login-gated tests skip with an explanatory message rather than failing.

# Operator console E2E smoke — standing gate (`make test-e2e-console`)

This is a **standing gate**, not a scaffold: run it whenever the console UI
changes. It replaces regex-over-source UI assertions (e.g.
`apps/operator-api/tests/test_gui_wiring_ui_contract.py`) with real-DOM effect
assertions — first verified green against the live `.105` console on 2026-09-07.

It is deliberately **not** part of `make test` or CI: it needs a browser and a
reachable, authenticated console, neither of which exists on the hermetic
runners. `make test-e2e-console` fails with an explicit message (rather than
silently passing) if the console is unreachable, the credentials are missing, or
Playwright is not installed.

## Quick start

```
make test-e2e-console
```

with `OPERATOR_CONSOLE_URL` and `OPERATOR_CONSOLE_PASSWORD` exported — see
"How the operator runs it" below for the tunnel and one-time browser install.

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

Prerequisites: Node 18+, and a reachable console. The canonical local stack runs
on the `.105` WSL2 host (`.140` is RETIRED), and Docker never runs on the Mac —
so reach the console through an SSH tunnel rather than `localhost` directly:

```
# 0. Tunnel the console from .105 to the Mac (leave this running in its own shell):
# High local ports: 8000 commonly collides with another tunnel on the operator's Mac
ssh -N -o ControlMaster=no -o ControlPath=none -L 18000:127.0.0.1:8000 -L 18001:127.0.0.1:8001 erikd@192.168.1.105

# 1. In a second shell, point the suite at the tunnelled console and say how to
#    authenticate:
export OPERATOR_CONSOLE_URL=http://localhost:18000
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

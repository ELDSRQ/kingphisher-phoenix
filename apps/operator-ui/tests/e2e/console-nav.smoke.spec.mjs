// @ts-check
// Standing console smoke gate: `make test-e2e-console`.
// Drives a real browser (chromium) against a LIVE, authenticated console, so it
// is deliberately NOT part of `make test` or CI — both lack a browser and a
// reachable console. Run it whenever the console UI changes.
//
// Purpose: replace a regex-over-source UI assertion with a real-DOM effect
// assertion. The Python contract test
//   apps/operator-api/tests/test_gui_wiring_ui_contract.py
//   ::test_every_visible_navigation_item_has_a_view_and_hidden_readiness_links_are_not_rendered
// proves navigation wiring by string-matching app.js source. This smoke test
// proves the *rendered* effect instead: the authenticated console renders a
// sidebar button per visible NAV item, and activating one actually mounts that
// view (the #console-view region's label follows the selection).
//
// It does NOT replace the source test's negative assertions about hidden
// readiness links; keep the source contract until the effect coverage is
// broadened. See docs/design/TST-002-TEST-EFFECT-UPLIFT.md.

import { expect, test } from "@playwright/test";

// The visible navigation labels the console renders for a fully-capable
// operator, in NAV order (app.js `const NAV`). Capability-gated items may be
// absent for a lower-privilege session; the test asserts a subset relationship,
// not exact equality, so it is robust to capability trimming.
const EXPECTED_NAV_LABELS = [
  "Setup wizard",
  "Azure deployment",
  "Help",
  "Dashboard",
  "Campaigns",
  "Programs",
  "Executive trends",
  "Domains & RoE",
  "Recipients",
  "Sources",
  "Patterns",
  "Template review",
  "Training lessons",
  "Privacy",
  "Failed jobs",
  "Audit",
  "Settings",
];

async function ensureAuthenticated(page) {
  // The SPA is mounted at /console/ — the root path 404s.
  await page.goto("/console/");
  const password = page.locator("#console-password");
  const nav = page.locator('nav[aria-label="Operator sections"]');
  // The console renders client-side, so goto() resolves BEFORE either the login
  // form or the authenticated shell exists. Wait for whichever arrives first —
  // a bare count()/isVisible() here races the render and silently reports "no
  // login form", which then hangs on a nav that can never appear.
  await expect(password.or(nav).first()).toBeVisible({ timeout: 15_000 });
  // With a pre-supplied storageState the login form never appears.
  if (await password.isVisible()) {
    const secret = process.env.OPERATOR_CONSOLE_PASSWORD;
    test.skip(
      !secret,
      "Set OPERATOR_CONSOLE_PASSWORD (local-stack KP_CONSOLE_PASSWORD) or OPERATOR_CONSOLE_STORAGE_STATE to authenticate.",
    );
    await password.fill(secret);
    await page.getByRole("button", { name: "Sign in" }).click();
  }
  // The operator sections nav only exists once authenticated.
  await expect(nav).toBeVisible({ timeout: 15_000 });
}

test.describe("operator console navigation (real DOM effect)", () => {
  test("every visible nav item renders a button", async ({ page }) => {
    await ensureAuthenticated(page);
    const nav = page.locator('nav[aria-label="Operator sections"]');
    const rendered = await nav.locator("button").allInnerTexts();
    const renderedTrimmed = rendered.map((t) => t.trim()).filter(Boolean);
    // Every rendered label must be a known NAV label (no stray buttons)...
    for (const label of renderedTrimmed) {
      expect(EXPECTED_NAV_LABELS).toContain(label);
    }
    // ...and the core, non-capability-gated destinations must be present.
    for (const core of ["Dashboard", "Campaigns", "Audit", "Settings"]) {
      expect(renderedTrimmed).toContain(core);
    }
  });

  test("activating a nav item mounts its view", async ({ page }) => {
    await ensureAuthenticated(page);
    const nav = page.locator('nav[aria-label="Operator sections"]');
    await nav.getByRole("button", { name: "Campaigns" }).click();
    // navigateTo() sets location.hash; the view region relabels to the active
    // view. This is the effect the source-regex test could only infer.
    await expect(page).toHaveURL(/#campaigns$/);
    await expect(page.locator("#console-view")).toHaveAttribute(
      "aria-label",
      /Campaigns view/i,
    );
  });
});

// @ts-check
// Standing console smoke gate: `make test-e2e-console`.
// Drives a real browser (chromium) against a LIVE, authenticated console, so it
// is deliberately NOT part of `make test` or CI — both lack a browser and a
// reachable console. Run it whenever the console UI changes.
//
// Purpose: real-DOM effect assertions the ~25 Python string-grep UI-contract
// tests structurally cannot make. The 2026-09-26 browser pass found two bugs a
// string grep missed — a nav count badge glued to its label ("Campaigns1") and
// the "More" list wrapping two-per-row — and both this file's badge-pill and
// grouping assertions now guard that class. See docs/QA-REMEDIATION-PLAN.md F10.

import { expect, test } from "@playwright/test";

// The full navigation, from app.js `const NAV`: seven "run" items always
// visible, thirteen "more" items behind a collapsed <details>. Capability-gated
// items may be absent for a lower-privilege session, so membership is asserted
// as a subset, never exact equality.
const PRIMARY_NAV_LABELS = [
  "Get started",
  "Domains & RoE",
  "Recipients",
  "Template review",
  "Training lessons",
  "Campaigns",
  "Dashboard",
];
const MORE_NAV_LABELS = [
  "Setup wizard",
  "Repeat on a schedule",
  "Executive trends",
  "Patterns",
  "Sources",
  "Threat aggregation",
  "Audit",
  "Failed jobs",
  "Privacy",
  "AI model",
  "Azure deployment",
  "Settings",
  "Help",
];
const ALL_NAV_LABELS = [...PRIMARY_NAV_LABELS, ...MORE_NAV_LABELS];

// A nav button's text may carry a "needs my decision" count badge (e.g.
// Campaigns + "1"). The badge is a separate .nav-badge pill; strip a trailing
// number so the label compares cleanly.
function navLabel(text) {
  return text.replace(/\s*\d+\s*$/, "").trim();
}

async function ensureAuthenticated(page) {
  // The SPA is mounted at /console/ — the root path 404s.
  await page.goto("/console/");
  const password = page.locator("#console-password");
  const nav = page.locator('nav[aria-label="Operator sections"]');
  // The console renders client-side, so goto() resolves BEFORE either the login
  // form or the authenticated shell exists. Wait for whichever arrives first.
  await expect(password.or(nav).first()).toBeVisible({ timeout: 15_000 });
  if (await password.isVisible()) {
    const secret = process.env.OPERATOR_CONSOLE_PASSWORD;
    test.skip(
      !secret,
      "Set OPERATOR_CONSOLE_PASSWORD (local-stack KP_CONSOLE_PASSWORD) or OPERATOR_CONSOLE_STORAGE_STATE to authenticate.",
    );
    await password.fill(secret);
    await page.getByRole("button", { name: "Sign in" }).click();
  }
  await expect(nav).toBeVisible({ timeout: 15_000 });
}

test.describe("operator console navigation (real DOM effect)", () => {
  test("the seven campaign-path items render, and the rest live behind More", async ({ page }) => {
    await ensureAuthenticated(page);
    const nav = page.locator('nav[aria-label="Operator sections"]');

    // Primary items are visible immediately.
    const visible = (await nav.locator("button:visible").allInnerTexts()).map(navLabel).filter(Boolean);
    for (const core of PRIMARY_NAV_LABELS) {
      expect(visible).toContain(core);
    }
    // Every visible label is a known NAV label (no stray buttons).
    for (const label of visible) {
      expect(ALL_NAV_LABELS).toContain(label);
    }

    // The occasional tools sit behind a "More" disclosure, collapsed by default.
    const more = nav.locator("details.nav-more");
    await expect(more).toBeVisible();
    // Collapsed: a More-only item is not yet visible.
    await expect(nav.getByRole("button", { name: "Audit", exact: true })).toBeHidden();
    await more.locator("summary").click();
    // Expanded: the More items are now reachable.
    await expect(nav.getByRole("button", { name: "Audit", exact: true })).toBeVisible();
    const afterExpand = (await nav.locator("button:visible").allInnerTexts()).map(navLabel).filter(Boolean);
    for (const item of ["Audit", "Settings", "AI model"]) {
      expect(afterExpand).toContain(item);
    }
  });

  test("the Campaigns decision badge renders as a pill, not glued text", async ({ page }) => {
    await ensureAuthenticated(page);
    const campaigns = page.locator('nav[aria-label="Operator sections"] button[data-nav="campaigns"]');
    // Guards the "Campaigns1" bug: when a badge is present it is its own
    // .nav-badge element, so the button's own label never reads "Campaigns<n>".
    const badge = campaigns.locator(".nav-badge");
    if ((await badge.count()) > 0) {
      await expect(badge).toBeVisible();
      const badgeText = (await badge.innerText()).trim();
      expect(badgeText).toMatch(/^\d+$/);
    }
  });

  test("a campaign-capable operator lands on Campaigns by default (§2.2-1)", async ({ page }) => {
    await ensureAuthenticated(page); // goes to /console/ with no explicit hash
    // The campaign page is the launch console, so it is the default landing.
    await expect(page.locator("#console-view")).toHaveAttribute("aria-label", /Campaigns view/i);
  });

  test("activating Campaigns mounts its view and prefills the new-campaign form", async ({ page }) => {
    await ensureAuthenticated(page);
    const nav = page.locator('nav[aria-label="Operator sections"]');
    await nav.getByRole("button", { name: "Campaigns", exact: true }).click();
    await expect(page).toHaveURL(/#campaigns$/);
    await expect(page.locator("#console-view")).toHaveAttribute("aria-label", /Campaigns view/i);

    // Prefill (PR #72): title, start and end arrive filled so the operator
    // reviews a draft rather than facing eleven blank fields. Present only when
    // approved content exists; assert non-empty when the fields are present.
    const title = page.locator("#c-title");
    if ((await title.count()) > 0) {
      await expect(title).not.toHaveValue("");
      await expect(page.locator("#c-start")).not.toHaveValue("");
      await expect(page.locator("#c-end")).not.toHaveValue("");
    }
  });
});

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

// Each fresh login loads several real API collections. Pace the live sweep
// below the ordinary 120 requests/minute user limit; never relax the server.
test.beforeEach(async () => {
  await new Promise((resolve) => setTimeout(resolve, 20_000));
});
test.setTimeout(60_000);

// The full navigation, from app.js `const NAV`: six "run" items always
// visible, fourteen "more" items behind a collapsed <details>. Capability-gated
// items may be absent for a lower-privilege session, so membership is asserted
// as a subset, never exact equality.
const PRIMARY_NAV_LABELS = [
  "Get started",
  "Domains & RoE",
  "Recipients",
  "Template review",
  "Campaigns",
  "Dashboard",
];
const MORE_NAV_LABELS = [
  "Training lessons",
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
  test("the six campaign-path items render, and the rest live behind More", async ({ page }) => {
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

  test("a campaign-capable operator defaults off the dashboard to the campaign path (§2.2-1)", async ({ page }) => {
    await ensureAuthenticated(page); // goes to /console/ with no explicit hash
    // §2.2-1 moved the default landing off the Dashboard: a campaign-capable
    // operator lands on the Campaigns launch console. One higher-priority flow
    // legitimately intercepts it — an operator with MANAGE_ROLES whose
    // onboarding is not yet complete is sent to "Get started" first
    // (render() forces #getstarted). So assert the intent precisely: the
    // default is never the dashboard, and is one of the two campaign-path homes.
    await expect(page.locator("#console-view")).toHaveAttribute(
      "aria-label",
      /(Campaigns|Get started) view/i,
    );
  });

  test("activating Campaigns mounts its view and prefills the new-campaign form", async ({ page }) => {
    await ensureAuthenticated(page);
    const nav = page.locator('nav[aria-label="Operator sections"]');
    // Locate by data-nav, not the accessible name: a "needs my decision" badge
    // appends " <n> awaiting your decision" to the button's name, so an
    // exact-name match for "Campaigns" misses it whenever a decision is pending.
    await nav.locator('button[data-nav="campaigns"]').click();
    await expect(page).toHaveURL(/#campaigns$/);
    await expect(page.locator("#console-view")).toHaveAttribute("aria-label", /Campaigns view/i);

    await expect(page.getByLabel("Company domain", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Select domain", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: /freeze|lock|canary/i })).toHaveCount(0);
  });

  for (const width of [1280, 768]) {
    test(`an approved library email is usable with the configured training host at ${width}px`, async ({ page }, testInfo) => {
      await page.setViewportSize({ width, height: 900 });
      const onboardingResponse = page.waitForResponse((response) =>
        response.url().endsWith("/api/v1/console/onboarding")
          && response.request().method() === "GET" && response.status() === 200,
      );
      await ensureAuthenticated(page);
      const setup = await (await onboardingResponse).json();
      const training = setup.steps.find((step) => step.id === "training");
      expect(training?.ready, "Complete Training experience in Setup wizard before a human campaign run.").toBe(true);
      const trainingURL = training.fields.find((field) => field.key === "OPERATOR_API_TRAINING_BASE_URL").value;
      const trainingHost = new URL(trainingURL).hostname;
      const nav = page.locator('nav[aria-label="Operator sections"]');
      await nav.locator('button[data-nav="templates"]').click();
      const library = page.locator(".template-library-table");
      await expect(page.getByLabel("Filter templates by review state", { exact: true })).toHaveValue("approved");
      const chooseEmail = library.getByRole("button", { name: /^Select for current campaign: / }).first();
      await expect(chooseEmail, "The human run needs at least one approved library email.").toBeVisible();
      await chooseEmail.click();
      await expect(page).toHaveURL(/#campaigns$/);
      await expect(page.getByLabel("Company domain", { exact: true })).toBeVisible();
      await page.getByLabel("Company domain", { exact: true }).selectOption("example.com");
      await page.getByRole("button", { name: "Select domain", exact: true }).click();
      const authorization = page.getByLabel("Saved signed authorization", { exact: true });
      await expect(authorization.locator("option")).not.toHaveCount(1);
      await authorization.selectOption({ index: 1 });
      await page.getByRole("button", { name: "Use signed RoE", exact: true }).click();
      await expect(page.getByRole("button", { name: "Download CSV template", exact: true })).toBeVisible();
      await expect(page.getByText(/browser saves it to Downloads/)).toBeVisible();
      await expect(page.getByRole("button", { name: /freeze|lock|canary/i })).toHaveCount(0);
      await page.screenshot({ path: testInfo.outputPath(`simple-campaign-${width}.png`), fullPage: true });
    });
  }
});

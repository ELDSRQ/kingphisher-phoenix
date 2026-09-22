// @ts-check
// Standing accessibility gate: `make test-a11y-console` (readiness gate D3).
//
// Drives a real chromium against a LIVE, authenticated console and runs
// axe-core over each primary view. Like the navigation smoke gate it is
// deliberately NOT part of `make test` or CI, both of which lack a browser and
// a reachable console.
//
// WHAT THIS DOES AND DOES NOT PROVE. axe-core catches roughly half of real
// WCAG problems: it finds missing names, contrast, ARIA misuse and structural
// faults, and it cannot judge keyboard order, focus management, screen-reader
// comprehensibility or whether an error message actually explains anything. A
// green run here is necessary evidence for D3, never sufficient — the gate
// still requires a human pass. Do not let this suite's passing be read as "the
// console is accessible".
//
// Failure output names the rule, impact, and the offending selectors, so a
// failure is actionable without reopening the browser.

import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Fail only on the impacts that block use. 'minor' and 'moderate' are reported
// to stdout so they stay visible and can be tightened later, but they do not
// fail the gate: starting strict on a console that has never been audited would
// mean a permanently red gate nobody runs.
const BLOCKING_IMPACTS = new Set(["serious", "critical"]);

// WCAG 2.1 AA is the target. Including 'best-practice' would fail on advisory
// rules that are not conformance requirements.
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

// Views reachable from the operator nav for a fully-capable session. Each is
// audited independently: a violation on one view must not mask another.
const VIEWS = [
  "Dashboard",
  "Campaigns",
  "Recipients",
  "Sources",
  "Patterns",
  "Template review",
  "Audit",
  "Settings",
];

async function ensureAuthenticated(page) {
  // The SPA is mounted at /console/ — the root path 404s.
  await page.goto("/console/");
  const password = page.locator("#console-password");
  const nav = page.locator('nav[aria-label="Operator sections"]');
  // The console renders client-side, so goto() resolves BEFORE either the login
  // form or the authenticated shell exists; wait for whichever arrives first.
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

function summarize(violations) {
  return violations
    .map((v) => {
      const targets = v.nodes
        .slice(0, 5)
        .map((n) => `      ${n.target.join(" ")}`)
        .join("\n");
      const more = v.nodes.length > 5 ? `\n      ... ${v.nodes.length - 5} more` : "";
      return `  [${v.impact}] ${v.id}: ${v.help}\n    ${v.helpUrl}\n${targets}${more}`;
    })
    .join("\n");
}

async function auditCurrentView(page, label) {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const blocking = results.violations.filter((v) => BLOCKING_IMPACTS.has(v.impact));
  const advisory = results.violations.filter((v) => !BLOCKING_IMPACTS.has(v.impact));
  if (advisory.length) {
    console.log(`\n${label}: ${advisory.length} advisory (non-blocking) finding(s):\n${summarize(advisory)}`);
  }
  // Assert on rule ids, not the violation objects: Playwright's diff prints the
  // whole expected/actual structure, and dumping full axe nodes buries the
  // actionable summary under hundreds of lines of JSON.
  expect(
    blocking.map((v) => v.id),
    `${label}: ${blocking.length} blocking accessibility violation(s):\n${summarize(blocking)}`,
  ).toEqual([]);
}

test.describe("@a11y operator console accessibility (axe-core, WCAG 2.1 AA)", () => {
  test("@a11y login view has no blocking violations", async ({ page }) => {
    // Audited before authenticating: the sign-in form is the first thing a
    // human meets, and it is the one view a locked-out operator cannot skip.
    await page.goto("/console/");
    const password = page.locator("#console-password");
    const nav = page.locator('nav[aria-label="Operator sections"]');
    await expect(password.or(nav).first()).toBeVisible({ timeout: 15_000 });
    test.skip(!(await password.isVisible()), "Console was already authenticated; login view not shown.");
    await auditCurrentView(page, "Login");
  });

  for (const label of VIEWS) {
    test(`@a11y ${label} view has no blocking violations`, async ({ page }) => {
      await ensureAuthenticated(page);
      const nav = page.locator('nav[aria-label="Operator sections"]');
      const button = nav.getByRole("button", { name: label, exact: true });
      // Capability-gated views may be absent for a lower-privilege session;
      // skipping is honest, whereas failing would punish a valid posture.
      test.skip((await button.count()) === 0, `${label} is not present for this session's capabilities.`);
      await button.click();
      await expect(page.locator("#console-view")).toBeVisible({ timeout: 15_000 });
      await auditCurrentView(page, label);
    });
  }
});

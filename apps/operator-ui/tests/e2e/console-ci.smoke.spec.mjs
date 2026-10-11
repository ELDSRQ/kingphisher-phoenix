// Production UI/auth/config/status on scratch fixture state. No live deployment.
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";
import AxeBuilder from "@axe-core/playwright";

const FIXTURE_PASSWORD = "ConsoleSmokeSynthetic2026";

async function installHumanFlowFixture(page) {
  const id = (suffix) => `30000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`;
  const rosterId = id(1), templateId = id(2), patternId = id(3), lessonId = id(4), campaignId = id(5), roeId = id(6);
  const recipients = [
    { recipient_id: id(10), display_name: "Erik", masked_mailbox: "c***@example.com", department: "Trial", status: "active", is_test_account: false },
    { recipient_id: id(11), display_name: "", masked_mailbox: "p***@example.com", department: "Trial", status: "active", is_test_account: false },
    { recipient_id: id(12), display_name: "Outside", masked_mailbox: "o***@unauthorized.example", department: "Trial", status: "active", is_test_account: false },
  ];
  const approvedRecipients = recipients.slice(0, 2);
  const draftId = id(20);
  const pastRecipient = { ...recipients[1], recipient_id: id(90), display_name: "Past import" };
  const state = { rosterSaved: false, campaign: null, writes: [], noTestAccount: false, failFreeze: false, failTemplates: false, throttleSchedule: false, setupIncomplete: false };
  const roe = { roe_id: roeId, authorizing_party: "Synthetic company", signer: "Fixture operator", window_start: "2020-01-01T00:00:00Z", window_end: "2050-12-31T00:00:00Z", target_domains: ["example.com"], terms: "Synthetic exercise authorization", revoked_at: null };
  const data = {
    "/patterns": [{ campaign_pattern_id: patternId, approval_state: "approved", lure_category: "credential" }],
    "/templates": [{ template_version_id: templateId, pattern_id: patternId, subject: "Approved human trial email", approval_state: "approved", reusable: true, version: 1 }],
    "/templates/pending": [],
    "/training-resources": [{ training_resource_id: lessonId, title: "Recognize phishing", version: 1, requires_completion: true }],
    "/sending-domains": { domains: [{ domain: "example.com", active: true, verified_at: "2026-01-01T00:00:00Z" }] },
    "/roe": { roes: [roe] },
    "/console/onboarding": { complete: true, completed: true, steps: [{ id: "smtp", ready: true }, { id: "training", ready: true, fields: [{ key: "OPERATOR_API_TRAINING_BASE_URL", value: "http://127.0.0.1:8001/v1/training/awareness" }] }] },
    "/console/status": { runtime_control: "local_supervisor", workers: { delivery: true }, capabilities: { local_component_probes: true, config_mutation: true, process_restart: true } },
    "/integrations/microsoft365/status": { directory: { status: "unconfigured" }, reported_mailbox: { configured: false, status: "unconfigured" }, directory_preview_available: false, mailbox_poll_available: false },
    "/kill-switch": { engaged: false, generation: 0 },
    "/alerts/subscriptions": [],
  };
  const campaignFlags = () => ({
    can_configure_audience: state.campaign.state === "draft", can_configure_training: state.campaign.state === "draft",
    can_submit: state.campaign.state === "draft" && state.campaign.audience_frozen,
    can_approve_security: false, can_approve_privacy: false,
    can_send: state.campaign.state === "approved",
    can_schedule: false,
    can_publish: false,
    can_test_send: false, can_proof_send: false, can_recall: false,
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(), url = new URL(request.url());
    const path = url.pathname.replace("/api/v1", ""), method = request.method();
    if (path === "/templates" && state.failTemplates) return route.fulfill({ status: 429, headers: { "Retry-After": "1" }, json: { detail: "Too many requests" } });
    if (path === "/console/onboarding") return route.fulfill({ json: { ...data[path], complete: !state.setupIncomplete } });
    if (path === "/audience-groups") return route.fulfill({ json: { groups: state.rosterSaved ? [{ audience_group_id: rosterId, name: "Human trial roster", member_count: 3, recipient_ids: recipients.map((r) => r.recipient_id), created_at: "2026-10-09T00:00:00Z" }] : [] } });
    if (path === "/recipients") {
      const rows = url.searchParams.get("roster_id") === rosterId ? approvedRecipients : [pastRecipient, ...recipients];
      const limit = Number(url.searchParams.get("limit") || 100), offset = Number(url.searchParams.get("offset") || 0);
      return route.fulfill({ json: { items: rows.slice(offset, offset + limit), total: rows.length, limit, offset, truncated: offset + limit < rows.length } });
    }
    if (path === "/recipients/import/preview") return route.fulfill({ json: {
      preview_digest: "a".repeat(64), input_rows: 3, header_detected: true, header_mode: "auto",
      columns: [{ index: 0, label: "email" }, { index: 1, label: "name" }, { index: 2, label: "department" }], mapping: { mailbox: 0, display_name: 1, department: 2 },
      counts: { created: 2, existing: 0, updateable: 0, blocked: 1, invalid: 0, duplicate: 0 }, can_apply: true, errors: [{ row: 4, code: "recipient_domain_not_allowed" }], recipients: approvedRecipients,
      roe_coverage: { checked: true, active_roe_domains: ["example.com"], uncovered: 1, uncovered_domains: ["unauthorized.example"] },
    } });
    if (path === "/recipients/import/apply") {
      state.writes.push({ path, body: request.postDataJSON() }); state.rosterSaved = true;
      return route.fulfill({ json: { created: 3, roster: { audience_group_id: rosterId, name: "Human trial roster", member_count: 2 } } });
    }
    if (path === `/templates/${draftId}/preview` && state.failPreview) return route.fulfill({ status: 422, json: { detail: "template contains unsupported or malformed rendering syntax" } });
    if ([`/templates/${templateId}/preview`, `/templates/${draftId}/preview`].includes(path)) return route.fulfill({ json: {
      template_version_id: path.includes(draftId) ? draftId : templateId, approval_state: path.includes(draftId) ? "draft" : "approved",
      subject: "Human trial email", plain_text: "Dear sample recipient, review your request.",
      editable_subject: "Human trial email", editable_plain_text: "Review your request. Continue: {{ tracking.training_url }}",
    } });
    if (path === `/templates/${templateId}/clone`) {
      state.writes.push({ path, body: request.postDataJSON() });
      return route.fulfill({ status: 201, json: { template_version_id: draftId } });
    }
    if (path === `/templates/${draftId}/decision`) { state.writes.push({ path }); return route.fulfill({ json: { approval_state: "approved" } }); }
    if (path === "/campaigns" && method === "GET") return route.fulfill({ json: state.campaign ? [{ ...state.campaign, ...campaignFlags() }] : [] });
    if (path === "/campaigns" && method === "POST") {
      state.writes.push({ path, body: request.postDataJSON() });
      state.campaign = { ...request.postDataJSON(), campaign_id: campaignId, state: "draft", current_template_id: templateId, audience_frozen: false, audience_version: 1, roe_bound: false, training_lesson: { ready: true, title: "Recognize phishing", bound_version: 1 }, launch_gate: { state: "unreviewed" } };
      return route.fulfill({ status: 201, json: { campaign_id: campaignId } });
    }
    if (path === `/campaigns/${campaignId}/audience` && method === "PUT") {
      state.writes.push({ path, body: request.postDataJSON() }); return route.fulfill({ json: {} });
    }
    if (path === `/campaigns/${campaignId}/audience/preview`) return route.fulfill({ json: {
      preview_hash: "b".repeat(64), selected_count: 2, included_count: 2, excluded_count: 0, excluded_counts: {}, roe_id: roeId,
      test_account_count: 0, recipients: approvedRecipients.map((r) => ({ ...r, mailbox: r.masked_mailbox })),
    } });
    if (path === `/campaigns/${campaignId}/confirm`) {
      state.writes.push({ path, body: request.postDataJSON() });
      if (state.failFreeze) return route.fulfill({ status: 409, json: { detail: "recipient list changed; review again" } });
      state.campaign.state = "approved"; state.campaign.audience_frozen = true; state.campaign.launch_gate.state = "reviewed";
      return route.fulfill({ json: { state: "approved" } });
    }
    if (path === `/campaigns/${campaignId}/send`) {
      state.sendAttempts = (state.sendAttempts || 0) + 1;
      if (state.throttleSchedule) return route.fulfill({ status: 429, headers: { "Retry-After": "1" }, json: { detail: "Too many requests" } });
      state.writes.push({ path }); state.campaign.state = "scheduled"; state.campaign.launch_gate.state = "direct_published";
      return route.fulfill({ json: { queued: 2 } });
    }
    if (path === `/campaigns/${campaignId}/recipients`) return route.fulfill({ json: { items: approvedRecipients.map((r, i) => ({ ...r, send_state: "accepted", clicked: i === 0, confirmed_interaction: false, reported: false, training_state: "assigned" })) } });
    if (Object.hasOwn(data, path)) return route.fulfill({ json: data[path] });
    await route.continue();
  });
  return { state, rosterId, campaignId };
}

for (const width of [1280, 768]) {
  test(`whole-roster human flow at ${width}px: domain, signed RoE, CSV, edit, approve, send and named results`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const { state, campaignId } = await installHumanFlowFixture(page);
    state.setupIncomplete = true; // Optional integration setup must not hijack the campaign view.
    const errors = []; page.on("pageerror", (error) => errors.push(error.message));
    await page.goto("/console/#campaigns");
    await page.locator("#console-password").fill(FIXTURE_PASSWORD);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await page.getByLabel("Company domain", { exact: true }).selectOption("example.com");
    await page.getByRole("button", { name: "Select domain", exact: true }).click();
    await page.getByLabel("Saved signed authorization", { exact: true }).selectOption("30000000-0000-4000-8000-000000000006");
    await page.getByRole("button", { name: "Use signed RoE", exact: true }).click();
    await expect(page.getByText(/only these domains are approved: example.com/)).toBeVisible();
    const downloadPromise = page.waitForEvent("download");
    await page.getByRole("button", { name: "Download CSV template", exact: true }).click();
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toBe("recipient-roster-template.csv");
    expect(await readFile(await download.path(), "utf8")).toBe("\uFEFFemail,name,department\r\n");
    await expect(page.getByText(/browser saves it to Downloads/)).toBeVisible();
    await page.getByLabel("Completed recipient CSV", { exact: true }).setInputFiles({ name: "roster.csv", mimeType: "text/csv", buffer: Buffer.from("email,name,department\nfirst@example.com,Erik,Trial\nparticipant@example.com,,Trial\noutside@unauthorized.example,Outside,Trial\n") });
    await page.getByRole("button", { name: "Review uploaded recipients", exact: true }).click();
    const review = page.getByRole("table", { name: "Validated recipients before confirmation", exact: true });
    await expect(review.locator("tbody tr")).toHaveCount(2);
    await expect(review).not.toContainText("Outside");
    await page.getByRole("button", { name: "Confirm validated recipients", exact: true }).click();
    const roster = page.getByRole("table", { name: "Confirmed campaign roster", exact: true });
    await expect(roster.locator("tbody tr")).toHaveCount(2);
    await expect(roster).not.toContainText("Past import");
    await page.getByLabel("Library email", { exact: true }).selectOption("30000000-0000-4000-8000-000000000002");
    await page.getByRole("button", { name: "Use this email as a starting point", exact: true }).click();
    await page.getByLabel("Email subject", { exact: true }).fill("Reviewed human trial email");
    state.failPreview = true;
    await page.getByRole("button", { name: "Create fake email for review", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: /unsupported or malformed rendering syntax/ }).first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Approve campaign", exact: true })).toHaveCount(0);
    state.failPreview = false;
    await page.getByRole("button", { name: "Create fake email for review", exact: true }).click();
    await expect(page.getByLabel("Campaign name", { exact: true })).toBeVisible();
    await page.getByLabel("Email subject", { exact: true }).fill("Revised reviewed human trial email");
    await expect(page.getByRole("button", { name: "Approve campaign", exact: true })).toBeDisabled();
    await expect(page.getByText(/Email edited\. Click Create fake email for review/)).toBeVisible();
    await page.getByRole("button", { name: "Create fake email for review", exact: true }).click();
    await expect(page.getByRole("button", { name: "Approve campaign", exact: true })).toBeEnabled();
    await page.getByLabel("Campaign name", { exact: true }).fill("Streamlined human trial");
    await expect(page.getByLabel("Training hostname", { exact: true })).toHaveValue("127.0.0.1");
    await page.getByRole("button", { name: "Approve campaign", exact: true }).click();
    await page.getByRole("dialog", { name: "Approve this campaign?", exact: true }).getByRole("button", { name: "Approve", exact: true }).click();
    await expect(page.getByRole("button", { name: "Send", exact: true })).toBeVisible();
    const created = state.writes.find((w) => w.path === "/campaigns").body;
    expect(created.delivery_mode).toBe("reviewed_direct"); expect(created.max_recipients).toBe(2);
    const emailCopy = state.writes.find((w) => w.path.endsWith("/clone")).body.plain_text;
    expect(emailCopy).toContain('{{ recipient.first_name or "colleague" }}');
    expect(emailCopy).toContain("{{ tracking.training_url }}");
    expect(state.writes.find((w) => w.path.endsWith("/audience")).body.group_ids).toHaveLength(1);
    expect(state.writes.find((w) => w.path.endsWith("/confirm")).body.preview_hash).toBe("b".repeat(64));
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Cancel", exact: true }).click();
    expect(state.sendAttempts || 0).toBe(0);
    state.throttleSchedule = true;
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: /Wait at least 1 second/ }).first()).toBeVisible();
    expect(state.sendAttempts).toBe(1);
    if (width === 1280) {
      const accessibility = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
      expect(accessibility.violations.filter((v) => ["serious", "critical"].includes(v.impact)).map((v) => v.id)).toEqual([]);
    }
    state.throttleSchedule = false;
    await page.getByRole("button", { name: "Send", exact: true }).click();
    await page.getByRole("dialog").getByRole("button", { name: "Send", exact: true }).click();
    await expect(page.getByRole("button", { name: "Send", exact: true })).toHaveCount(0);
    expect(state.writes.filter((w) => w.path === `/campaigns/${campaignId}/send`)).toHaveLength(1);
    expect(state.writes.some((w) => /freeze|schedule|publish|test-account/.test(w.path))).toBe(false);
    await page.getByRole("button", { name: "Monitor recipient results", exact: true }).click();
    await expect(page.getByRole("table", { name: "Campaign recipient results", exact: true }).locator("tbody tr")).toHaveCount(2);
    await expect(page.getByText(/Replies: unavailable/)).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("reviewed-direct-campaign.png"), fullPage: true });
    expect(errors).toEqual([]);
  });
}

test("password login, status and an audited reversible Settings edit", async ({ page, request, baseURL }, testInfo) => {
  const marker = await request.get("/__smoke__/ready");
  expect(await marker.json()).toEqual({ fixture: "console-ci-smoke", run_id: testInfo.config.metadata.fixtureRunId });
  expect((await request.get("/api/v1/console/status")).status()).toBe(401);
  expect((await request.put("/api/v1/console/config", { data: { values: { OPERATOR_API_APP_NAME: "unauthorized" } } })).status()).toBe(401);

  const pageErrors = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  // No browser request may escape this exact fixture origin.
  await page.route("**/*", async (route) => {
    expect(new URL(route.request().url()).origin).toBe(baseURL);
    await route.continue();
  });
  await page.goto("/console/#settings");
  const password = page.locator("#console-password");
  await expect(password).toBeVisible();
  await password.fill("SyntheticWrongPassword");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator("#login-error")).toContainText("invalid console password");
  await expect(page.locator('nav[aria-label="Operator sections"]')).toHaveCount(0);

  const sessionPromise = page.waitForResponse((response) => response.url().endsWith("/console/session") && response.request().method() === "POST");
  await password.fill(FIXTURE_PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const session = await sessionPromise;
  expect(session.status()).toBe(200);
  const { token, roles } = await session.json();
  expect(roles).toContain("administrator");
  const headers = { Authorization: `Bearer ${token}` };
  await expect(page.locator("#console-view")).toHaveAttribute("aria-label", "Settings view");
  await expect(page.getByRole("heading", { name: "Service status", exact: true })).toBeVisible();
  await expect(page.getByText("operator-api: up", { exact: true })).toBeVisible();
  const status = await request.get("/api/v1/console/status", { headers });
  expect(status.status()).toBe(200);
  const health = await status.json();
  expect(health.runtime_control).toBe("local_supervisor");
  expect(Object.keys(health.workers)).toHaveLength(10);
  expect(health.workers.curation).toBe(false);
  expect(health.workers["audit-anchor"]).toBe(false);

  const nameInput = page.getByLabel("OPERATOR_API_APP_NAME", { exact: true });
  await expect(nameInput).toHaveValue("console-smoke-original");
  const original = await nameInput.inputValue();
  const updated = "console-smoke-edited";
  const save = async (value) => {
    await nameInput.fill(value);
    const saved = page.waitForResponse((response) => response.url().endsWith("/console/config") && response.request().method() === "PUT");
    await page.getByRole("button", { name: "Save changes", exact: true }).click();
    const response = await saved;
    expect(response.status()).toBe(200);
    expect((await response.json()).changed).toContain("OPERATOR_API_APP_NAME");
    await expect(page.getByText(/Saved\. Changed:.*OPERATOR_API_APP_NAME/).last()).toBeVisible();
    const persisted = await request.get("/api/v1/console/config", { headers });
    expect(persisted.status()).toBe(200);
    expect((await persisted.json()).values.OPERATOR_API_APP_NAME).toBe(value);
  };
  await save(updated);
  await page.reload();
  await expect(nameInput).toHaveValue(updated);
  await save(original);
  await page.reload();
  await expect(nameInput).toHaveValue(original);
  const audit = await request.get("/__smoke__/audit", { headers });
  expect(audit.status()).toBe(200);
  expect((await audit.json()).events.filter((event) => event.action === "console.config.update")).toEqual([
    expect.objectContaining({ detail: { changed: expect.arrayContaining(["OPERATOR_API_APP_NAME"]) } }),
    expect.objectContaining({ detail: { changed: expect.arrayContaining(["OPERATOR_API_APP_NAME"]) } }),
  ]);
  expect(pageErrors).toEqual([]);
});

for (const width of [1280, 768]) {
  test(`library and campaign layout stay readable at ${width}px; chosen email supplies category and after-click content`, async ({ page }, testInfo) => {
    await page.setViewportSize({ width, height: 900 });
    const patternId = "20000000-0000-4000-8000-000000000001";
    const templateId = "20000000-0000-4000-8000-000000000002";
    const lessonId = "20000000-0000-4000-8000-000000000003";
    const rosterId = "20000000-0000-4000-8000-000000000004";
    const subject = "Microsoft 365 account verification — a long subject that must stay readable";
    const editedSubject = "October account notice";
    const editedWording = "Please review this account notice before the end of the week.";
    let editPreviewPayload;
    let editedClonePayload;
    let createdPayload;
    let audiencePayload;
    const data = {
      "/patterns": [{ campaign_pattern_id: patternId, approval_state: "approved", lure_category: "credential" }],
      "/templates": [
        { template_version_id: templateId, version: 1, subject, model_id: "synthetic-model-with-a-long-name", approval_state: "approved", reusable: true, is_clone: true, pattern_id: patternId },
        { template_version_id: "20000000-0000-4000-8000-000000000099", subject: "Draft for human review", approval_state: "draft", reusable: false, model_id: "synthetic" },
      ],
      "/templates/pending": [{ template_version_id: templateId, subject, plain_text: "Synthetic draft words", is_clone: true, requested_by: "other-synthetic-author" }],
      "/campaigns": [{ campaign_id: "20000000-0000-4000-8000-000000000005", title: "Synthetic campaign with a long title", sender_mailbox: "security@example.com", state: "draft", audience_frozen: true, audience_version: 1, roe_bound: true, training_lesson: { ready: true, title: "Recognize and report phishing with a long lesson title", bound_version: 1 }, launch_gate: { state: "unreviewed" }, can_configure_audience: true, can_configure_training: true, can_submit: true, can_approve_security: false, can_approve_privacy: false, can_schedule: false, can_publish: false, can_test_send: false, can_proof_send: true, can_recall: false }],
      "/audience-groups": { groups: [{ audience_group_id: rosterId, name: "Uploaded October roster", member_count: 3, recipient_ids: [] }] },
      "/recipients": { items: [], total: 0, limit: 500, offset: 0, truncated: false },
      "/training-resources": [{ training_resource_id: lessonId, title: "After-click explanation", version: 1, requires_completion: true }],
      "/sending-domains": { domains: [{ domain: "example.com", active: true }, { domain: "second.example.com", active: true }] },
      "/console/onboarding": { complete: true, completed: true, steps: [
        { id: "smtp", ready: true },
        { id: "training", ready: true, fields: [{ key: "OPERATOR_API_TRAINING_BASE_URL", value: "http://127.0.0.1:8001/v1/training/awareness" }] },
      ] },
      "/roe": { roes: [] },
      "/integrations/microsoft365/status": { reported_mailbox: { configured: false } },
      "/alerts/subscriptions": [],
    };
    await page.route("**/api/v1/**", async (route) => {
      const url = new URL(route.request().url());
      const pathname = url.pathname.replace("/api/v1", "");
      if (route.request().method() === "GET" && pathname === "/templates") {
        const approvalState = url.searchParams.get("approval_state");
        return route.fulfill({ json: data["/templates"].filter((template) => !approvalState || template.approval_state === approvalState) });
      }
      if (route.request().method() === "GET" && pathname === `/templates/${templateId}/preview`) {
        return route.fulfill({ json: {
          template_version_id: templateId, approval_state: "approved",
          subject, plain_text: "Original sample email", editable_subject: subject,
          editable_plain_text: "Original sample email\n\nContinue: {{ tracking.training_url }}",
        } });
      }
      if (route.request().method() === "POST" && pathname === "/templates/preview") {
        editPreviewPayload = route.request().postDataJSON();
        return route.fulfill({ json: { subject: editedSubject, plain_text: editedWording } });
      }
      if (route.request().method() === "POST" && pathname === `/templates/${templateId}/clone`) {
        expect(editPreviewPayload).toBeTruthy();
        editedClonePayload = route.request().postDataJSON();
        return route.fulfill({ status: 201, json: {
          template_version_id: "20000000-0000-4000-8000-000000000098",
          approval_state: "draft", requires_human_review: true,
        } });
      }
      if (route.request().method() === "POST" && pathname === "/campaigns") {
        createdPayload = route.request().postDataJSON();
        return route.fulfill({ status: 201, json: { campaign_id: "20000000-0000-4000-8000-000000000010" } });
      }
      if (route.request().method() === "PUT" && pathname.endsWith("/audience")) {
        audiencePayload = route.request().postDataJSON();
        return route.fulfill({ json: { changed: true } });
      }
      if (Object.hasOwn(data, pathname)) return route.fulfill({ json: data[pathname] });
      await route.continue();
    });
    await page.goto("/console/#templates");
    await page.locator("#console-password").fill(FIXTURE_PASSWORD);
    await page.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Template library & review" })).toBeVisible();
    await page.getByRole("button", { name: "Dismiss notification", exact: true }).click();
    const library = page.locator(".template-library-table");
    await expect(page.getByLabel("Filter templates by review state", { exact: true })).toHaveValue("approved");
    await expect(library.locator("tbody tr")).toHaveCount(1);
    await expect(library).not.toContainText("Draft for human review");
    await page.getByLabel("Filter templates by review state", { exact: true }).selectOption("");
    await page.getByRole("button", { name: "Search library", exact: true }).click();
    await expect(library.locator("tbody tr")).toHaveCount(2);
    const firstCell = library.locator("tbody tr").first().locator("td").first();
    const titleBox = await firstCell.locator("div").first().boundingBox();
    const badgeBox = await firstCell.getByText("Working copy", { exact: true }).boundingBox();
    expect(badgeBox.y).toBeGreaterThanOrEqual(titleBox.y + titleBox.height);
    const state = library.getByText("draft — human review required", { exact: true });
    const metrics = await state.evaluate((node) => ({ height: node.clientHeight, scroll: node.scrollHeight, width: node.clientWidth, scrollWidth: node.scrollWidth }));
    expect(metrics.scroll).toBeLessThanOrEqual(metrics.height + 1);
    expect(metrics.scrollWidth).toBeLessThanOrEqual(metrics.width + 1);
    const scroller = page.locator('.table-scroll[aria-label="Template library table"]');
    const libraryBox = await scroller.boundingBox();
    for (const action of [`Safely preview ${subject}`, `Select for current campaign: ${subject}`, "Edit wording & graphics"]) {
      const actionBox = await library.getByRole("button", { name: action, exact: true }).first().boundingBox();
      expect(actionBox.x + actionBox.width).toBeLessThanOrEqual(libraryBox.x + libraryBox.width + 1);
    }
    await page.screenshot({ path: testInfo.outputPath("template-library.png"), fullPage: true });
    await library.getByRole("button", { name: "Edit wording & graphics", exact: true }).first().click();
    const editor = page.getByRole("dialog", { name: "Edit a copy of this email", exact: true });
    await expect(editor.getByLabel("Email subject", { exact: true })).toHaveValue(subject);
    await expect(editor.getByLabel("Email wording", { exact: true })).toHaveValue("Original sample email\n\nContinue: {{ tracking.training_url }}");
    await editor.getByLabel("Email subject", { exact: true }).fill(editedSubject);
    await editor.getByLabel("Email wording", { exact: true }).fill(editedWording);
    await editor.getByRole("button", { name: "Save draft for review", exact: true }).click();
    await expect.poll(() => editedClonePayload).toBeTruthy();
    expect(editPreviewPayload).toEqual({ subject: editedSubject, plain_text: editedWording, safe_html: "" });
    expect(editedClonePayload).toEqual({
      subject: editedSubject, plain_text: editedWording,
      reason: "Operator adapted wording or graphics for an exercise",
    });
    await expect(page.getByText("Draft saved. Preview it, upload a logo if needed, and approve it in Draft review below.", { exact: true })).toBeVisible();
    await page.getByRole("button", { name: "Dismiss notification", exact: true }).click();
    await page.getByRole("button", { name: `Select for current campaign: ${subject}`, exact: true }).click();
    await expect(page.getByLabel("Company domain", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Send test email", exact: true })).toHaveCount(0);
    await expect(page.getByRole("button", { name: /freeze|lock/i })).toHaveCount(0);
    await page.screenshot({ path: testInfo.outputPath("campaigns.png"), fullPage: true });
  });
}

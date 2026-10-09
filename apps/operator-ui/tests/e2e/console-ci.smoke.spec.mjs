// Production UI/auth/config/status on scratch fixture state. No live deployment.
import { expect, test } from "@playwright/test";
import { readFile } from "node:fs/promises";

const FIXTURE_PASSWORD = "ConsoleSmokeSynthetic2026";

async function installHumanFlowFixture(page) {
  const id = (suffix) => `30000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`;
  const rosterId = id(1), templateId = id(2), patternId = id(3), lessonId = id(4), campaignId = id(5), roeId = id(6);
  const recipients = [
    { recipient_id: id(10), display_name: "Erik", masked_mailbox: "c***@example.com", department: "Trial", status: "active", is_test_account: true },
    { recipient_id: id(11), display_name: "", masked_mailbox: "p***@example.com", department: "Trial", status: "active", is_test_account: false },
    { recipient_id: id(12), display_name: "Outside", masked_mailbox: "o***@unauthorized.example", department: "Trial", status: "active", is_test_account: false },
  ];
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
    can_schedule: state.campaign.launch_gate.state === "reviewed",
    can_publish: state.campaign.launch_gate.state === "canary_succeeded",
    can_test_send: false, can_proof_send: false, can_recall: false,
  });
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request(), url = new URL(request.url());
    const path = url.pathname.replace("/api/v1", ""), method = request.method();
    if (path === "/templates" && state.failTemplates) return route.fulfill({ status: 429, headers: { "Retry-After": "1" }, json: { detail: "Too many requests" } });
    if (path === "/console/onboarding") return route.fulfill({ json: { ...data[path], complete: !state.setupIncomplete } });
    if (path === "/audience-groups") return route.fulfill({ json: { groups: state.rosterSaved ? [{ audience_group_id: rosterId, name: "Human trial roster", member_count: 3, recipient_ids: recipients.map((r) => r.recipient_id), created_at: "2026-10-09T00:00:00Z" }] : [] } });
    if (path === "/recipients") {
      const rows = url.searchParams.get("roster_id") === rosterId ? recipients : [pastRecipient, ...recipients];
      const limit = Number(url.searchParams.get("limit") || 100), offset = Number(url.searchParams.get("offset") || 0);
      return route.fulfill({ json: { items: rows.slice(offset, offset + limit), total: rows.length, limit, offset, truncated: offset + limit < rows.length } });
    }
    if (path === "/recipients/import/preview") return route.fulfill({ json: {
      preview_digest: "synthetic-preview-digest", input_rows: 3, header_detected: true, header_mode: "auto",
      columns: [{ index: 0, label: "email" }, { index: 1, label: "name" }, { index: 2, label: "department" }], mapping: { mailbox: 0, display_name: 1, department: 2 },
      counts: { created: 3, existing: 0, updateable: 0, blocked: 0, invalid: 0, duplicate: 0 }, can_apply: true, errors: [],
      roe_coverage: { checked: true, active_roe_domains: ["example.com"], uncovered: 1, uncovered_domains: ["unauthorized.example"] },
    } });
    if (path === "/recipients/import/apply") {
      state.writes.push({ path, body: request.postDataJSON() }); state.rosterSaved = true;
      return route.fulfill({ json: { created: 3, roster: { audience_group_id: rosterId, name: "Human trial roster", member_count: 3 } } });
    }
    if (path === `/templates/${templateId}/preview`) return route.fulfill({ json: { subject: "Approved human trial email", plain_text: "Dear sample recipient, this is a safe fixture preview." } });
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
      preview_hash: "exact-server-preview-hash", selected_count: 3, included_count: 2, excluded_count: 1, excluded_counts: { recipient_domain_not_authorized: 1 }, roe_id: roeId, over_limit: false,
      test_account_count: state.noTestAccount ? 0 : 1,
      recipients: recipients.slice(0, 2).map((r) => ({ ...r, mailbox: r.masked_mailbox, is_test_account: state.noTestAccount ? false : r.is_test_account })),
    } });
    if (path === `/campaigns/${campaignId}/audience/freeze`) {
      state.writes.push({ path, body: request.postDataJSON() });
      if (state.failFreeze) return route.fulfill({ status: 409, json: { detail: "recipient roster changed; preview again" } });
      state.campaign.audience_frozen = true; state.campaign.roe_bound = true;
      return route.fulfill({ json: { recipient_count: 2 } });
    }
    if (path === `/campaigns/${campaignId}/submit`) {
      state.writes.push({ path }); state.campaign.state = "approved"; state.campaign.launch_gate.state = "reviewed";
      return route.fulfill({ json: { state: "approved" } });
    }
    if (path === `/campaigns/${campaignId}/schedule`) {
      if (state.throttleSchedule) return route.fulfill({ status: 429, headers: { "Retry-After": "1" }, json: { detail: "Too many requests" } });
      state.writes.push({ path }); state.campaign.state = "scheduled"; state.campaign.launch_gate.state = "canary_queued";
      return route.fulfill({ json: { queued: 1 } });
    }
    if (path === `/campaigns/${campaignId}/publish`) {
      state.writes.push({ path }); state.campaign.launch_gate.state = "full_published";
      return route.fulfill({ json: { queued: 1 } });
    }
    if (Object.hasOwn(data, path)) return route.fulfill({ json: data[path] });
    await route.continue();
  });
  return { state, rosterId, campaignId };
}

test("human flow: downloadable CSV, exact saved roster, email selection in preview, one recipient confirmation and observable sends", async ({ page }, testInfo) => {
  const { state, rosterId, campaignId } = await installHumanFlowFixture(page);
  const errors = []; page.on("pageerror", (error) => errors.push(error.message));
  await page.goto("/console/#sending");
  await page.locator("#console-password").fill(FIXTURE_PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("button", { name: "View authorization for example.com", exact: true }).click();
  const authorization = page.getByRole("dialog", { name: "Authorization for example.com", exact: true });
  await expect(authorization).toContainText("Synthetic company"); await expect(authorization).toContainText("Status: Active");
  await authorization.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: "Continue to recipient roster", exact: true }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download CSV template", exact: true }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("recipient-roster-template.csv");
  await download.saveAs(testInfo.outputPath("recipient-roster-template.csv"));
  expect(await readFile(await download.path(), "utf8")).toBe("\uFEFFemail,name,department\r\n");
  await expect(page.getByText("Approved recipient domains: ", { exact: true }).first()).toBeVisible();
  await expect(page.getByRole("button", { name: "Collect employee-reported phishing", exact: true })).not.toBeVisible();
  await page.getByLabel("Save this upload as a named roster", { exact: true }).fill("Human trial roster");
  await page.getByLabel("Choose a CSV file", { exact: true }).setInputFiles({ name: "roster.csv", mimeType: "text/csv", buffer: Buffer.from("email,name,department\ncanary@example.com,Erik,Trial\nparticipant@example.com,,Trial\noutside@unauthorized.example,Outside,Trial\n") });
  await page.getByRole("button", { name: "Validate roster", exact: true }).click();
  await expect(page.getByText(/1 recipient will import but cannot be sent to/)).toBeVisible();
  await page.getByRole("button", { name: "Confirm validated roster", exact: true }).click();
  await page.getByRole("dialog", { name: "Confirm this validated recipient roster?", exact: true }).getByRole("button", { name: "Confirm roster", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Review saved recipients", exact: true }).click();
  await expect(page.getByLabel("Viewing recipient roster", { exact: true })).toHaveValue(rosterId);
  const recipientTable = page.getByRole("table", { name: "Authorized recipient records and test-account designations", exact: true });
  await expect(recipientTable.locator("tbody tr")).toHaveCount(3); await expect(recipientTable).not.toContainText("Past import");
  await expect(recipientTable).toContainText("Rejected for sending: domain not authorized");
  await page.screenshot({ path: testInfo.outputPath("human-roster.png"), fullPage: true });
  await page.getByRole("button", { name: "Choose an email for this roster", exact: true }).click();
  await page.getByRole("button", { name: "Safely preview Approved human trial email", exact: true }).click();
  await page.getByRole("dialog", { name: "Preview: Approved human trial email", exact: true }).getByRole("button", { name: "Select for current campaign", exact: true }).click();
  await expect(page.locator("#c-roster")).toHaveValue(rosterId);
  await page.locator("#c-title").fill("Human workflow fixture");
  await page.getByRole("button", { name: "Create campaign", exact: true }).click();
  await page.getByRole("button", { name: "Confirm recipients for Human workflow fixture", exact: true }).click();
  let confirmation = page.getByRole("dialog", { name: "Confirm recipients: Human workflow fixture", exact: true });
  await expect(confirmation).toContainText("2 recipients included; 1 excluded");
  await expect(confirmation.getByRole("table", { name: "Validated campaign recipients", exact: true })).not.toContainText("unauthorized.example");
  await confirmation.getByRole("button", { name: "Cancel", exact: true }).click();
  expect(state.writes.filter((w) => /freeze|submit|schedule|publish/.test(w.path))).toEqual([]);
  state.noTestAccount = true;
  await page.getByRole("button", { name: "Confirm recipients for Human workflow fixture", exact: true }).click();
  confirmation = page.getByRole("dialog", { name: "Confirm recipients: Human workflow fixture", exact: true });
  await expect(confirmation.getByRole("button", { name: "Confirm recipients", exact: true })).toBeDisabled();
  await expect(confirmation.getByRole("button", { name: /Designate .* as the test recipient/ }).first()).toBeVisible();
  await confirmation.getByRole("button", { name: "Cancel", exact: true }).click(); state.noTestAccount = false;
  await page.getByRole("button", { name: "Confirm recipients for Human workflow fixture", exact: true }).click();
  await page.getByRole("dialog", { name: "Confirm recipients: Human workflow fixture", exact: true }).getByRole("button", { name: "Confirm recipients", exact: true }).click();
  await expect(page.getByText("Recipients confirmed. Next: Send test email to the designated test account.", { exact: true })).toBeVisible();
  const preparation = state.writes.filter((w) => /freeze|submit/.test(w.path));
  expect(preparation.map((w) => w.path)).toEqual([`/campaigns/${campaignId}/audience/freeze`, `/campaigns/${campaignId}/submit`]);
  expect(preparation[0].body).toEqual({ preview_hash: "exact-server-preview-hash" });
  expect(state.writes.find((w) => w.path.endsWith("/audience")).body.group_ids).toEqual([rosterId]);
  state.failTemplates = true;
  await page.getByRole("button", { name: "Refresh current view", exact: true }).click();
  await expect(page.getByText(/Some campaign data could not be loaded.*Wait at least 1 seconds/)).toBeVisible();
  await expect(page.getByText("That email is no longer approved. Choose another approved template.", { exact: true })).toHaveCount(0);
  state.failTemplates = false;
  await page.getByRole("button", { name: "Refresh current view", exact: true }).click();
  await expect(page.locator("#c-template")).toHaveValue("30000000-0000-4000-8000-000000000002");
  state.throttleSchedule = true;
  await page.getByRole("button", { name: "Send the test (canary) for Human workflow fixture", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Send test email", exact: true }).click();
  await expect(page.getByText(/Too many requests.*Wait at least 1 seconds.*not been automatically retried/)).toBeVisible();
  expect(state.writes.filter((w) => w.path.endsWith("/schedule"))).toHaveLength(0);
  expect(state.campaign.launch_gate.state).toBe("reviewed");
  state.throttleSchedule = false;
  state.setupIncomplete = true;
  await page.getByRole("button", { name: "Send the test (canary) for Human workflow fixture", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Send test email", exact: true }).click();
  await expect(page.getByText(/Test email queued — waiting for delivery confirmation/)).toBeVisible();
  await expect(page).toHaveURL(/#campaigns$/);
  await expect(page.locator('fieldset[data-refresh-guard="New campaign draft"]')).toHaveAttribute("data-dirty", "false");
  await expect(page.getByRole("button", { name: "Send the test (canary) for Human workflow fixture", exact: true })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Send to everyone (publish full audience) for Human workflow fixture", exact: true })).toHaveCount(0);
  state.campaign.launch_gate = { state: "canary_succeeded", provider: "smtp", canary_evidence_hash: "synthetic-evidence", canary_expires_at: "2050-01-01T00:00:00Z" };
  await page.getByRole("button", { name: "Refresh current view", exact: true }).click();
  await expect(page.getByText("Test email passed. Next: Send campaign to the confirmed recipient list.", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Send to everyone (publish full audience) for Human workflow fixture", exact: true }).click();
  await page.getByRole("dialog").getByRole("button", { name: "Send campaign", exact: true }).click();
  await expect(page.getByText("Campaign send started. Open Report to follow delivery and training results.", { exact: true })).toBeVisible();
  expect(state.writes.filter((w) => w.path.endsWith("/schedule"))).toHaveLength(1);
  expect(state.writes.filter((w) => w.path.endsWith("/publish"))).toHaveLength(1);
  expect(errors).toEqual([]);
});

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
    await expect(page.locator("#c-template")).toHaveValue(templateId);
    await expect(page.locator("#c-pattern")).toBeHidden();
    await expect(page.locator("#c-training-resource")).toBeHidden();
    await expect(page.locator("#c-training-resource")).toHaveValue(lessonId);
    // Training setup is independent of either registered sending domain.
    // A missing hidden required field otherwise blocks the ordinary Create path.
    await expect(page.locator("#c-tdomain")).toHaveValue("127.0.0.1");
    await expect(page.locator("#c-sender")).toHaveValue("");
    if (width === 768) {
      const titleField = await page.locator("#c-title").boundingBox();
      const templateField = await page.locator("#c-template").boundingBox();
      expect(Math.abs(templateField.x - titleField.x)).toBeLessThanOrEqual(1);
      expect(Math.abs(templateField.width - titleField.width)).toBeLessThanOrEqual(1);
      expect(templateField.y).toBeGreaterThan(titleField.y);
    }
    await expect(page.locator(".campaign-table thead")).not.toContainText("Training lesson");
    await expect(page.locator(".campaign-table thead")).toContainText("Next steps");
    const campaignBox = await page.locator('.table-scroll[aria-label="Campaign table"]').boundingBox();
    for (const button of await page.locator(".campaign-table").getByRole("button").all()) {
      const buttonBox = await button.boundingBox();
      expect(buttonBox.x + buttonBox.width).toBeLessThanOrEqual(campaignBox.x + campaignBox.width + 1);
    }
    await expect(page.getByRole("button", { name: "Review audience for Synthetic campaign with a long title", exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Change after-click page for Synthetic campaign with a long title", exact: true })).toBeVisible();
    await page.screenshot({ path: testInfo.outputPath("campaigns.png"), fullPage: true });
    await page.locator("#c-domain").selectOption("example.com");
    await expect(page.locator("#c-sender")).toHaveValue("security-awareness@example.com");
    await page.locator("#c-roster").selectOption(rosterId);
    await page.locator('nav[aria-label="Operator sections"]').getByRole("button", { name: "Template review", exact: true }).click();
    await page.getByRole("dialog", { name: "Discard unsaved changes?", exact: true }).getByRole("button", { name: "Discard changes", exact: true }).click();
    await expect(page.getByRole("heading", { name: "Template library & review", exact: true })).toBeVisible();
    await page.getByRole("button", { name: `Select for current campaign: ${subject}`, exact: true }).click();
    await expect(page.locator("#c-roster")).toHaveValue(rosterId);
    await expect(page.locator("#c-template")).toHaveValue(templateId);
    await page.locator("#c-domain").selectOption("example.com");
    await expect(page.locator("#c-tdomain")).toHaveValue("127.0.0.1");
    await page.locator("#c-title").fill("Synthetic roster exercise");
    await page.getByRole("button", { name: "Create campaign", exact: true }).click();
    await expect.poll(() => audiencePayload).toBeTruthy();
    expect(createdPayload.pattern_id).toBe(patternId);
    expect(createdPayload.template_version_id).toBe(templateId);
    expect(createdPayload.training_resource_id).toBe(lessonId);
    expect(createdPayload.training_domain).toBe("127.0.0.1");
    expect(audiencePayload.group_ids).toEqual([rosterId]);
    expect(audiencePayload.departments).toEqual([]);
    expect(audiencePayload.include_recipient_ids).toEqual([]);

    // Missing setup must stay visible rather than inventing training.<mail-domain>.
    data["/console/onboarding"] = { complete: true, completed: true, steps: [] };
    data["/sending-domains"] = { domains: [{ domain: "example.com", active: true }] };
    await page.reload();
    await expect(page.locator("#c-sender")).toHaveValue("security-awareness@example.com");
    await expect(page.locator("#c-tdomain")).toHaveValue("");
  });
}

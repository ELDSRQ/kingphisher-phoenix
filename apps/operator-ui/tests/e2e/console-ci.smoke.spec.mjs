// Production UI/auth/config/status on scratch fixture state. No live deployment.
import { expect, test } from "@playwright/test";

const FIXTURE_PASSWORD = "ConsoleSmokeSynthetic2026";

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
      "/sending-domains": { domains: [{ domain: "example.com", active: true }] },
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
    for (const action of [`Safely preview ${subject}`, `Use ${subject} in a campaign`, "Edit wording & graphics"]) {
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
    await page.getByRole("button", { name: `Use ${subject} in a campaign`, exact: true }).click();
    await expect(page.locator("#c-template")).toHaveValue(templateId);
    await expect(page.locator("#c-pattern")).toBeHidden();
    await expect(page.locator("#c-training-resource")).toBeHidden();
    await expect(page.locator("#c-training-resource")).toHaveValue(lessonId);
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
    await page.getByRole("button", { name: `Use ${subject} in a campaign`, exact: true }).click();
    await expect(page.locator("#c-roster")).toHaveValue(rosterId);
    await expect(page.locator("#c-template")).toHaveValue(templateId);
    await page.locator("#c-domain").selectOption("example.com");
    await page.getByText("Advanced delivery settings", { exact: true }).click();
    await page.locator("#c-tdomain").fill("127.0.0.1");
    await page.locator("#c-title").fill("Synthetic roster exercise");
    await page.getByRole("button", { name: "Create campaign", exact: true }).click();
    await expect.poll(() => audiencePayload).toBeTruthy();
    expect(createdPayload.pattern_id).toBe(patternId);
    expect(createdPayload.template_version_id).toBe(templateId);
    expect(createdPayload.training_resource_id).toBe(lessonId);
    expect(audiencePayload.group_ids).toEqual([rosterId]);
    expect(audiencePayload.departments).toEqual([]);
    expect(audiencePayload.include_recipient_ids).toEqual([]);
  });
}

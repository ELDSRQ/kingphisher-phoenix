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

// Dedicated isolated gate: never consumes live-console URLs, passwords or storage state.
import { defineConfig, devices } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const projectRoot = fileURLToPath(new URL("../../../../", import.meta.url));
// Playwright reloads this file in workers. Only its runner chooses the port and
// run identity; worker processes inherit those values. Ambient values supplied
// to the runner cannot redirect this gate to an existing console.
let port;
let runId;
if (process.env.TEST_WORKER_INDEX !== undefined) {
  port = Number(process.env.KP_CONSOLE_CI_PORT);
  runId = process.env.KP_CONSOLE_CI_RUN_ID;
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || !/^[a-f0-9-]{36}$/.test(runId || "")) {
    throw new Error("missing runner-owned console smoke endpoint");
  }
} else {
  // An intervening bind fails startup rather than reusing or terminating
  // another process.
  const reservation = createServer();
  await new Promise((done, reject) => {
    reservation.once("error", reject);
    reservation.listen(0, "127.0.0.1", done);
  });
  port = reservation.address().port;
  await new Promise((done, reject) => reservation.close((error) => error ? reject(error) : done()));
  runId = randomUUID();
  process.env.KP_CONSOLE_CI_PORT = String(port);
  process.env.KP_CONSOLE_CI_RUN_ID = runId;
}
const baseURL = `http://127.0.0.1:${port}`;
const shellQuote = (value) => `'${value.replaceAll("'", "'\\''")}'`;

export default defineConfig({
  testDir: ".",
  testMatch: "console-ci.smoke.spec.mjs",
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  timeout: 45_000,
  reporter: [["list"], ["html", { outputFolder: resolve(projectRoot, "data/qualification/console-smoke", runId, "report"), open: "never" }]],
  outputDir: resolve(projectRoot, "data/qualification/console-smoke", runId, "test-results"),
  metadata: { fixtureRunId: runId },
  use: {
    baseURL,
    storageState: { cookies: [], origins: [] },
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `${shellQuote(resolve(projectRoot, ".venv/bin/python"))} ${shellQuote(resolve(projectRoot, "scripts/operator/e2e/console_smoke_fixture.py"))} --port ${port} --run-id ${runId}`,
    cwd: projectRoot,
    url: `${baseURL}/__smoke__/ready`,
    reuseExistingServer: false,
    timeout: 30_000,
    gracefulShutdown: { signal: "SIGTERM", timeout: 5_000 },
    env: { KP_DISABLE_DOTENV: "1", PYTHONUNBUFFERED: "1" },
  },
});

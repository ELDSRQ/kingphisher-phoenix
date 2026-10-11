// @ts-check
// Operator-run live checks. The current worker is .105; use its existing
// controller tunnel through OPERATOR_CONSOLE_URL. This starts no web server.
import { defineConfig, devices } from "@playwright/test";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const baseURL = process.env.OPERATOR_CONSOLE_URL || "http://127.0.0.1:8000";
const projectRoot = fileURLToPath(new URL("../../../../", import.meta.url));
// Preserve earlier results: Playwright clears its output directory at startup.
// Only the runner chooses a new directory; workers inherit the same identity.
const runId = process.env.TEST_WORKER_INDEX === undefined
  ? randomUUID() : process.env.KP_LIVE_CONSOLE_RUN_ID;
if (!/^[a-f0-9-]{36}$/.test(runId || "")) throw new Error("missing live-console run identity");
process.env.KP_LIVE_CONSOLE_RUN_ID = runId;
const evidenceDir = resolve(projectRoot, "data/qualification/live-console", runId);

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.(smoke|a11y)\.spec\.mjs/,
  testIgnore: "console-ci.smoke.spec.mjs", // Dedicated scratch fixture; never run against the live console.
  // No webServer block on purpose: the operator owns stack lifecycle.
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  outputDir: resolve(evidenceDir, "test-results"),
  metadata: { liveConsoleRunId: runId, evidenceDir },
  use: {
    baseURL,
    // Live traces can contain deployment credentials and bearer tokens.
    trace: "off",
    screenshot: "only-on-failure",
    // A pre-authenticated session may be supplied by the operator; when unset
    // the spec performs the local-stack password login itself.
    storageState: process.env.OPERATOR_CONSOLE_STORAGE_STATE || undefined,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});

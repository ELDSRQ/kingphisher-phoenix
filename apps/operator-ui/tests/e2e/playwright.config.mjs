// @ts-check
// TST-002 SCAFFOLD -- operator-run only. This config is intentionally minimal
// and starts NO web server: the operator brings up the operator-api + console
// (the platform runs on the .140 host, not localhost -- see MEMORY) and points
// this suite at it via OPERATOR_CONSOLE_URL. Nothing here installs browsers or
// runs the suite automatically.
import { defineConfig, devices } from "@playwright/test";

const baseURL = process.env.OPERATOR_CONSOLE_URL || "http://127.0.0.1:8000";

export default defineConfig({
  testDir: ".",
  testMatch: /.*\.smoke\.spec\.mjs/,
  // No webServer block on purpose: the operator owns stack lifecycle.
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL,
    trace: "on-first-retry",
    // A pre-authenticated session may be supplied by the operator; when unset
    // the spec performs the local-stack password login itself.
    storageState: process.env.OPERATOR_CONSOLE_STORAGE_STATE || undefined,
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});

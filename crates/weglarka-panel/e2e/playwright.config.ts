// Browser tests of the panel's scripts against a fixture server (`fixture.ts`) that serves the
// real template section, `app.js` and the vendored htmx under the panel's CSP.
import { defineConfig, devices } from "@playwright/test";

const port = Number(process.env.FIXTURE_PORT ?? 4173);

export default defineConfig({
  testDir: "tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? [["list"], ["github"]] : "list",
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "bun fixture.ts",
    url: `http://127.0.0.1:${port}/__health`,
    reuseExistingServer: false,
    env: { FIXTURE_PORT: String(port), PORTAL_PORT: String(port + 1) },
  },
});

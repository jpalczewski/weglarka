// #444: behind forward auth an ended provider session makes the ingress answer the Resources poll
// before the panel can, so the panel's own 286 "session ended" fragment never arrives.
import { expect, test, type Page } from "@playwright/test";

const ENDED = "Your session has ended.";

test("runs on the Bun runtime", () => {
  // `playwright test` started without `bun --bun` silently runs on Node and still passes.
  expect(typeof (globalThis as { Bun?: unknown }).Bun).toBe("object");
});

async function open(page: Page, request: Page["request"]) {
  const violations: string[] = [];
  // A script or style the CSP blocks is a bug; a blocked `connect-src` is the redirect under test
  // (the panel's CSP refuses the followed redirect to the portal, which is how it fails in production).
  page.on("console", (msg) => {
    const text = msg.text();
    if (msg.type() === "error" && /Content Security Policy/i.test(text) && !/connect-src/.test(text)) {
      violations.push(text);
    }
  });
  await request.get("/__mode?m=ok");
  await page.goto("/");
  await expect(page.locator("#stats-live")).toContainText("Sampled poll");
  return violations;
}

const polls = async (request: Page["request"]) => Number(await (await request.get("/__polls")).text());

for (const [mode, what] of [
  ["redirect", "a redirect to the sign-in portal"],
  ["unauthorized", "a bare 401"],
  ["forbidden", "a bare 403"],
] as const) {
  test(`${what} from the ingress ends the poll`, async ({ page }) => {
    const violations = await open(page, page.request);
    await page.request.get(`/__mode?m=${mode}`);
    const section = page.locator("#stats-live");
    await expect(section).toContainText(ENDED);
    await expect(section.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/auth/login");
    await expect(section).not.toContainText("Sampled");
    await expect(page.locator("[hx-get]")).toHaveCount(0);
    // Polling stopped: no further request over several intervals.
    const seen = await polls(page.request);
    await page.waitForTimeout(1500);
    expect(await polls(page.request)).toBe(seen);
    expect(violations).toEqual([]);
  });
}

test("a dropped connection keeps polling and the last data", async ({ page }) => {
  const violations = await open(page, page.request);
  let aborted = 0;
  await page.route("**/apps/web/stats", (route) => {
    aborted += 1;
    return route.abort("internetdisconnected");
  });
  // Several polls fail (each with its redirect-less probe) without ending the section.
  await expect.poll(() => aborted, { timeout: 5000 }).toBeGreaterThan(4);
  const section = page.locator("#stats-live");
  await expect(section).toContainText("Sampled poll");
  await expect(section).not.toContainText(ENDED);
  // The network comes back: the next poll updates the section again.
  await page.unroute("**/apps/web/stats");
  await page.request.get("/__mode?m=ok");
  await expect(section).toContainText("Sampled poll 1.");
  expect(violations).toEqual([]);
});

// The site page's environment cards under the panel's CSP and stylesheet: nothing blocked, and no
// horizontal scrolling on a phone even with long domains.
import { expect, test } from "@playwright/test";

test("environment cards render under the CSP without page overflow", async ({ page }) => {
  const violations: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error" && /Content Security Policy/i.test(msg.text())) violations.push(msg.text());
  });
  await page.setViewportSize({ width: 375, height: 800 });
  await page.goto("/sites/blog");

  const cards = page.locator(".env-card");
  await expect(cards).toHaveCount(3);
  await expect(cards.first().getByRole("heading", { level: 2 })).toContainText("dev");
  await expect(cards.nth(1)).toContainText("pending promotion");
  await expect(cards.first().getByRole("link", { name: "blog-dev" })).toHaveAttribute("href", "/apps/blog-dev");

  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
  expect(overflow).toBeLessThanOrEqual(0);
  expect(violations).toEqual([]);
});

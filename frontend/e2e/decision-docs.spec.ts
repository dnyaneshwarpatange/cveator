import { test, expect, type BrowserContext } from "@playwright/test";

test.use({ actionTimeout: 30_000 });
test.setTimeout(120_000);

// Opt in with an existing local test account. Never store credentials or auth state in the repo.
let cookies: Awaited<ReturnType<BrowserContext["cookies"]>> = [];
test.beforeAll(async ({ request }) => {
  test.skip(!process.env.E2E_EMAIL || !process.env.E2E_PASSWORD, "Requires a verified local test account");
  const response = await request.post("/api/session/login", {
    headers: { Origin: "http://localhost:3002" },
    data: { email: process.env.E2E_EMAIL, password: process.env.E2E_PASSWORD }, timeout: 60_000,
  });
  expect(response.status()).toBe(200);
  cookies = (await request.storageState()).cookies;
});
test.beforeEach(async ({ context }) => {
  await context.addCookies(cookies);
});

test("real imported vulnerability supports triage and fits desktop/mobile", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/dashboard/cves/CVE-2021-44228");
  await expect(page.getByRole("heading", { name: "Remediation & mitigation evidence" })).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText("Your exposure: unverified", { exact: true })).toBeVisible();
  await expect(page.locator(".cve-description")).not.toHaveText("No description is recorded.");
  await expect(page.locator(".affected-record").first()).toBeVisible();
  await expect(page.getByRole("heading", { name: "Attack requirements & impact" })).toBeVisible();
  await expect(page.locator(".attack-facts").first()).toContainText("Privileges required");
  const expandConditions = page.getByRole("button", { name: /Show all \d+ conditions/ });
  if (await expandConditions.count()) {
    await expect(page.locator(".affected-record")).toHaveCount(8);
    await expandConditions.click();
    expect(await page.locator(".affected-record").count()).toBeGreaterThan(8);
    await page.getByRole("button", { name: "Show fewer conditions" }).click();
  }
  const expandReferences = page.getByRole("button", { name: /Show all \d+ references/ });
  if (await expandReferences.count()) {
    await expect(page.locator(".reference-list li")).toHaveCount(10);
    await expandReferences.click();
    expect(await page.locator(".reference-list li").count()).toBeGreaterThan(10);
    await page.getByRole("button", { name: "Show fewer references" }).click();
  }
  await page.evaluate(() => scrollTo(0, 0));
  await page.screenshot({ path: test.info().outputPath("detail-desktop.png") });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("detail-mobile.png") });
  await page.locator("#technical").screenshot({ path: test.info().outputPath("attack-requirements-mobile.png") });
});

test("missing evidence stays unknown and unsafe references are not links", async ({ page }) => {
  await page.route("**/api/intelligence/cves/CVE-2099-12345", route => route.fulfill({ json: {
    cve_id: "CVE-2099-12345", cvss_score: null, epss_score: null, is_kev: false,
    published_at: null, last_modified_at: null, description: "Evidence is incomplete.",
    products: [], vendors: [], history: [],
    normalized: { references: ["javascript:alert(1)", "https://vendor.example/advisory"], affected: [] },
    decision_evidence: { solutions: ["<script>alert(1)</script>"], workarounds: [], exploits: [], exploitation: {} },
  } }));
  await page.goto("/dashboard/cves/CVE-2099-12345");
  await expect(page.getByRole("heading", { name: "Assess your exposure" })).toBeVisible();
  await expect(page.getByText("No workaround is recorded.", { exact: false })).toBeVisible();
  await expect(page.locator("#remediation")).toContainText("<script>alert(1)</script>");
  await expect(page.locator('a[href^="javascript:"]')).toHaveCount(0);
  await expect(page.getByText("Imported sources:", { exact: false })).toHaveCount(0);
});

test("documentation explains auth, switches framework examples and filters endpoints", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto("/dashboard/api-docs");
  await expect(page.getByRole("heading", { name: "Authentication lifecycle" })).toBeVisible();
  for (const [name, content] of [["Vue 3", "<script setup>"], ["Angular", "provideHttpClient"], ["Python / FastAPI", "httpx.Client"], ["React / Next.js", "useState"]]) {
    // A cold Next dev page can be visible before client hydration completes.
    await expect(async () => {
      await page.getByRole("button", { name, exact: true }).click();
      await expect(page.locator("#frameworks .framework-example")).toContainText(content);
    }).toPass({ timeout: 30_000 });
  }
  await page.getByLabel("Search endpoints").fill("/api/session/register");
  await expect(page.getByRole("status").filter({ hasText: "endpoints" })).toHaveText("3 endpoints");
  await page.getByLabel("Search endpoints").fill("");
  await page.evaluate(() => scrollTo(0, 0));
  await page.screenshot({ path: test.info().outputPath("docs-desktop.png") });
  await page.setViewportSize({ width: 390, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: test.info().outputPath("docs-mobile.png") });
});

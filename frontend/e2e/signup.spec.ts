import { test, expect } from "@playwright/test";

test("email link opens verification without exposing a password or automatically verifying", async ({page}) => {
  const state = {id:"00000000-0000-4000-8000-000000000001", email:"test@example.com", expiresAt:Date.now()+600000, resendAt:Date.now()+60000};
  await page.goto("/register#verification=" + encodeURIComponent(JSON.stringify(state)));
  await expect(page.getByRole("heading",{name:"Verify your email"})).toBeVisible();
  await expect(page.getByLabel("Verification code",{exact:true})).toHaveValue("");
  await expect(page).toHaveURL(/\/register$/);
});

test("OTP screen survives reload, rejects wrong code, resends without password and verifies", async ({page}) => {
  const challenge = "00000000-0000-4000-8000-000000000001";
  const next = "00000000-0000-4000-8000-000000000002";
  await page.route("**/api/session/register", route => route.fulfill({status:202, json:{challenge_id:challenge}}));
  await page.route("**/api/session/register/resend", async route => {
    expect(route.request().postDataJSON()).toEqual({challenge_id:challenge});
    await route.fulfill({status:202,json:{challenge_id:next}});
  });
  await page.route("**/api/session/register/verify", async route => {
    const body = route.request().postDataJSON();
    if(body.code !== "123456") return route.fulfill({status:400,json:{detail:"Code is invalid or expired."}});
    expect(body.challenge_id).toBe(next);
    return route.fulfill({status:200,json:{user:{email:"test@example.com"}}});
  });
  await page.route("**/dashboard", route => route.fulfill({contentType:"text/html",body:"<h1>Test dashboard</h1>"}));
  await page.goto("/register");
  await page.getByLabel("Organization name").fill("Browser test");
  await page.getByLabel("Work email").fill("test@example.com");
  await page.getByLabel("Password", {exact:true}).fill("Browser-test-password-2026!");
  await page.getByRole("button",{name:"Send verification code"}).click();
  await expect(page.getByRole("heading",{name:"Verify your email"})).toBeVisible();
  const stored = await page.evaluate(() => sessionStorage.getItem("cveator.signup.challenge"));
  expect(stored).not.toContain("password");
  await page.reload();
  await expect(page.getByRole("heading",{name:"Verify your email"})).toBeVisible();
  await page.getByLabel("Verification code",{exact:true}).fill("000000");
  await page.getByRole("button",{name:"Verify and create workspace"}).click();
  await expect(page.getByRole("alert").filter({hasText:"Code is invalid"})).toBeVisible();
  await page.evaluate(() => {
    const key = "cveator.signup.challenge";
    const value = JSON.parse(sessionStorage.getItem(key)!);
    value.resendAt = Date.now() - 1;
    sessionStorage.setItem(key, JSON.stringify(value));
  });
  await page.reload();
  await page.getByRole("button",{name:"Resend code",exact:true}).click();
  await expect(page.getByRole("status")).toContainText("new code");
  await page.getByLabel("Verification code",{exact:true}).fill("123456");
  await page.getByRole("button",{name:"Verify and create workspace"}).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  expect(await page.evaluate(() => sessionStorage.getItem("cveator.signup.challenge"))).toBeNull();
});

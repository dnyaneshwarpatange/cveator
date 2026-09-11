import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { expect, it } from "vitest";
import { apiReference } from "./api-reference";

it("documents only implemented browser API methods", () => {
  for (const entry of apiReference) {
    const path = resolve("app", entry.path.slice(1).replace("{cveId}", "[cveId]"), "route.ts");
    expect(existsSync(path), entry.path).toBe(true);
    expect(readFileSync(path, "utf8"), entry.path).toMatch(new RegExp(`export async function ${entry.method}\\(`));
  }
});
it("does not publish administrative source endpoints in the ordinary-user reference", () => {
  expect(apiReference.some(entry => entry.path === "/api/intelligence/status")).toBe(false);
});

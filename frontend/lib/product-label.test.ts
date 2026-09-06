import { describe, expect, it } from "vitest";
import { productVersionLabel } from "@/lib/product-label";

describe("subscription scope labels", () => {
  const product = { id: 1, vendor: "atlassian", product_name: "jira", version: "*" };
  it("makes product-family scope explicit", () => {
    expect(productVersionLabel(product)).toBe("All versions");
    expect(productVersionLabel({ ...product, version: "" })).toBe("All versions");
  });
  it("does not label an unspecified or exact version as the whole family", () => {
    expect(productVersionLabel({ ...product, version: "-" })).toBe("Version unspecified");
    expect(productVersionLabel({ ...product, version: "9.12.36" })).toBe("9.12.36");
  });
});

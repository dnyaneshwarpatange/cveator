import { describe, expect, it } from "vitest";

import { severityClassName, severityLabel } from "@/lib/severity";

describe("severity presentation", () => {
  it("gives every backend severity a non-empty label and visual treatment", () => {
    for (const severity of ["critical", "high", "medium", "low", "unknown"] as const) {
      expect(severityLabel[severity]).not.toHaveLength(0);
      expect(severityClassName[severity]).toContain("bg-");
    }
  });
});

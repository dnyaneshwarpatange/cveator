import { expect, it } from "vitest";
import { proxyBackendResponse } from "./backend-response";

it.each([204, 205, 304])("forwards bodyless status %i without constructing an invalid response", async (status) => {
  const result = await proxyBackendResponse(new Response(null, { status }));
  expect(result.status).toBe(status);
  expect(await result.text()).toBe("");
});

it("preserves successful JSON responses", async () => {
  const result = await proxyBackendResponse(Response.json({ product_id: 1 }));
  expect(await result.json()).toEqual({ product_id: 1 });
});

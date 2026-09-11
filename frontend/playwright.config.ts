import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./e2e", workers: 1, timeout: 90_000,
  use: {baseURL: "http://localhost:3002", channel: "msedge", headless: true},
});

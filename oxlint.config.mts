import { defineConfig } from "oxlint";
import core from "ultracite/oxlint/core";

export default defineConfig({
  env: core.env,
  extends: [core],
  // site/figure/kit is the Anatomy kit, vendored as published (MIT).
  ignorePatterns: [...core.ignorePatterns, "site/figure/kit/**"],
});

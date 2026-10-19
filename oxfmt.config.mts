import { defineConfig } from "oxfmt";
import ultracite from "ultracite/oxfmt";

export default defineConfig({
  ...ultracite,
  // site/figure/kit is the Anatomy kit, vendored as published (MIT).
  ignorePatterns: [...(ultracite.ignorePatterns ?? []), "site/figure/kit/**"],
});

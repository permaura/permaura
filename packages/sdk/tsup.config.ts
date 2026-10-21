import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  // @permaura/types and zod are real runtime deps, so keep them external, not bundled.
  external: ["@permaura/types", "zod"],
});

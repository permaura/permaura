import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  // React is a peer dependency, never bundle it.
  external: ["react", "react-dom", "react/jsx-runtime"],
});

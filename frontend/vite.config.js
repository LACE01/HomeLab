// OPT-IN Vite build (default build is still CRA/react-scripts; see package.json
// "build" vs "build:vite" and the Dockerfile FRONTEND_BUILD_CMD arg).
//
// CRA-compatibility, verified against a mixed .js/.jsx tree:
//   * JSX lives in BOTH .js and .jsx files. esbuild handles all of them via the
//     include below; `exclude: []` is required -- Vite's default esbuild exclude
//     otherwise skips these and Rollup then chokes on raw JSX.
//   * The app reads process.env.REACT_APP_* (CRA convention); those are `define`d
//     here so the same source works under Vite untouched.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  define: {
    "process.env.REACT_APP_BACKEND_URL": JSON.stringify(process.env.REACT_APP_BACKEND_URL ?? ""),
    "process.env.REACT_APP_ENABLE_GOOGLE_SIGNIN": JSON.stringify(process.env.REACT_APP_ENABLE_GOOGLE_SIGNIN ?? ""),
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "production"),
  },
  // esbuild transforms JSX in .js/.jsx/.ts/.tsx under src/. exclude:[] is required.
  esbuild: { loader: "jsx", include: /src\/.*\.[jt]sx?$/, exclude: [] },
  optimizeDeps: { esbuildOptions: { loader: { ".js": "jsx" } } },
  build: { outDir: "build", chunkSizeWarningLimit: 1500 },  // outDir=build so the Dockerfile copy works for both toolchains
  server: {
    port: 3000,
    proxy: { "/api": { target: process.env.VITE_DEV_BACKEND || "http://localhost:8000", changeOrigin: true } },
  },
});

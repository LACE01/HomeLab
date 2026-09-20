// OPT-IN Vite build (the default build is still CRA/react-scripts; see package.json
// "build" vs "build:vite" and the Dockerfile FRONTEND_BUILD_CMD arg). This exists so
// the frontend can migrate off the unmaintained CRA toolchain when validated.
//
// Two CRA-compatibility details:
//   * JSX lives in .js files (not just .jsx), which Vite/esbuild won't parse by
//     default -- the esbuild loader override below fixes that for src/.
//   * The app reads process.env.REACT_APP_* (CRA convention); those are `define`d
//     here so the same source works under Vite without touching every reference.
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig({
  plugins: [react({ include: /\.(js|jsx)$/ })],  // CRA puts JSX in .js files -- Babel-transform those too
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  define: {
    "process.env.REACT_APP_BACKEND_URL": JSON.stringify(process.env.REACT_APP_BACKEND_URL ?? ""),
    "process.env.REACT_APP_ENABLE_GOOGLE_SIGNIN": JSON.stringify(process.env.REACT_APP_ENABLE_GOOGLE_SIGNIN ?? ""),
    "process.env.NODE_ENV": JSON.stringify(process.env.NODE_ENV ?? "production"),
  },
  esbuild: { loader: "jsx", include: /src\/.*\.jsx?$/ },
  optimizeDeps: { esbuildOptions: { loader: { ".js": "jsx" } } },
  build: { outDir: "build", chunkSizeWarningLimit: 1500 },  // outDir=build so the Dockerfile copy works for both toolchains
  server: {
    port: 3000,
    proxy: { "/api": { target: process.env.VITE_DEV_BACKEND || "http://localhost:8000", changeOrigin: true } },
  },
});

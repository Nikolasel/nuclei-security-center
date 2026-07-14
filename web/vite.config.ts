import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The SPA is served by the Go backend from web/dist (go:embed). In dev, run the
// backend in auth-disabled mode (OIDC_ISSUER unset) and Vite proxies the API to
// it; real OIDC login is exercised through the docker compose stack.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
    // false so a build never deletes the committed dist/.gitkeep (needed for
    // //go:embed all:dist on a fresh clone before the SPA has ever been built).
    // dist/ is otherwise git-ignored and rebuilt from scratch in CI/Docker, so the
    // only cost is old hashed chunks lingering locally across builds — harmless,
    // and `rm -rf web/dist` clears it if it ever matters.
    emptyOutDir: false,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
    },
  },
});

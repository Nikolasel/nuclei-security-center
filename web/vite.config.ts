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
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://localhost:8080",
      "/healthz": "http://localhost:8080",
    },
  },
});

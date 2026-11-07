import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // The ThreatLens backend runs on port 8001 (8000 is often taken by another project); the dev server forwards /api to it.
    proxy: { "/api": { target: "http://127.0.0.1:8001", changeOrigin: false } },
  },
  test: { environment: "node", include: ["src/**/*.test.ts"] },
});

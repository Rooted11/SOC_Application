import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Prefer the Ubuntu VM IP when the dev server runs on Windows,
// otherwise fall back to localhost (Ubuntu host) or explicit env overrides.
const proxyTarget =
  process.env.BACKEND_URL ||
  process.env.VITE_BACKEND_URL ||
  (process.platform === "win32" ? "http://192.168.56.101:8000" : "http://localhost:8000");

export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      "/api": {
        // Docker: "http://backend:8000" | Windows host: "http://192.168.56.101:8000" | Ubuntu host: "http://localhost:8000"
        target: proxyTarget,
        changeOrigin: true,
      },
    },
  },
});

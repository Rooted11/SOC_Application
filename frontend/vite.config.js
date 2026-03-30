import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Proxy target for the Vite dev server.
// Priority: VITE_API_BASE_URL → BACKEND_URL → VITE_BACKEND_URL → platform default
const proxyTarget =
  process.env.VITE_API_BASE_URL ||
  process.env.BACKEND_URL ||
  process.env.VITE_BACKEND_URL ||
  (process.platform === "win32" ? "http://192.168.56.102:8000" : "http://localhost:8000");

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

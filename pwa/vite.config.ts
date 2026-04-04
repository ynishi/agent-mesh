import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { VitePWA } from "vite-plugin-pwa";
import path from "node:path";

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: "autoUpdate",
      manifest: {
        name: "agent-mesh",
        short_name: "mesh",
        description: "Private mesh network for AI agents",
        start_url: ".",
        display: "standalone",
        background_color: "#1e1e2e",
        theme_color: "#1e1e2e",
        icons: [
          {
            src: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 192 192'><rect width='192' height='192' rx='32' fill='%231e1e2e'/><text x='96' y='125' text-anchor='middle' font-size='110' font-weight='bold' fill='%23cba6f7'>M</text></svg>",
            sizes: "192x192",
            type: "image/svg+xml",
          },
          {
            src: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 512 512'><rect width='512' height='512' rx='80' fill='%231e1e2e'/><text x='256' y='330' text-anchor='middle' font-size='300' font-weight='bold' fill='%23cba6f7'>M</text></svg>",
            sizes: "512x512",
            type: "image/svg+xml",
          },
        ],
      },
      workbox: {
        globPatterns: ["**/*.{js,css,html,wasm}"],
        // Skip API/relay requests — let them go straight to network.
        navigateFallbackDenylist: [/^\/relay\//, /^\/agents/, /^\/oauth\//],
      },
    }),
  ],
  resolve: {
    alias: {
      "@wasm": path.resolve(__dirname, "../crates/agent-mesh-wasm/pkg"),
    },
  },
  server: {
    proxy: {
      "/relay": "http://localhost:8080",
      "/agents": "http://localhost:8080",
      "/oauth": "http://localhost:8080",
    },
  },
});

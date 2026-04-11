import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "/dashboard/",
  plugins: [react()],
  server: {
    proxy: {
      "/admin": "http://127.0.0.1:8470",
      "/peers": "http://127.0.0.1:8470",
      "/health": "http://127.0.0.1:8470",
      "/network": "http://127.0.0.1:8470",
      "/register": "http://127.0.0.1:8470",
    },
  },
});

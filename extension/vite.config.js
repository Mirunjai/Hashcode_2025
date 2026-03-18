import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    // Output goes into dist/ — this is the folder you load into Chrome
    outDir: "dist",
    rollupOptions: {
      input: "index.html",
    },
  },
});

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    exclude: ["dist/**", "node_modules/**"],
  },
  build: {
    lib: { entry: "src/plugin.tsx", formats: ["es"], fileName: () => "plugin.js" },
    outDir: "dist-plugin",
    emptyOutDir: true,
    rollupOptions: { external: ["react", "react-dom", "react/jsx-runtime"] },
  },
});

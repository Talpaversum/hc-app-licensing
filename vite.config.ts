import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  build: {
    lib: { entry: "src/plugin.tsx", formats: ["es"], fileName: () => "plugin.js" },
    outDir: "dist-plugin",
    emptyOutDir: true,
    rollupOptions: { external: ["react", "react-dom", "react/jsx-runtime"] },
  },
});

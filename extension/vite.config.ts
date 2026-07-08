import { copyFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vite";

const outDir = resolve(__dirname, "dist");

export default defineConfig({
  base: "./",
  build: {
    outDir,
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "popup.html"),
        options: resolve(__dirname, "options.html"),
        background: resolve(__dirname, "background.ts"),
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name].js",
        assetFileNames: "[name][extname]",
      },
    },
  },
  plugins: [
    {
      name: "copy-manifest",
      closeBundle() {
        mkdirSync(outDir, { recursive: true });
        copyFileSync(
          resolve(__dirname, "manifest.json"),
          resolve(outDir, "manifest.json"),
        );
        copyFileSync(
          resolve(__dirname, "logo.png"),
          resolve(outDir, "logo.png"),
        );
      },
    },
  ],
});

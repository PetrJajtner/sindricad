// Dev-server half of the browser export (see src/io/files.ts, "Browser export").
// The sidecar writes exports into EXPORT_DIR on this machine; these two
// endpoints tell the page where that is and hand finished files back.
//
//   GET /__sindri/export-dir        -> { "dir": EXPORT_DIR }
//   GET /__sindri/download?name=X   -> EXPORT_DIR/X as an attachment
//
// Single shared folder: fine for testing, NOT for several students. The
// gateway will give each session its own folder.
import type { Plugin } from "vite";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const EXPORT_DIR = path.resolve(
  process.env.SINDRI_EXPORT_DIR || path.join(os.tmpdir(), "sindri-exports"),
);

export function sindriWeb(): Plugin {
  return {
    name: "sindri-web",
    configureServer(server) {
      fs.mkdirSync(EXPORT_DIR, { recursive: true });

      server.middlewares.use("/__sindri/export-dir", (_req, res) => {
        res.setHeader("Content-Type", "application/json");
        res.setHeader("Cache-Control", "no-store");
        res.end(JSON.stringify({ dir: EXPORT_DIR }));
      });

      server.middlewares.use("/__sindri/download", (req, res) => {
        const q = new URL(req.url ?? "/", "http://local").searchParams;
        // basename() strips any directory part, so "../x" cannot leave the folder.
        const name = path.basename(q.get("name") ?? "");
        const file = path.join(EXPORT_DIR, name);
        let ok = false;
        try {
          ok = name !== "" && fs.statSync(file).isFile();
        } catch {
          ok = false;
        }
        if (!ok) {
          res.statusCode = 404;
          res.end("not found");
          return;
        }
        const ascii = name.replace(/[^\x20-\x7e]/g, "_").replace(/["\\]/g, "_");
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader(
          "Content-Disposition",
          `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`,
        );
        res.setHeader("Cache-Control", "no-store");
        fs.createReadStream(file).pipe(res);
      });

      server.config.logger.info(`  sindri-web: exports go to ${EXPORT_DIR}`);
    },
  };
}

#!/usr/bin/env node
// Build the operator console: bundle the ES module sources in src/console-js/
// into the single committed file src/console/app.js that the API server mounts
// at /console. The bundle is committed so production deploys serve it without
// needing node at runtime; this script is what keeps it in sync with sources.
//
// Deterministic: esbuild output for identical sources is byte-identical, so
// `node scripts/build-console.mjs` after editing sources either reproduces the
// committed bundle or produces a diff that must be committed with the change.
// Uses esbuild's IIFE format (classic script, no type=module needed) so
// index.html and the CSP contract stay unchanged.

import { build } from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const entry = path.join(root, "src", "console-js", "app.js");
const outfile = path.join(root, "src", "console", "app.js");

await build({
  entryPoints: [entry],
  outfile,
  bundle: true,
  format: "iife",
  // Keep it readable and source-matching: no minification, no mangling. The
  // console's strict CSP forbids eval; esbuild never emits eval here.
  minify: false,
  legalComments: "inline",
  logLevel: "warning",
  sourcemap: false,
});

console.log(`console bundle written: ${outfile}`);

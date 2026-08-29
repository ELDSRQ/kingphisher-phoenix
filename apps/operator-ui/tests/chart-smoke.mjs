// ad-hoc smoke harness for the ledger trend SVG chart (not part of the suite).
// Loads el/svg/ledgerTrendChart from app.js with a minimal DOM shim and
// verifies the produced SVG tree is structurally correct and CSP-clean.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appPath = path.join(__dirname, "..", "src", "console", "app.js");
const lines = readFileSync(appPath, "utf8").split("\n");

// Extract lines 194..302 (el, SVG_NS, svg, ledgerTrendChart). Indices are 0-based
// so the target line "function el(" (1-based 194) is at index 193.
const source = lines.slice(193, 302).join("\n");

// ---- minimal DOM shim ----
function makeNode(tag, ns) {
  return {
    tagName: tag, attrs: {}, children: [], textContent: "", className: "",
    setAttribute(k, v) { this.attrs[k] = v; },
    getAttribute(k) { return this.attrs[k]; },
    appendChild(c) { this.children.push(typeof c === "string" ? { text: c } : c); return c; },
    addEventListener() {},
  };
}
const document = {
  createElement: (tag) => makeNode(tag, false),
  createElementNS: (ns, tag) => makeNode(tag, ns),
  createTextNode: (text) => ({ text }),
};

const fn = new Function("document", `
  ${source}
  return { el, svg, ledgerTrendChart };
`);
const shimEl = (tag, attrs, children) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children || []) node.appendChild(c);
  return node;
};
const { svg, ledgerTrendChart } = fn(document, shimEl);

const report = {
  generated_at: "2026-08-01T00:00:00Z",
  buckets: [
    { month: "2026-01", counts: [ { name: "confirmed_interaction", value: 2 }, { name: "clicked", value: 5 }, { name: "no_click", value: 20 } ] },
    { month: "2026-02", counts: [ { name: "confirmed_interaction", value: 4 }, { name: "clicked", value: 7 }, { name: "no_click", value: 15 } ] },
  ],
};

const figure = ledgerTrendChart(report);
assert.equal(figure.tagName, "figure", "chart wraps in <figure>");

let svgNode = null;
(function findSvg(n) {
  if (!n) return;
  if (n.tagName === "svg") { svgNode = n; return; }
  (n.children || []).forEach(findSvg);
})(figure);

assert.ok(svgNode, "an <svg> element is produced");
assert.equal(svgNode.getAttribute("role"), "img", "chart is an image for assistive tech");
assert.ok(svgNode.getAttribute("aria-label"), "chart has an accessible aria-label");
assert.equal(svgNode.getAttribute("width"), "720");
assert.equal(svgNode.getAttribute("height"), "240");

let rectCount = 0, titleCount = 0, textCount = 0;
(function walk(n) {
  if (!n) return;
  if (n.tagName === "rect") rectCount += 1;
  if (n.tagName === "title") titleCount += 1;
  if (n.tagName === "text") textCount += 1;
  (n.children || []).forEach(walk);
})(svgNode);

// 2 months x 3 series = 6 bars, each with a title; plus one chart-level <title>.
assert.equal(rectCount, 6, `expected 6 bars, got ${rectCount}`);
assert.equal(titleCount, 7, `expected 6 bar titles + 1 chart title, got ${titleCount}`);
assert.ok(textCount >= 5, `expected axis text, got ${textCount}`);

// No inline style attributes anywhere in the SVG (CSP clean).
(function walkForStyle(n) {
  if (!n || !n.tagName) return;
  assert.equal(n.getAttribute("style"), undefined, `inline style attribute forbidden on <${n.tagName}>`);
  (n.children || []).forEach(walkForStyle);
})(svgNode);

// Legend present.
let legendItems = 0;
(function walkLegend(n) {
  if (!n || !n.tagName) return;
  if (n.className === "chart-legend-item") legendItems += 1;
  (n.children || []).forEach(walkLegend);
})(figure);
assert.equal(legendItems, 3, `expected 3 legend items, got ${legendItems}`);

console.log("chart-smoke OK: figure+svg, 6 bars, 6 titles, axis text, legend, CSP-clean");
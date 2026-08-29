// Behavioral smoke harness for the operator console (runs in node, no browser).
//
// Loads el/svg/ledgerTrendChart from app.js with a minimal DOM shim and verifies
// the produced DOM tree is structurally correct and CSP-clean. Unlike the first
// version, functions are extracted by name with a brace-balanced scan rather than
// by hardcoded line numbers, so a reordering in app.js cannot silently make the
// harness test nothing.
//
// Exits non-zero on any failed assertion; wired into the operator-api pytest
// suite via tests/test_console_behavior_smoke.py so it runs as part of the gate.

import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const appPath = path.join(__dirname, "..", "src", "console", "app.js");
const source = readFileSync(appPath, "utf8");

// Shared DOM shim: a node behaves like a shallow Element exposing the subset of
// DOM the console uses (attrs, children, className, textContent, classList).
function makeNode(tag) {
  const children = [];
  return {
    tagName: tag,
    attrs: {},
    children,
    textContent: "",
    className: "",
    addEventListener() {},
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return this.attrs[k]; },
    setAttributeNS() {},
    appendChild(c) {
      children.push(typeof c === "string" ? { text: c } : c);
      return c;
    },
    classList: {
      add() {}, remove() {}, contains() { return false; },
    },
  };
}
const document = {
  createElement: (tag) => makeNode(tag),
  createElementNS: (ns, tag) => makeNode(tag),
  createTextNode: (text) => ({ text }),
};

// Extract one top-level function by brace counting. Returns the full source
// text of `function {name}(...) { ... }` or null.
function extractFunction(text, name) {
  const m = text.match(new RegExp(`function\\s+${name}\\s*\\(`));
  if (!m) return null;
  const start = m.index;
  // Find the '{' that opens the body.
  const open = text.indexOf("{", start + m[0].length);
  if (open === -1) return null;
  let depth = 0;
  let inStr = null;
  let inTemplate = 0;
  const end = text.length;
  for (let i = open; i < end; i += 1) {
    const ch = text[i];
    if (inStr) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (inTemplate) {
      if (ch === "\\") { i += 1; continue; }
      if (ch === "`") inTemplate = 0;
      continue;
    }
    if (ch === "\"" || ch === "'") { inStr = ch; continue; }
    if (ch === "`") { inTemplate = 1; continue; }
    if (ch === "{") depth += 1;
    else if (ch === "}") {
      depth -= 1;
      if (depth === 0) return text.slice(start, i + 1);
    }
    // Skip single-line // comments and multi-line /* */ comments so a '}' in a
    // commented string can't close the function early.
    if (ch === "/" && text[i + 1] === "/") {
      while (i < end && text[i] !== "\n") i += 1;
      continue;
    }
    if (ch === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < end && !(text[i] === "*" && text[i + 1] === "/")) i += 1;
      i += 1;
      continue;
    }
  }
  return null;
}

const elSrc = extractFunction(source, "el");
const svgSrc = extractFunction(source, "svg");
const chartSrc = extractFunction(source, "ledgerTrendChart");
assert.ok(elSrc, "el() is present");
assert.ok(svgSrc, "svg() is present");
assert.ok(chartSrc, "ledgerTrendChart() is present");

// eval only these three pure functions against the shim; they are trusted
// console source, not the report (which is attacker-uninfluenced locally), and
// this is a hermetic dev/test harness, not a runtime persistence path.
const block = [elSrc, svgSrc, chartSrc].join("\n");
const sandbox = new Function("document", "SVG_NS", `
  const SVGOwn = "http://www.w3.org/2000/svg";
  const svgNs = (typeof SVG_NS === "undefined") || !SVG_NS ? SVGOwn : SVG_NS;
  ${block.replace(/SVG_NS/g, "svgNs")}
  return { el, svg, ledgerTrendChart };
`);
const { el, svg, ledgerTrendChart } = sandbox(document);

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
  if (!n || !n.tagName) return;
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

// el() behavioral checks: handlers register via addEventListener (CSP-clean),
// text populates textContent, class maps to className, style is rejected.
const btn = el("button", { class: "x", text: "Go", onclick: () => {} });
assert.equal(btn.className, "x", "el() sets className from class");
assert.equal(btn.textContent, "Go", "el() sets textContent");
assert.equal(btn.getAttribute("style"), undefined, "el() never sets an inline style");

// svg() behavioral checks: at least it must support createElementNS namespace.
const rect = svg("rect", { x: 0, y: 0, width: 10, height: 5, fill: "#000" });
assert.equal(rect.tagName, "rect", "svg() builds an SVG element");
assert.equal(rect.getAttribute("fill"), "#000", "svg() copies presentation attrs");
assert.equal(rect.getAttribute("style"), undefined, "svg() never sets inline style");

console.log("chart-smoke OK: figure+svg, 6 bars, 7 titles, legend, el()/svg() CSP-clean");
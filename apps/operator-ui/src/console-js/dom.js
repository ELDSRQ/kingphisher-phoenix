// DOM/SVG primitives shared by the operator console. Pure helpers: they only
// touch the DOM and SVG namespace, never application state. Extracted from the
// former single-file app.js so the console is composed from ES modules and
// bundled by esbuild; the committed bundle is what the server serves.
//
// CSP contract: el() routes on* keys to addEventListener (never inline handler
// attributes) and never sets an inline style attribute; svg() only sets
// presentation attributes. Keep it that way — the console's script-src 'self'
// and style-src 'self' policy depends on it.

export function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children || []) {
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

export const SVG_NS = "http://www.w3.org/2000/svg";

export function svg(tag, attrs, children) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    // SVG presentation attributes (x, y, width, fill, …) are not governed by
    // the console's CSP style-src; only an inline style="" attribute would
    // be. We must never set `style` here.
    node.setAttribute(k, String(v));
  }
  for (const c of children || []) {
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

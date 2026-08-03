/* Kingphisher-Phoenix Operator Console — browser GUI, no CLI required. */
"use strict";

const API = "/api/v1";

const TOKEN_KEY = "kp_console_token";

function token() { return localStorage.getItem(TOKEN_KEY) || ""; }
function setToken(t) { localStorage.setItem(TOKEN_KEY, t); }
function clearToken() { localStorage.removeItem(TOKEN_KEY); }

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const resp = await fetch(`${API}${path}`, { ...options, headers });
  if (resp.status === 401 && path !== "/console/session") {
    clearToken();
    render();
    throw new Error("Session expired");
  }
  const text = await resp.text();
  let body;
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  if (!resp.ok) {
    const detail = body && (body.detail || body.detail_text || body.message);
    throw new Error(detail || `${resp.status} ${resp.statusText}`);
  }
  return body;
}

/* ---------- state ---------- */
let configCache = null;
const views = {};

function toast(message, type = "") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function el(tag, attrs, children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
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

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

/* ---------- login ---------- */
views.login = (root) => {
  const err = el("div", { class: "login-error" });
  const password = el("input", { type: "password", placeholder: "Console password" });
  password.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  const submit = async () => {
    err.textContent = "";
    try {
      const data = await api("/console/session", {
        method: "POST",
        body: JSON.stringify({ password: password.value }),
      });
      setToken(data.token);
      toast("Signed in", "success");
      render();
    } catch (e) { err.textContent = e.message; }
  };
  root.appendChild(el("div", { class: "login-wrap" }, [
    el("div", { class: "login-card" }, [
      el("h1", { text: "Kingphisher-Phoenix" }),
      el("p", { text: "Operator console" }),
      el("label", { text: "Password" }),
      password,
      err,
      el("button", { class: "btn primary", type: "button", onclick: submit, text: "Sign in" }),
    ]),
  ]));
};

/* ---------- shell ---------- */
const NAV = [
  ["dashboard", "Dashboard"],
  ["campaigns", "Campaigns"],
  ["recipients", "Recipients"],
  ["sources", "Sources"],
  ["patterns", "Patterns"],
  ["audit", "Audit"],
  ["settings", "Settings"],
];

function shell() {
  const active = NAV.find(([id]) => id === (location.hash.slice(1) || "dashboard"))?.[0] || "dashboard";
  const nav = el("nav");
  for (const [id, label] of NAV) {
    nav.appendChild(el("button", {
      class: id === active ? "active" : "",
      text: label,
      onclick: () => { location.hash = id; },
    }));
  }
  const content = el("div", { class: "content" });
  const root = el("div", { class: "shell" }, [
    el("aside", { class: "sidebar" }, [
      el("div", { class: "brand" }, [el("span", { text: "Kingphisher" }), el("small", { text: "Operator console" })]),
      nav,
      el("div", { class: "footer" }, [
        el("div", { text: "Signed in as console-operator" }),
        el("button", { text: "Sign out", onclick: () => { clearToken(); render(); } }),
      ]),
    ]),
    content,
  ]);
  document.getElementById("app").replaceChildren(root);
  views[active](content);
}

/* ---------- shared UI helpers ---------- */
function statusPills(state) {
  const row = el("div", { class: "status-row" });
  const defs = [
    ["operator-api", state.operator_api],
    ["tracking-api", state.tracking_api],
    ["postgres", state.postgres],
    ["redis", state.redis],
  ];
  for (const [name, ok] of defs) {
    row.appendChild(el("span", { class: `pill ${ok ? "ok" : "down"}`, text: `${name}: ${ok ? "up" : "down"}` }));
  }
  return row;
}

/* ---------- dashboard ---------- */
views.dashboard = async (root) => {
  root.appendChild(el("h2", { text: "Dashboard" }));
  root.appendChild(el("p", { class: "sub", text: "System health and recent campaign activity." }));
  let status, campaigns, audit;
  try {
    [status, campaigns, audit] = await Promise.all([
      api("/console/status"), api("/campaigns"), api("/audit/verify"),
    ]);
  } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` }));
    return;
  }
  root.appendChild(statusPills(status));
  const workerNames = Object.entries(status.workers || {});
  const workerRow = el("div", { class: "status-row" });
  for (const [name, ok] of workerNames) {
    workerRow.appendChild(el("span", { class: `pill ${ok ? "ok" : "down"}`, text: `worker ${name}: ${ok ? "running" : "stopped"}` }));
  }
  if (workerNames.length) root.appendChild(workerRow);

  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Audit chain" }),
    el("p", { text: audit && audit.ok ? "Chain integrity verified." : `Chain problems: ${JSON.stringify(audit && audit.problems)}` }),
  ]));

  const table = el("table", {}, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Title" }), el("th", { text: "State" }), el("th", { text: "Start" }), el("th", { text: "End" }),
    ])]),
    el("tbody", {}, campaigns.length ? campaigns.map((c) => el("tr", {}, [
      el("td", { text: c.title }),
      el("td", { text: c.state }),
      el("td", { class: "mono", text: String(c.schedule_start).slice(0, 16) }),
      el("td", { class: "mono", text: String(c.schedule_end).slice(0, 16) }),
    ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 4, text: "No campaigns yet." })])]),
  ]);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Campaigns" }), table]));
};

/* ---------- campaigns ---------- */
views.campaigns = async (root) => {
  root.appendChild(el("h2", { text: "Campaigns" }));
  root.appendChild(el("p", { class: "sub", text: "Create, approve, schedule and manage campaigns." }));

  let campaigns;
  try { campaigns = await api("/campaigns"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }

  const [patterns, templates] = await Promise.all([
    api("/patterns").catch(() => []),
    api("/templates").catch(() => []),
  ]);

  const form = el("fieldset", {}, [
    el("legend", { text: "New campaign" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [
        el("label", { text: "Title" }), el("input", { id: "c-title" }),
        el("label", { text: "Sender mailbox" }), el("input", { id: "c-sender", value: "security-drills@example.com" }),
        el("label", { text: "Training domain" }), el("input", { id: "c-tdomain", value: "training.local" }),
        el("label", { text: "Max recipients" }), el("input", { id: "c-max", type: "number", value: "1000" }),
      ]),
      el("div", {}, [
        el("label", { text: "Pattern" }),
        el("select", { id: "c-pattern" }, patterns.map((p) => el("option", { value: p.campaign_pattern_id, text: `${p.lure_category} (${p.approval_state})` }))),
        el("label", { text: "Template version" }),
        el("select", { id: "c-template" }, templates.map((t) => el("option", { value: t.template_version_id, text: `${t.version} ${t.subject}` }))),
        el("label", { text: "Start" }), el("input", { id: "c-start", type: "datetime-local" }),
        el("label", { text: "End" }), el("input", { id: "c-end", type: "datetime-local" }),
      ]),
    ]),
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Create campaign", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          await api("/campaigns", { method: "POST", body: JSON.stringify({
            pattern_id: document.getElementById("c-pattern").value,
            title: document.getElementById("c-title").value,
            sender_mailbox: document.getElementById("c-sender").value,
            training_domain: document.getElementById("c-tdomain").value,
            schedule_start: document.getElementById("c-start").value,
            schedule_end: document.getElementById("c-end").value,
            max_recipients: Number(document.getElementById("c-max").value),
            template_version_id: document.getElementById("c-template").value,
          }) });
          toast("Campaign created", "success");
          location.reload();
        } catch (e) { toast(e.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ]),
  ]);

  const list = el("table", {}, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Title" }), el("th", { text: "State" }), el("th", { text: "Actions" }),
    ])]),
    el("tbody", {}, campaigns.map((c) => el("tr", {}, [
      el("td", { text: c.title }),
      el("td", { text: c.state }),
      el("td", {}, (() => {
        const actions = [];
        if (c.state === "draft") actions.push(el("button", { class: "btn small", text: "Submit", onclick: act(`/campaigns/${c.campaign_id}/submit`, "Submitted") }));
        if (c.state === "pending_approval") actions.push(el("button", { class: "btn small", text: "Approve", onclick: act(`/campaigns/${c.campaign_id}/approvals/security`, "Approved") }));
        if (c.state === "approved") actions.push(el("button", { class: "btn small primary", text: "Schedule", onclick: act(`/campaigns/${c.campaign_id}/schedule`, "Scheduled") }));
        if (c.state === "scheduled") actions.push(el("button", { class: "btn small", text: "Test send", onclick: act(`/campaigns/${c.campaign_id}/test-send`, "Test send queued") }));
        if (["scheduled", "approved"].includes(c.state)) actions.push(el("button", { class: "btn small danger", text: "Recall", onclick: act(`/campaigns/${c.campaign_id}/recall`, "Recall initiated") }));
        return actions;
      })()),
    ]))),
  ]);

  root.appendChild(form);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "All campaigns" }), list]));

  function act(path, successMsg) {
    return async (e) => {
      const btn = e.target; btn.disabled = true;
      try { await api(path, { method: "POST" }); toast(successMsg, "success"); location.reload(); }
      catch (err) { toast(err.message, "error"); }
      finally { btn.disabled = false; }
    };
  }
};

/* ---------- recipients ---------- */
views.recipients = async (root) => {
  root.appendChild(el("h2", { text: "Recipients" }));
  root.appendChild(el("p", { class: "sub", text: "Import and review training recipients." }));
  let recipients;
  try { recipients = await api("/recipients"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Import CSV" }),
    el("label", { text: "CSV text (mailbox, name, department)" }),
    el("textarea", { id: "r-csv", placeholder: "user@example.com, Jane Doe, Engineering" }),
    el("label", { text: "Default department" }),
    el("input", { id: "r-dept", value: "Engineering" }),
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Import", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          const res = await api("/recipients/import", { method: "POST", body: JSON.stringify({
            csv_text: document.getElementById("r-csv").value,
            department: document.getElementById("r-dept").value,
          }) });
          toast(`Imported ${res.created}, skipped ${res.skipped}`, "success");
          location.reload();
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ]),
  ]));
  const table = el("table", {}, [
    el("thead", {}, [el("tr", {}, [el("th", { text: "Department" }), el("th", { text: "Status" })])]),
    el("tbody", {}, recipients.length ? recipients.map((r) => el("tr", {}, [
      el("td", { text: r.department }), el("td", { text: r.status }),
    ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 2, text: "No recipients." })])]),
  ]);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Recipients" }), table]));
};

/* ---------- sources ---------- */
views.sources = async (root) => {
  root.appendChild(el("h2", { text: "Sources" }));
  root.appendChild(el("p", { class: "sub", text: "Register intelligence sources." }));
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "New source" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [
        el("label", { text: "Name" }), el("input", { id: "s-name" }),
        el("label", { text: "Base domain" }), el("input", { id: "s-domain", value: "example.com" }),
      ]),
      el("div", {}, [
        el("label", { text: "Source type" }),
        el("select", { id: "s-type" }, ["rss", "feed", "api"].map((t) => el("option", { value: t, text: t }))),
      ]),
    ]),
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Create source", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          await api("/sources", { method: "POST", body: JSON.stringify({
            name: document.getElementById("s-name").value,
            source_type: document.getElementById("s-type").value,
            base_domain: document.getElementById("s-domain").value,
          }) });
          toast("Source created", "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ]),
  ]));
};

/* ---------- patterns ---------- */
views.patterns = async (root) => {
  root.appendChild(el("h2", { text: "Patterns" }));
  root.appendChild(el("p", { class: "sub", text: "Approved campaign patterns." }));
  let patterns;
  try { patterns = await api("/patterns"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  const rows = patterns.map((p) => el("tr", {}, [
    el("td", { text: p.lure_category }),
    el("td", { text: p.approval_state }),
    el("td", {}, p.approval_state !== "approved" ? [
      el("button", { class: "btn small primary", text: "Approve", onclick: async (e) => {
        e.target.disabled = true;
        try { await api(`/patterns/${p.campaign_pattern_id}/approve`, { method: "POST" }); toast("Pattern approved", "success"); location.reload(); }
        catch (err) { toast(err.message, "error"); }
      } }),
    ] : []),
  ]));
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Campaign patterns" }), el("table", {}, [
    el("thead", {}, [el("tr", {}, [el("th", { text: "Lure category" }), el("th", { text: "State" }), el("th", { text: "Actions" })])]),
    el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", { class: "empty", colspan: 3, text: "No patterns." })])]),
  ])]));
};

/* ---------- audit ---------- */
views.audit = async (root) => {
  root.appendChild(el("h2", { text: "Audit" }));
  root.appendChild(el("p", { class: "sub", text: "Hash-chained append-only event log." }));
  root.appendChild(el("div", { class: "btn-row" }, [
    el("button", { class: "btn", text: "Verify chain", onclick: async (e) => {
      e.target.disabled = true;
      try {
        const res = await api("/audit/verify", { method: "POST" });
        toast(res.ok ? "Chain OK" : `Problems: ${JSON.stringify(res.problems)}`, res.ok ? "success" : "error");
      } catch (err) { toast(err.message, "error"); }
      finally { e.target.disabled = false; }
    } }),
    el("button", { class: "btn danger", text: "Engage kill switch", onclick: async (e) => {
      if (!confirm("Engage kill switch? This cancels queued deliveries and revokes tracking tokens.")) return;
      e.target.disabled = true;
      try {
        const res = await api("/kill-switch", { method: "POST" });
        toast(`Kill switch engaged: ${res.cancelled} cancelled, ${res.tokens_revoked} tokens revoked`, "success");
      } catch (err) { toast(err.message, "error"); }
      finally { e.target.disabled = false; }
    } }),
  ]));
  let events;
  try { events = await api("/audit"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Recent events" }), el("table", {}, [
    el("thead", {}, [el("tr", {}, [el("th", { text: "Time" }), el("th", { text: "Actor" }), el("th", { text: "Action" }), el("th", { text: "Object" })])]),
    el("tbody", {}, events.length ? events.map((ev) => el("tr", {}, [
      el("td", { class: "mono", text: String(ev.occurred_at).slice(0, 19) }),
      el("td", { text: ev.actor }),
      el("td", { text: ev.action }),
      el("td", { class: "mono", text: ev.object_id }),
    ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 4, text: "No audit events yet." })])]),
  ])]));
};

/* ---------- settings ---------- */
views.settings = async (root) => {
  root.appendChild(el("h2", { text: "Settings" }));
  root.appendChild(el("p", { class: "sub", text: "GUI configuration for the local stack. Secrets are masked." }));

  let cfg;
  try { cfg = await api("/console/config"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  configCache = cfg;

  const inputs = {};
  const container = el("div", { class: "form-grid" });
  for (const [key, value] of Object.entries(cfg.values)) {
    const wrap = el("div", {}, [el("label", { text: key })]);
    const input = el("input", { id: `cfg-${key}`, value });
    if (cfg.masked[key]) {
      input.type = "password";
      input.placeholder = "set to change (masked)";
    }
    inputs[key] = input;
    wrap.appendChild(input);
    container.appendChild(wrap);
  }
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Configuration (.env)" }),
    container,
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Save changes", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        const values = {};
        for (const [key, input] of Object.entries(inputs)) values[key] = input.value;
        try {
          const res = await api("/console/config", { method: "PUT", body: JSON.stringify({ values }) });
          toast(`Saved. Changed: ${res.changed.length ? res.changed.join(", ") : "none"}`, "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
      el("button", { class: "btn", text: "Reload from disk", onclick: () => { location.reload(); } }),
      el("button", { class: "btn", text: "Restart services", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          await api("/console/restart", { method: "POST" });
          toast("Restart requested. Services will bounce momentarily.", "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
      el("button", { class: "btn danger", text: "Stop services", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          await api("/console/stop", { method: "POST" });
          toast("Stop requested. The stack will shut down.", "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ])),
  ]));

  let status;
  try { status = await api("/console/status"); } catch { status = null; }
  if (status) {
    root.appendChild(el("div", { class: "card" }, [
      el("h3", { text: "Service status" }),
      statusPills(status),
      el("p", { text: "Note: configuration changes apply after services are restarted by the launcher supervisor." }),
    ]));
  }
};

/* ---------- boot ---------- */
function render() {
  if (!token()) { views.login(document.getElementById("app")); return; }
  shell();
}

window.addEventListener("hashchange", render);
render();

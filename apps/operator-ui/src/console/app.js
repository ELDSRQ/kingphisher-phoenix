/* Kingphisher-Phoenix Operator Console — browser GUI, no CLI required. */
"use strict";

const API = "/api/v1";

const TOKEN_KEY = "kp_console_token";
const SESSION_KEY = "kp_console_session";

/* Session-scoped, not persisted to disk: the admin JWT must not survive the
   tab (MED-07 / WS-15). */
function token() { return sessionStorage.getItem(TOKEN_KEY) || ""; }
function setToken(t) { sessionStorage.setItem(TOKEN_KEY, t); }
function sessionInfo() {
  try { return JSON.parse(sessionStorage.getItem(SESSION_KEY) || "null"); } catch { return null; }
}
function setSessionInfo(info) { sessionStorage.setItem(SESSION_KEY, JSON.stringify(info)); }
function clearToken() {
  sessionStorage.removeItem(TOKEN_KEY);
  sessionStorage.removeItem(SESSION_KEY);
}

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
let onboardingChecked = false;
const views = {};

function toast(message, type = "") {
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.setAttribute("role", type === "error" ? "alert" : "status");
  el.setAttribute("aria-live", type === "error" ? "assertive" : "polite");
  el.textContent = message;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 5000);
}

function el(tag, attrs, children) {
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

/* ---------- dialogs ----------
   Real <dialog> modals instead of prompt()/confirm(): those cannot be styled,
   cannot show more than one field, cannot explain a rule, and are suppressed
   entirely by some browsers. Everything here is textContent only — no
   innerHTML anywhere in this console, ever. */

function openDialog(node) {
  document.body.appendChild(node);
  node.addEventListener("close", () => node.remove());
  node.showModal();
  const focusable = node.querySelector("input, select, textarea, button.primary, button");
  if (focusable) focusable.focus();
  return node;
}

function dialogShell(title, description) {
  const dlg = el("dialog", { class: "modal" });
  const form = el("form", { method: "dialog", class: "modal-form" });
  form.appendChild(el("h3", { class: "modal-title", text: title }));
  if (description) form.appendChild(el("p", { class: "modal-desc", text: description }));
  dlg.appendChild(form);
  return { dlg, form };
}

function confirmDialog({ title, message, detail, confirmLabel = "Confirm", danger = false }) {
  return new Promise((resolve) => {
    const { dlg, form } = dialogShell(title, message);
    if (detail) {
      const list = el("dl", { class: "modal-detail" });
      for (const [k, v] of Object.entries(detail)) {
        list.appendChild(el("dt", { text: k }));
        list.appendChild(el("dd", { text: String(v) }));
      }
      form.appendChild(list);
    }
    let decided = false;
    const finish = (value) => { decided = true; resolve(value); dlg.close(); };
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Cancel", onclick: () => finish(false) }),
      el("button", { class: `btn primary${danger ? " danger" : ""}`, type: "button", text: confirmLabel, onclick: () => finish(true) }),
    ]));
    dlg.addEventListener("close", () => { if (!decided) resolve(false); });
    openDialog(dlg);
  });
}

/* fields: [{ name, label, type, value, options, required, help, placeholder }] */
function promptDialog({ title, description, fields, submitLabel = "Save" }) {
  return new Promise((resolve) => {
    const { dlg, form } = dialogShell(title, description);
    const inputs = {};
    const errorLine = el("div", { class: "modal-error", role: "alert" });
    for (const field of fields) {
      const id = `dlg-${field.name}`;
      form.appendChild(el("label", { for: id, text: field.label }));
      let input;
      if (field.type === "select") {
        input = el("select", { id, name: field.name });
        for (const opt of field.options || []) {
          input.appendChild(el("option", { value: opt.value, text: opt.label, selected: opt.value === field.value }));
        }
      } else if (field.type === "textarea") {
        input = el("textarea", { id, name: field.name, rows: "3", placeholder: field.placeholder || "" });
        input.value = field.value || "";
      } else {
        input = el("input", { id, name: field.name, type: field.type || "text", placeholder: field.placeholder || "" });
        input.value = field.value || "";
      }
      inputs[field.name] = input;
      form.appendChild(input);
      if (field.help) form.appendChild(el("p", { class: "modal-help", text: field.help }));
    }
    form.appendChild(errorLine);
    let decided = false;
    const cancel = () => { decided = true; resolve(null); dlg.close(); };
    const submit = () => {
      const values = {};
      for (const field of fields) {
        const value = String(inputs[field.name].value || "").trim();
        if (field.required && !value) {
          errorLine.textContent = `${field.label} is required.`;
          inputs[field.name].focus();
          return;
        }
        values[field.name] = value;
      }
      decided = true; resolve(values); dlg.close();
    };
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Cancel", onclick: cancel }),
      el("button", { class: "btn primary", type: "button", text: submitLabel, onclick: submit }),
    ]));
    dlg.addEventListener("close", () => { if (!decided) resolve(null); });
    openDialog(dlg);
  });
}

/* A value shown exactly once (a signing secret). prompt() was being used for
   this, which is not selectable on every browser and looks like an input. */
function showCopyable({ title, description, value }) {
  const { dlg, form } = dialogShell(title, description);
  const box = el("textarea", { class: "modal-copyable", rows: "3", readonly: "readonly" });
  box.value = value;
  form.appendChild(box);
  const status = el("p", { class: "modal-help", "aria-live": "polite" });
  form.appendChild(status);
  form.appendChild(el("div", { class: "modal-actions" }, [
    el("button", { class: "btn", type: "button", text: "Copy", onclick: async () => {
      box.select();
      try {
        await navigator.clipboard.writeText(value);
        status.textContent = "Copied to clipboard.";
      } catch {
        status.textContent = "Copy failed — the value is selected, press Ctrl/Cmd+C.";
      }
    } }),
    el("button", { class: "btn primary", type: "button", text: "I have saved it", onclick: () => dlg.close() }),
  ]));
  openDialog(dlg);
}

/* ---------- campaign report ----------
   The funnel used to be a three-number toast that vanished after five seconds.
   Percentages are all relative to DELIVERED, not to the recipient count: a
   message that never left the building cannot be opened, and dividing by
   recipients would quietly understate every rate. */

function pct(part, whole) {
  if (!whole) return "—";
  return `${((part / whole) * 100).toFixed(1)}%`;
}

const FAILURE_REASON_TEXT = {
  domain_not_allowed: "Recipient domain is not in the allowed list — policy refused the send",
  stale_queued_reconcile: "Still queued when the campaign closed; settled by the reconciler, never re-sent",
  recipient_unavailable: "Recipient record or tracking token was missing or inactive",
  send_error: "The mail transport rejected or failed the message",
  unspecified: "No reason recorded (failed before reasons were tracked)",
};

function showCampaignReport(report) {
  const { dlg, form } = dialogShell(
    report.title || "Campaign report",
    `State: ${report.state} · ${report.recipients} recipient${report.recipients === 1 ? "" : "s"}`,
  );

  const delivered = report.send_counts.delivered || 0;
  const funnel = [
    ["Delivered", delivered, report.recipients],
    ["Opened", report.event_counts.opened || 0, delivered],
    ["Clicked", report.event_counts.clicked || 0, delivered],
    // The enum member is MESSAGE_REPORTED, so the key is "message_reported";
    // reading "reported" silently rendered 0 for every campaign.
    ["Reported", report.event_counts.message_reported || 0, delivered],
    ["Training completed", report.training.completed || 0, report.training.assigned || 0],
  ];
  const funnelTable = el("table", { class: "report-table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Stage" }), el("th", { text: "Count" }), el("th", { text: "Rate" }),
    ])]),
    el("tbody", {}, funnel.map(([label, count, base]) => el("tr", {}, [
      el("td", { text: label }),
      el("td", { class: "num", text: String(count) }),
      el("td", { class: "num", text: pct(count, base) }),
    ]))),
  ]);
  form.appendChild(el("h4", { class: "modal-section", text: "Funnel" }));
  form.appendChild(funnelTable);
  form.appendChild(el("p", { class: "modal-help", text: "Open, click and report rates are a share of delivered messages. Training completion is a share of assigned training." }));

  const sendRows = Object.entries(report.send_counts).filter(([, v]) => v > 0);
  form.appendChild(el("h4", { class: "modal-section", text: "Send states" }));
  form.appendChild(el("table", { class: "report-table" }, [
    el("tbody", {}, sendRows.length ? sendRows.map(([state, count]) => el("tr", {}, [
      el("td", { text: state }), el("td", { class: "num", text: String(count) }),
    ])) : [el("tr", {}, [el("td", { colspan: "2", text: "No assignments yet." })])]),
  ]));

  const failures = Object.entries(report.failure_reasons || {});
  if (failures.length) {
    form.appendChild(el("h4", { class: "modal-section", text: "Why sends failed" }));
    form.appendChild(el("table", { class: "report-table" }, [
      el("tbody", {}, failures.map(([reason, count]) => el("tr", {}, [
        el("td", {}, [
          el("div", { text: reason }),
          el("div", { class: "modal-help", text: FAILURE_REASON_TEXT[reason] || "" }),
        ]),
        el("td", { class: "num", text: String(count) }),
      ]))),
    ]));
  }

  // Per-recipient detail is loaded on demand: it is the larger query, and most
  // of the time the aggregate answers the question.
  const perRecipient = el("div", {});
  form.appendChild(el("h4", { class: "modal-section", text: "Per recipient" }));
  form.appendChild(el("p", { class: "modal-help", text: "Shows assignment outcomes by department. Mailboxes are never returned — the platform reports on assignments, not on named individuals' behaviour." }));
  const loadBtn = el("button", { class: "btn small", type: "button", text: "Load per-recipient results", onclick: async (e) => {
    e.target.disabled = true;
    try {
      const rows = await api(`/campaigns/${report.campaign_id}/recipients`);
      perRecipient.replaceChildren(renderRecipientTable(rows));
      e.target.remove();
    } catch (err) {
      perRecipient.replaceChildren(el("p", { class: "modal-warn", text: err.message }));
      e.target.disabled = false;
    }
  } });
  form.appendChild(loadBtn);
  form.appendChild(perRecipient);

  form.appendChild(el("div", { class: "modal-actions" }, [
    el("button", { class: "btn", type: "button", text: "Download CSV", onclick: async (e) => {
      e.target.disabled = true;
      try { await downloadReportCsv(report.campaign_id); }
      catch (err) { toast(err.message, "error"); }
      finally { e.target.disabled = false; }
    } }),
    el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => dlg.close() }),
  ]));
  openDialog(dlg);
}

function renderRecipientTable(rows) {
  if (!rows.length) return el("p", { class: "modal-help", text: "No assignments for this campaign yet." });
  return el("table", { class: "report-table" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Department" }),
      el("th", { text: "Send state" }),
      el("th", { text: "Reason" }),
      el("th", { text: "Opened" }),
      el("th", { text: "Clicked" }),
      el("th", { text: "Reported" }),
    ])]),
    el("tbody", {}, rows.map((r) => el("tr", {}, [
      el("td", { text: r.department || "—" }),
      el("td", { text: r.send_state }),
      el("td", { text: r.failure_reason || "—" }),
      el("td", { class: "num", text: r.opened ? "yes" : "—" }),
      el("td", { class: "num", text: r.clicked ? "yes" : "—" }),
      el("td", { class: "num", text: r.reported ? "yes" : "—" }),
    ]))),
  ]);
}

/* The CSV route is authenticated, so a plain link would 401. Fetch with the
   bearer token and hand the browser a blob instead. */
async function downloadReportCsv(campaignId) {
  const resp = await fetch(`${API}/campaigns/${campaignId}/report.csv`, {
    headers: { Authorization: `Bearer ${token()}` },
  });
  if (!resp.ok) throw new Error(`Export failed (${resp.status})`);
  const blob = await resp.blob();
  const url = URL.createObjectURL(blob);
  const link = el("a", { href: url, download: `campaign-${campaignId}-report.csv` });
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

/* Import outcomes were previously collapsed into "Imported N, skipped M",
   which hid the rows the domain allowlist refused. An operator whose recipients
   silently vanish has no way to discover why. */
function showImportResult(res) {
  const created = res.created || 0;
  const skipped = res.skipped || 0;
  const blocked = res.blocked || 0;
  const errors = res.errors || [];
  const { dlg, form } = dialogShell("Import complete", null);

  form.appendChild(el("table", { class: "report-table" }, [
    el("tbody", {}, [
      el("tr", {}, [el("td", { text: "Imported" }), el("td", { class: "num", text: String(created) })]),
      el("tr", {}, [el("td", { text: "Already present" }), el("td", { class: "num", text: String(skipped) })]),
      el("tr", {}, [el("td", { text: "Blocked by domain policy" }), el("td", { class: "num", text: String(blocked) })]),
    ]),
  ]));

  if (blocked) {
    form.appendChild(el("p", { class: "modal-warn", text: "Blocked rows are outside the recipient domains this deployment is allowed to mail. Nothing was sent to them and no record was created." }));
  }
  if (errors.length) {
    form.appendChild(el("h4", { class: "modal-section", text: "Rows not imported" }));
    const list = el("ul", { class: "modal-errors" });
    for (const line of errors) list.appendChild(el("li", { text: line }));
    form.appendChild(list);
    form.appendChild(el("p", { class: "modal-help", text: "Only the first 20 problem rows are listed." }));
  }

  form.appendChild(el("div", { class: "modal-actions" }, [
    el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => { dlg.close(); location.reload(); } }),
  ]));
  openDialog(dlg);
}

/* Human labels for the connection-test categories returned by the API. */
const CONNECTION_LABELS = {
  auth: "Credentials rejected",
  dns: "Hostname not found",
  timeout: "No response (likely firewall)",
  refused: "Connection refused",
  tls: "TLS/STARTTLS mismatch",
  config: "Address not valid",
  http_error: "Unexpected response",
  unknown: "Connection failed",
};

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function browserTimeZone() {
  return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
}

function localDateTimeToIso(value, label) {
  if (!value) throw new Error(`${label} date and time are required`);
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) throw new Error(`${label} date and time are invalid`);
  return parsed.toISOString();
}

function formatInstant(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "Invalid date";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "long" }).format(parsed);
}

/* ---------- login ---------- */
views.login = async (root) => {
  const err = el("div", { class: "login-error" });
  const password = el("input", { id: "console-password", type: "password", placeholder: "Console password", autocomplete: "current-password" });
  password.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  const submit = async () => {
    err.textContent = "";
    try {
      const data = await api("/console/session", {
        method: "POST",
        body: JSON.stringify({ password: password.value }),
      });
      setToken(data.token);
      setSessionInfo({
        authMode: data.auth_mode,
        principalId: data.principal_id,
        approvalLimited: Boolean(data.approval_limited),
        approvalPolicy: data.approval_policy || "single-admin",
      });
      onboardingChecked = false;
      toast("Signed in", "success");
      render();
    } catch (e) {
      // A bare "429 Too Many Requests" leaves an operator stuck with no idea
      // how long to wait or where the password came from.
      const message = String(e.message || "");
      if (/429|too many|locked/i.test(message)) {
        const seconds = (message.match(/(\d+)\s*second/i) || [])[1];
        err.textContent = seconds
          ? `Too many attempts. Try again in ${seconds} seconds.`
          : "Too many attempts. Wait a few minutes before trying again.";
        hint.hidden = false;
      } else {
        err.textContent = message;
      }
    }
  };
  const hint = el("p", { class: "login-hint", hidden: true, text: "The console password is KP_CONSOLE_PASSWORD in your .env file. On Azure it is the console-password secret in Key Vault. See RUNBOOK section 2.1." });
  let authMode = "dev";
  try {
    const resp = await fetch(`${API}/console/auth-mode`);
    if (resp.ok) authMode = (await resp.json()).auth_mode;
  } catch { /* The password form remains a safe fallback display. */ }
  const loginControls = authMode === "oidc" ? [
    el("button", { class: "btn primary", type: "button", onclick: async () => {
      err.textContent = "";
      try {
        const resp = await fetch(`${API}/console/oidc/start`, { credentials: "same-origin" });
        const body = await resp.json();
        if (!resp.ok) throw new Error(body.detail || "Unable to start sign-in");
        location.assign(body.authorization_url);
      } catch (e) { err.textContent = e.message; }
    }, text: "Sign in with identity provider" }),
  ] : [
    el("label", { for: "console-password", text: "Password" }),
    password,
    el("button", { class: "btn primary", type: "button", onclick: submit, text: "Sign in" }),
  ];
  root.replaceChildren(el("div", { class: "login-wrap" }, [
    el("div", { class: "login-card" }, [
      el("h1", { text: "Kingphisher-Phoenix" }),
      el("p", { text: "Operator console" }),
      ...loginControls,
      err,
      hint,
    ]),
  ]));
};

/* ---------- shell ---------- */
const NAV = [
  ["onboarding", "Setup wizard"],
  ["azure-deployment", "Azure deployment"],
  ["help", "Help"],
  ["dashboard", "Dashboard"],
  ["campaigns", "Campaigns"],
  ["sending", "Domains & RoE"],
  ["recipients", "Recipients"],
  ["sources", "Sources"],
  ["patterns", "Patterns"],
  ["templates", "Template review"],
  ["privacy", "Privacy"],
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
  const info = sessionInfo();
  const root = el("div", { class: "shell" }, [
    el("aside", { class: "sidebar" }, [
      el("div", { class: "brand" }, [
        el("img", { src: "/console/logo.png", alt: "Kingphisher logo", class: "brand-logo" }),
        el("span", { text: "Kingphisher" }), el("small", { text: "Operator console" }),
      ]),
      nav,
      el("div", { class: "footer" }, [
        el("div", { text: info?.authMode === "dev" ? "Signed in as development operator" : "Signed in with OIDC" }),
        el("div", { id: "last-updated", class: "last-updated" }),
        el("button", { text: "Sign out", onclick: async () => {
          await fetch(`${API}/console/logout`, { method: "POST", credentials: "same-origin" });
          clearToken(); render();
        } }),
      ]),
    ]),
    content,
  ]);
  document.getElementById("app").replaceChildren(root);
  views[active](content);
  if (LIVE_VIEWS.has(active)) stampLastUpdated();
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

/* ---------- onboarding ---------- */
views.onboarding = async (root) => {
  root.appendChild(el("h2", { text: "Let’s set up Kingphisher" }));
  root.appendChild(el("p", { class: "sub", text: "A guided, plain-language setup for each service Kingphisher uses." }));

  let onboarding;
  try { onboarding = await api("/console/onboarding"); } catch (e) {
    root.appendChild(el("div", { class: "card", role: "alert", text: `Failed to load setup: ${e.message}` }));
    return;
  }

  const steps = Array.isArray(onboarding.steps) ? onboarding.steps : [];
  let current = -1;
  const savedValues = {};
  let restartNeeded = false;
  const stage = el("div", { class: "onboarding-stage" });
  root.appendChild(stage);

  const renderStep = () => {
    if (current < 0) {
      const requiredCount = steps.filter((step) => !step.optional).length;
      stage.replaceChildren(el("section", { class: "card wizard-card wizard-welcome", "aria-labelledby": "wizard-title" }, [
        el("div", { class: "eyebrow", text: "WELCOME" }),
        el("h3", { id: "wizard-title", tabindex: "-1", text: "Get connected with confidence" }),
        el("p", { text: "We’ll explain what each connection does, help you find the right values, and test it before anything is saved." }),
        el("ul", { class: "welcome-facts" }, [
          el("li", { text: `About ${Math.max(5, steps.length * 3)}–${Math.max(10, steps.length * 5)} minutes` }),
          el("li", { text: `${requiredCount} required connection${requiredCount === 1 ? "" : "s"}; optional items can be skipped` }),
          el("li", { text: "You can leave and return without losing saved connections" }),
        ]),
        el("div", { class: "notice", role: "note", text: "Have provider admin pages and credentials nearby. Passwords and API keys are hidden and are never shared with the setup assistant." }),
        el("div", { class: "btn-row" }, [
          el("button", { class: "btn primary", type: "button", text: "Start guided setup", onclick: () => { current = 0; renderStep(); } }),
          el("button", { class: "btn", type: "button", text: "Browse help first", onclick: () => { location.hash = "help"; } }),
        ]),
      ]));
      stage.querySelector("#wizard-title").focus();
      return;
    }
    const review = current === steps.length;
    const progress = el("ol", { class: "wizard-progress", "aria-label": "Setup progress" });
    steps.forEach((step, index) => {
      const item = el("li", {
        class: `${index === current ? "current" : ""} ${index < current || step.configured ? "done" : ""}`.trim(),
        "aria-current": index === current ? "step" : null,
      }, [el("span", { class: "step-number", text: index + 1 }), el("span", { text: step.title })]);
      progress.appendChild(item);
    });
    progress.appendChild(el("li", {
      class: review ? "current" : "",
      "aria-current": review ? "step" : null,
    }, [el("span", { class: "step-number", text: steps.length + 1 }), el("span", { text: "Review" })]));

    if (review) {
      const summary = el("dl", { class: "wizard-summary" });
      steps.forEach((step) => {
        const visible = (step.fields || []).filter((field) => !field.secret).map((field) => {
          const value = savedValues[step.id]?.[field.key];
          return value !== undefined && value !== "" ? `${field.label}: ${value}` : null;
        }).filter(Boolean);
        summary.appendChild(el("dt", { text: step.title }));
        summary.appendChild(el("dd", { text: visible.join(" · ") || (step.configured ? "Configured" : "No non-secret values entered") }));
      });
      const finish = el("button", { class: "btn primary", type: "button", text: "Finish setup", onclick: async () => {
        finish.disabled = true;
        try {
          await api("/console/onboarding", { method: "PUT", body: JSON.stringify({ values: {}, completed: true }) });
          onboarding.complete = true;
          toast("Setup complete", "success");
          location.hash = "dashboard";
        } catch (e) { toast(e.message, "error"); finish.disabled = false; }
      } });
      stage.replaceChildren(progress, el("section", { class: "card wizard-card", "aria-labelledby": "wizard-title" }, [
        el("h3", { id: "wizard-title", tabindex: "-1", text: "Review setup" }),
        el("p", { text: "Confirm your connections. Passwords and keys are never displayed here." }),
        summary,
        el("div", { class: "btn-row wizard-actions" }, [
          el("button", { class: "btn", type: "button", text: "Back", onclick: () => { current--; renderStep(); } }),
          ...(restartNeeded ? [el("button", { class: "btn", type: "button", text: "Restart services now", onclick: async (event) => {
            event.target.disabled = true;
            try { await api("/console/restart", { method: "POST" }); restartNeeded = false; toast("Restart requested", "success"); renderStep(); }
            catch (e) { toast(e.message, "error"); event.target.disabled = false; }
          } })] : []), finish,
        ]),
      ]));
      stage.querySelector("#wizard-title").focus();
      return;
    }

    const step = steps[current];
    if (!step) {
      stage.replaceChildren(el("div", { class: "card", text: "No setup steps are currently required." }));
      return;
    }
    const inputs = {};
    const form = el("form", { class: "wizard-form" });
    (step.fields || []).forEach((field, fieldIndex) => {
      const id = `onboarding-${current}-${fieldIndex}`;
      const inputType = field.secret ? "password" : (field.type || "text");
      const inputAttrs = {
        id, name: field.key, placeholder: field.placeholder || "",
        autocomplete: field.secret ? "new-password" : "off",
        required: field.required && !(field.secret && step.configured) ? "" : null,
        "aria-describedby": (field.help || field.explanation || field.example || field.where_to_find) ? `${id}-help` : null,
      };
      const input = field.choices?.length
        ? el("select", inputAttrs, field.choices.map((choice) => el("option", { value: choice.value, text: choice.label })))
        : el("input", { ...inputAttrs, type: inputType });
      if (!field.secret) {
        input.value = savedValues[step.id]?.[field.key] ?? field.value ?? "";
      }
      inputs[field.key] = input;
      form.appendChild(el("div", { class: "wizard-field" }, [
        el("label", { for: id }, [el("span", { text: field.label }), el("span", { class: `requirement ${field.required ? "required" : "optional"}`, text: field.required ? "Required" : "Optional" })]), input,
        ...((field.help || field.explanation || field.example) ? [el("div", { id: `${id}-help`, class: "field-help", text: [field.explanation || field.help, field.example ? `Example: ${field.example}` : ""].filter(Boolean).join(" · ") })] : []),
        ...(field.where_to_find ? [el("details", { class: "field-location" }, [el("summary", { text: "Where do I find this?" }), el("p", { text: field.where_to_find })])] : []),
      ]));
    });
    const feedback = el("div", { class: "wizard-feedback", role: "status", "aria-live": "polite" });
    const values = () => Object.fromEntries(Object.entries(inputs).filter(([, input]) => input.value !== "").map(([key, input]) => [key, input.value]));
    const changedValues = () => Object.fromEntries((step.fields || []).filter((field) => {
      const entered = inputs[field.key]?.value || "";
      return field.secret ? Boolean(entered) : entered !== (field.value ?? "");
    }).map((field) => [field.key, inputs[field.key].value]));
    const saveButton = el("button", { class: "btn primary", type: "submit", text: step.configured ? "Continue" : "Test, save and continue" });
    const updateSaveLabel = () => { saveButton.textContent = Object.keys(changedValues()).length ? "Test, save and continue" : (step.configured ? "Continue" : "Test, save and continue"); };
    Object.values(inputs).forEach((input) => input.addEventListener("input", updateSaveLabel));
    const save = async () => {
      if (!form.reportValidity()) return false;
      const submitted = values();
      const changed = changedValues();
      if (step.configured && !Object.keys(changed).length) return true;
      const result = await api("/console/onboarding", { method: "PUT", body: JSON.stringify({ values: submitted }) });
      savedValues[step.id] = { ...(savedValues[step.id] || {}), ...submitted };
      step.configured = true;
      restartNeeded = restartNeeded || Boolean(result?.restart_required ?? result?.changed?.length);
      return true;
    };
    const testConnection = async () => {
      if (!form.reportValidity()) return;
      feedback.className = "wizard-feedback testing"; feedback.textContent = "Testing securely… This can take a few seconds.";
      try {
        const result = await api("/console/onboarding/test", { method: "POST", body: JSON.stringify({ component: step.id, values: values() }) });
        feedback.className = `wizard-feedback ${result.ok ? "success" : "error"}`;
        // The API now categorises the failure (auth / dns / timeout / tls /
        // refused / config), so show what to actually go and fix instead of a
        // generic "check the address and credentials".
        const label = CONNECTION_LABELS[result.error_kind];
        feedback.textContent = [
          label ? `${label}:` : null,
          result.message || (result.ok ? "Connected successfully. You can save and continue." : "We couldn’t connect."),
        ].filter(Boolean).join(" ");
        return Boolean(result.ok);
      } catch (e) { feedback.className = "wizard-feedback error"; feedback.textContent = `${e.message} Check the values above and your provider’s access settings, then try again.`; return false; }
    };
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = event.submitter; if (button) button.disabled = true;
      try {
        const hasChanges = Boolean(Object.keys(changedValues()).length);
        if (hasChanges && !(await testConnection())) return;
        if (await save()) { toast(hasChanges ? `${step.title} tested and saved` : `${step.title} unchanged`, "success"); current++; renderStep(); }
      } catch (e) { feedback.textContent = e.message; }
      finally { if (button?.isConnected) button.disabled = false; }
    });
    const testButton = el("button", { class: "btn", type: "button", text: "Test connection", onclick: async () => {
      testButton.disabled = true;
      await testConnection();
      testButton.disabled = false;
    } });
    const actions = [
      el("button", { class: "btn", type: "button", text: "Back", disabled: current === 0 ? "" : null, onclick: () => { current--; renderStep(); } }),
      testButton,
    ];
    if (step.optional) actions.push(el("button", { class: "btn", type: "button", text: "Skip for now", onclick: () => { current++; renderStep(); } }));
    actions.push(saveButton);
    form.append(feedback, el("div", { class: "btn-row wizard-actions" }, actions));
    const assistantAnswer = el("div", { class: "assistant-answer", role: "status", "aria-live": "polite", text: "Ask a question about this connection. Suggestions are only applied when you approve them." });
    const assistantQuestion = el("textarea", { rows: "2", placeholder: "For example: Where do I find my issuer URL?", "aria-label": `Question about ${step.title}` });
    const suggestionsBox = el("div", { class: "assistant-suggestions" });
    const askAssistant = el("button", { class: "btn small", type: "button", text: "Ask setup assistant", onclick: async () => {
      if (!assistantQuestion.value.trim()) { assistantQuestion.focus(); return; }
      askAssistant.disabled = true; assistantAnswer.textContent = "Thinking…"; suggestionsBox.replaceChildren();
      const safeValues = Object.fromEntries((step.fields || []).filter((field) => !field.secret && inputs[field.key]?.value).map((field) => [field.key, inputs[field.key].value]));
      try {
        const result = await api("/console/onboarding/assist", { method: "POST", body: JSON.stringify({ component: step.id, question: assistantQuestion.value.trim(), values: safeValues }) });
        assistantAnswer.textContent = result.answer || "No guidance was returned.";
        if (result.warnings?.length) suggestionsBox.appendChild(el("div", { class: "notice", text: result.warnings.join(" ") }));
        const suggestions = Array.isArray(result.suggestions) ? result.suggestions : Object.entries(result.suggestions || {}).map(([field, value]) => ({ field, value }));
        suggestions.forEach((suggestion) => {
          const key = suggestion.field || suggestion.key;
          if (!key || !inputs[key] || (step.fields || []).find((field) => field.key === key)?.secret) return;
          suggestionsBox.appendChild(el("div", { class: "suggestion-preview" }, [
            el("span", { text: `${(step.fields || []).find((field) => field.key === key)?.label || key}: ${suggestion.value}` }),
            el("button", { class: "btn small", type: "button", text: "Apply to form", onclick: () => { inputs[key].value = suggestion.value ?? ""; inputs[key].dispatchEvent(new Event("input")); toast("Suggestion applied to the form. Review it before saving.", "success"); } }),
          ]));
        });
      } catch (e) { assistantAnswer.textContent = `Assistant unavailable: ${e.message}`; }
      finally { askAssistant.disabled = false; }
    } });
    const assistant = el("details", { class: "setup-assistant" }, [
      el("summary", { text: "Ask the AI setup assistant" }),
      el("p", { class: "field-help", text: "It can explain provider screens and suggest non-secret form values. Nothing is applied or saved automatically." }),
      el("div", { class: "quick-questions", "aria-label": "Suggested questions" }, [
        ...["Where do I find these values?", "What permissions are required?", "How should I troubleshoot a failed test?"].map((question) => el("button", { class: "btn small", type: "button", text: question, onclick: () => { assistantQuestion.value = question; askAssistant.click(); } })),
      ]),
      assistantQuestion, el("div", { class: "btn-row" }, [askAssistant]), assistantAnswer, suggestionsBox,
    ]);
    const contextHelp = el("details", { class: "context-help", open: "" }, [
      el("summary", { text: "Setup help and prerequisites" }),
      el("p", { text: step.learn_more || `This connection lets Kingphisher use ${step.title}. Gather the items below before testing.` }),
      ...(step.prerequisites?.length ? [el("ul", { class: "prerequisite-list" }, step.prerequisites.map((item) => el("li", { text: item })))] : []),
      el("p", { class: "field-help", text: `Typical time: about ${step.estimated_minutes || 5} minutes. You can ask the setup assistant for provider-specific guidance without sharing credentials.` }),
      el("button", { class: "link-button", type: "button", text: "Open searchable help center", onclick: () => { location.hash = "help"; } }),
    ]);
    stage.replaceChildren(progress, el("section", { class: "card wizard-card", "aria-labelledby": "wizard-title" }, [
      el("div", { class: "step-heading" }, [el("h3", { id: "wizard-title", tabindex: "-1", text: step.title }), el("span", { class: `step-kind ${step.optional ? "optional" : "required"}`, text: step.optional ? "Optional" : "Required" })]),
      el("p", { class: "wizard-description", text: step.explanation || step.description || "Enter the connection details below." }),
      contextHelp,
      step.configured ? el("p", { class: "configured-label", text: "Already configured. Leave secret fields blank to keep their current values." }) : el("span"),
      form, assistant,
    ]));
    stage.querySelector("#wizard-title").focus();
  };
  renderStep();
};

/* ---------- Azure deployment wizard ---------- */
views["azure-deployment"] = async (root) => {
  root.appendChild(el("h2", { text: "Deploy Kingphisher to Azure" }));
  root.appendChild(el("p", { class: "sub", text: "Gather, validate, and export the non-secret values used by the protected Azure deployment workflow." }));
  let schema;
  try { schema = await api("/console/azure-deployment"); } catch (e) {
    root.appendChild(el("div", { class: "card", role: "alert", text: `Failed to load Azure deployment guidance: ${e.message}` }));
    return;
  }
  const steps = Array.isArray(schema.steps) ? schema.steps : [];
  const collected = {};
  let current = -1;
  const stage = el("div", { class: "onboarding-stage" });
  root.appendChild(stage);

  const download = (name, content) => {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    link.download = name;
    link.click();
    URL.revokeObjectURL(link.href);
  };
  const render = () => {
    if (current < 0) {
      stage.replaceChildren(el("section", { class: "card wizard-card wizard-welcome", "aria-labelledby": "azure-wizard-title" }, [
        el("div", { class: "eyebrow", text: "AZURE DEPLOYMENT" }),
        el("h3", { id: "azure-wizard-title", tabindex: "-1", text: "Prepare a secure, automated deployment" }),
        el("p", { text: "This wizard explains every identifier, hostname, and governance choice required by the deployment automation. It validates your entries before producing a configuration handoff." }),
        el("ul", { class: "welcome-facts" }, [
          el("li", { text: "No Azure password, client secret, access key, or Terraform state is requested" }),
          el("li", { text: "Nothing is provisioned until an authorized operator runs and approves the GitHub workflow" }),
          el("li", { text: "Production remains protected by the GitHub environment’s required reviewers" }),
        ]),
        el("div", { class: "notice", role: "note", text: schema.safety_note }),
        el("div", { class: "btn-row" }, [
          el("button", { class: "btn primary", type: "button", text: "Start Azure deployment setup", onclick: () => { current = 0; render(); } }),
          el("button", { class: "btn", type: "button", text: "Read deployment guide", onclick: () => { location.hash = "help"; } }),
        ]),
      ]));
      stage.querySelector("#azure-wizard-title").focus();
      return;
    }
    const review = current === steps.length;
    const progress = el("ol", { class: "wizard-progress", "aria-label": "Azure deployment progress" });
    steps.forEach((step, index) => progress.appendChild(el("li", {
      class: `${index === current ? "current" : ""} ${index < current ? "done" : ""}`.trim(),
      "aria-current": index === current ? "step" : null,
    }, [el("span", { class: "step-number", text: index + 1 }), el("span", { text: step.title })])));
    progress.appendChild(el("li", { class: review ? "current" : "", "aria-current": review ? "step" : null }, [
      el("span", { class: "step-number", text: steps.length + 1 }), el("span", { text: "Validate" }),
    ]));

    if (review) {
      const resultBox = el("div", { class: "wizard-feedback", role: "status", "aria-live": "polite", text: "Select Validate configuration to run the readiness checks." });
      const exports = el("div", { class: "btn-row" });
      const validateButton = el("button", { class: "btn primary", type: "button", text: "Validate configuration", onclick: async () => {
        validateButton.disabled = true; exports.replaceChildren(); resultBox.textContent = "Validating non-secret deployment values…";
        try {
          const result = await api("/console/azure-deployment/validate", { method: "POST", body: JSON.stringify({ values: collected }) });
          if (!result.ok) {
            resultBox.className = "wizard-feedback error";
            resultBox.textContent = Object.entries(result.errors || {}).map(([key, message]) => `${key}: ${message}`).join(" ");
            return;
          }
          resultBox.className = "wizard-feedback success";
          resultBox.textContent = ["Configuration is structurally ready.", ...(result.warnings || [])].join(" ");
          const terraformKeys = ["subscription_id", "environment", "location", "name_prefix", "operator_fqdn", "tracking_fqdn", "entra_tenant_id", "entra_client_id", "communication_data_location", "ai_endpoint", "alert_webhook_domains"];
          const tfvars = terraformKeys.filter((key) => collected[key] !== undefined).map((key) => `${key} = ${JSON.stringify(collected[key])}`).join("\n") + "\n";
          const workflowValues = {
            AZURE_SUBSCRIPTION_ID: collected.subscription_id,
            AZURE_TENANT_ID: collected.entra_tenant_id,
            ENTRA_APPLICATION_CLIENT_ID: collected.entra_client_id,
            OPERATOR_FQDN: collected.operator_fqdn,
            TRACKING_FQDN: collected.tracking_fqdn,
            AI_GATEWAY_ENDPOINT: collected.ai_endpoint || "",
            ALERT_WEBHOOK_DOMAINS: collected.alert_webhook_domains || "",
            TF_STATE_RESOURCE_GROUP: collected.tf_state_resource_group,
            TF_STATE_STORAGE_ACCOUNT: collected.tf_state_storage_account,
            TF_STATE_CONTAINER: collected.tf_state_container,
          };
          exports.append(
            el("button", { class: "btn", type: "button", text: "Download Terraform values", onclick: () => download(`${collected.environment}.auto.tfvars`, tfvars) }),
            el("button", { class: "btn", type: "button", text: "Download GitHub variables", onclick: () => download("github-environment-variables.json", JSON.stringify(workflowValues, null, 2) + "\n") }),
          );
        } catch (e) { resultBox.className = "wizard-feedback error"; resultBox.textContent = e.message; }
        finally { validateButton.disabled = false; }
      } });
      const summary = el("dl", { class: "wizard-summary" });
      steps.forEach((step) => {
        summary.append(el("dt", { text: step.title }), el("dd", { text: (step.fields || []).map((field) => `${field.label}: ${collected[field.key] || "Not entered"}`).join(" · ") }));
      });
      stage.replaceChildren(progress, el("section", { class: "card wizard-card", "aria-labelledby": "azure-wizard-title" }, [
        el("h3", { id: "azure-wizard-title", tabindex: "-1", text: "Validate and hand off deployment" }),
        el("p", { text: "Review the non-secret values below. Validation does not contact Azure or deploy resources." }),
        summary, resultBox, exports,
        el("div", { class: "notice", role: "note", text: "After adding these values to the protected GitHub environment, an authorized operator runs Azure deployment. The workflow plans, requires environment approval, applies, migrates, and health-checks the release." }),
        el("div", { class: "btn-row wizard-actions" }, [
          el("button", { class: "btn", type: "button", text: "Back", onclick: () => { current--; render(); } }), validateButton,
        ]),
      ]));
      stage.querySelector("#azure-wizard-title").focus();
      return;
    }

    const step = steps[current];
    const inputs = {};
    const form = el("form", { class: "wizard-form" });
    (step.fields || []).forEach((field, index) => {
      const id = `azure-${current}-${index}`;
      const attrs = { id, name: field.key, required: field.required ? "" : null, placeholder: field.placeholder || "", autocomplete: "off", "aria-describedby": `${id}-help` };
      const input = field.choices?.length
        ? el("select", attrs, field.choices.map((choice) => el("option", { value: choice.value, text: choice.label })))
        : el("input", { ...attrs, type: field.type === "url" ? "url" : "text" });
      input.value = collected[field.key] ?? (field.choices?.[0]?.value || ""); inputs[field.key] = input;
      form.appendChild(el("div", { class: "wizard-field" }, [
        el("label", { for: id }, [el("span", { text: field.label }), el("span", { class: `requirement ${field.required ? "required" : "optional"}`, text: field.required ? "Required" : "Optional" })]), input,
        el("details", { id: `${id}-help`, class: "field-location" }, [el("summary", { text: "Where do I find this?" }), el("p", { text: field.where_to_find })]),
      ]));
    });
    form.addEventListener("submit", (event) => {
      event.preventDefault(); if (!form.reportValidity()) return;
      Object.entries(inputs).forEach(([key, input]) => { collected[key] = input.value.trim(); }); current++; render();
    });
    form.appendChild(el("div", { class: "btn-row wizard-actions" }, [
      el("button", { class: "btn", type: "button", text: "Back", onclick: () => { current--; render(); } }),
      el("button", { class: "btn primary", type: "submit", text: "Save in this wizard and continue" }),
    ]));
    const answer = el("div", { class: "assistant-answer", role: "status", "aria-live": "polite", text: "Ask where to find a value or why it is required. Nothing is changed automatically." });
    const question = el("textarea", { rows: "2", placeholder: "For example: Where do I find my tenant ID?", "aria-label": `Question about ${step.title}` });
    const ask = el("button", { class: "btn small", type: "button", text: "Ask setup assistant", onclick: async () => {
      if (!question.value.trim()) { question.focus(); return; } ask.disabled = true; answer.textContent = "Thinking…";
      const values = Object.fromEntries(Object.entries(inputs).filter(([, input]) => input.value).map(([key, input]) => [key, input.value]));
      try {
        const result = await api("/console/onboarding/assist", { method: "POST", body: JSON.stringify({ component: step.id, question: question.value.trim(), values }) });
        answer.textContent = [result.answer, ...(result.warnings || [])].filter(Boolean).join(" ");
      } catch (e) { answer.textContent = `Assistant unavailable: ${e.message}`; }
      finally { ask.disabled = false; }
    } });
    const assistant = el("details", { class: "setup-assistant" }, [
      el("summary", { text: "Ask the AI setup assistant" }),
      el("p", { class: "field-help", text: "Only the non-secret fields on this page are eligible for assistance. AI cannot deploy or save settings." }),
      question, el("div", { class: "btn-row" }, [ask]), answer,
    ]);
    stage.replaceChildren(progress, el("section", { class: "card wizard-card", "aria-labelledby": "azure-wizard-title" }, [
      el("div", { class: "step-heading" }, [el("h3", { id: "azure-wizard-title", tabindex: "-1", text: step.title }), el("span", { class: "step-kind required", text: "Deployment" })]),
      el("p", { class: "wizard-description", text: step.description }),
      el("details", { class: "context-help", open: "" }, [
        el("summary", { text: "Prerequisites for this step" }),
        el("ul", { class: "prerequisite-list" }, (step.prerequisites || []).map((item) => el("li", { text: item }))),
        el("p", { class: "field-help", text: `Typical time: about ${step.estimated_minutes || 5} minutes.` }),
      ]), form, assistant,
    ]));
    stage.querySelector("#azure-wizard-title").focus();
  };
  render();
};

/* ---------- help ---------- */
views.help = async (root) => {
  root.appendChild(el("h2", { text: "Help center" }));
  root.appendChild(el("p", { class: "sub", text: "Plain-language setup guides and definitions, all in one place." }));
  const search = el("input", { type: "search", class: "help-search", placeholder: "Search topics and terms (for example, OIDC)", "aria-label": "Search help" });
  const results = el("div", { class: "help-results", "aria-live": "polite" });
  root.append(search, results);
  let help;
  try { help = await api("/console/help"); }
  catch (e) { results.replaceChildren(el("div", { class: "card", role: "alert", text: `Help is unavailable: ${e.message}` })); return; }
  const topics = Array.isArray(help?.topics) ? help.topics : Object.entries(help?.topics || {}).map(([title, body]) => ({ title, body }));
  const glossary = Array.isArray(help?.glossary) ? help.glossary : Object.entries(help?.glossary || {}).map(([term, definition]) => ({ term, definition }));
  const draw = () => {
    const query = search.value.trim().toLowerCase();
    const topicMatches = topics.filter((topic) => `${topic.title || topic.name || ""} ${topic.summary || topic.body || topic.content || ""}`.toLowerCase().includes(query));
    const termMatches = glossary.filter((item) => `${item.term || item.name || ""} ${item.meaning || item.definition || item.description || ""}`.toLowerCase().includes(query));
    const topicGrid = el("div", { class: "help-grid" }, topicMatches.map((topic) => el("article", { class: "card help-card" }, [
      el("h3", { text: topic.title || topic.name || "Help topic" }),
      el("p", { text: topic.summary || topic.body || topic.content || "" }),
      ...(topic.steps?.length ? [el("ol", {}, topic.steps.map((step) => el("li", { text: typeof step === "string" ? step : step.text || step.title })))] : []),
    ])));
    const glossaryList = el("dl", { class: "glossary-list" });
    termMatches.forEach((item) => {
      glossaryList.append(el("dt", { text: item.term || item.name }), el("dd", { text: item.meaning || item.definition || item.description }));
    });
    results.replaceChildren(
      el("section", { "aria-labelledby": "help-topics" }, [el("h3", { id: "help-topics", text: `Setup topics (${topicMatches.length})` }), topicMatches.length ? topicGrid : el("p", { class: "empty", text: "No setup topics match your search." })]),
      el("section", { "aria-labelledby": "help-glossary" }, [el("h3", { id: "help-glossary", text: `Glossary (${termMatches.length})` }), termMatches.length ? glossaryList : el("p", { class: "empty", text: "No glossary terms match your search." })]),
    );
  };
  search.addEventListener("input", draw);
  draw();
};

/* ---------- dashboard ---------- */
views.dashboard = async (root) => {
  root.appendChild(el("h2", { text: "Dashboard" }));
  root.appendChild(el("p", { class: "sub", text: "System health and recent campaign activity." }));
  let status, campaigns, audit;
  try {
    [status, campaigns, audit] = await Promise.all([
      api("/console/status"), api("/campaigns"), api("/audit/verify", { method: "POST" }),
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
      el("td", { class: "mono", text: formatInstant(c.schedule_start) }),
      el("td", { class: "mono", text: formatInstant(c.schedule_end) }),
    ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 4, text: "No campaigns yet." })])]),
  ]);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Campaigns" }), table]));
};

/* ---------- campaigns ---------- */
views.campaigns = async (root) => {
  const policy = (sessionInfo() || {}).approvalPolicy || "single-admin";
  const enforcing = policy === "enforce";

  root.appendChild(el("h2", { text: "Campaigns" }));
  root.appendChild(el("p", { class: "sub", text: "Create, review and run awareness campaigns." }));

  // The approval rule is the single most confusing thing about this screen, so
  // state it up front rather than letting an operator discover it as a 409.
  const banner = el("div", { class: "policy-banner" });
  banner.appendChild(el("strong", { text: enforcing ? "Two-person approval is required. " : "Single-admin mode. " }));
  banner.appendChild(document.createTextNode(enforcing
    ? "A campaign must collect both a security and a privacy approval before it can be scheduled. You cannot approve a campaign you created, and the two approvals must come from different people. Submit a draft for approval to start that process."
    : "One administrator can schedule a campaign without separate approvals. This is intended for the offline evaluation stack; deployments using an identity provider always require two-person approval."));
  root.appendChild(banner);

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
        el("label", { for: "c-title", text: "Title" }), el("input", { id: "c-title" }),
        el("label", { for: "c-sender", text: "Sender mailbox" }), el("input", { id: "c-sender", value: "security-drills@example.com" }),
        el("label", { for: "c-sender-display", text: "Sender display name (persona)" }),
        el("input", { id: "c-sender-display", placeholder: "e.g. Account Security" }),
        el("p", { class: "field-help", text: "Shown in the From header; honored only when the mailbox is on a registered sending domain (KP_SENDING_DOMAINS), otherwise delivery falls back to the configured sender." }),
        el("label", { for: "c-tdomain", text: "Training domain" }), el("input", { id: "c-tdomain", value: "127.0.0.1" }),
        el("label", { for: "c-max", text: "Max recipients" }), el("input", { id: "c-max", type: "number", min: "1", max: "100000", value: "1000" }),
      ]),
      el("div", {}, [
        el("label", { for: "c-pattern", text: "Pattern" }),
        el("select", { id: "c-pattern" }, patterns.map((p) => el("option", { value: p.campaign_pattern_id, text: `${p.lure_category} (${p.approval_state})` }))),
        el("label", { for: "c-template", text: "Template version" }),
        el("select", { id: "c-template" }, templates.map((t) => el("option", { value: t.template_version_id, text: `${t.version} ${t.subject}` }))),
        el("label", { for: "c-start", text: "Start (your local time)" }), el("input", { id: "c-start", type: "datetime-local" }),
        el("label", { for: "c-end", text: "End (your local time)" }), el("input", { id: "c-end", type: "datetime-local" }),
        el("p", { class: "field-help", text: `Times will be stored as absolute instants. Browser timezone: ${browserTimeZone()}.` }),
      ]),
    ]),
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Create campaign", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          const start = localDateTimeToIso(document.getElementById("c-start").value, "Start");
          const end = localDateTimeToIso(document.getElementById("c-end").value, "End");
          if (new Date(end) <= new Date(start)) throw new Error("End must be after start");
          await api("/campaigns", { method: "POST", body: JSON.stringify({
            pattern_id: document.getElementById("c-pattern").value,
            title: document.getElementById("c-title").value,
            sender_mailbox: document.getElementById("c-sender").value,
            sender_display_name: document.getElementById("c-sender-display").value.trim() || null,
            training_domain: document.getElementById("c-tdomain").value,
            schedule_start: start,
            schedule_end: end,
            timezone: browserTimeZone(),
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
      el("th", { text: "Title" }), el("th", { text: "Sender" }), el("th", { text: "State" }), el("th", { text: "Actions" }),
    ])]),
    el("tbody", {}, campaigns.map((c) => el("tr", {}, [
      el("td", { text: c.title }),
      el("td", { text: c.sender_display_name ? `${c.sender_display_name} <${c.sender_mailbox}>` : c.sender_mailbox }),
      el("td", { text: c.state }),
      el("td", {}, (() => {
        const actions = [];
        if (c.state === "draft") {
          actions.push(el("button", { class: "btn small primary", text: "Submit for approval",
            onclick: act(`/campaigns/${c.campaign_id}/submit`, "Submitted for approval") }));
          // Offering "Schedule" under enforce would just produce a 409 the
          // operator cannot act on, so it is only shown where it can succeed.
          if (!enforcing) {
            actions.push(el("button", { class: "btn small", text: "Schedule", onclick: scheduleAct(c) }));
          }
        }
        if (c.state === "pending_approval") {
          for (const type of ["security", "privacy"]) {
            actions.push(el("button", { class: "btn small", text: `Approve ${type}`, onclick: approvalAct(c, type, "approved") }));
            actions.push(el("button", { class: "btn small danger", text: `Reject ${type}`, onclick: approvalAct(c, type, "rejected") }));
          }
        }
        if (c.state === "approved") actions.push(el("button", { class: "btn small primary", text: "Schedule", onclick: scheduleAct(c) }));
        if (c.state === "scheduled") actions.push(el("button", { class: "btn small", text: "Test send", onclick: act(`/campaigns/${c.campaign_id}/test-send`, "Test send queued") }));
        if (["scheduled", "approved"].includes(c.state)) actions.push(el("button", { class: "btn small danger", text: "Recall", onclick: act(`/campaigns/${c.campaign_id}/recall`, "Recall initiated") }));
        if (["scheduled", "sending", "active"].includes(c.state)) actions.push(el("button", { class: "btn small danger", text: "Kill switch", onclick: (async (e) => {
          const ok = await confirmDialog({
            title: "Engage scoped kill switch?",
            message: `This revokes queued deliveries and tracking tokens for "${c.title}". It cannot be undone.`,
            confirmLabel: "Engage kill switch", danger: true,
          });
          if (!ok) return;
          e.target.disabled = true;
          try {
            const res = await api("/kill-switch", { method: "POST", body: JSON.stringify({ campaign_id: c.campaign_id, confirm: true }) });
            toast(`Kill switch: ${res.cancelled} cancelled, ${res.tokens_revoked} tokens revoked`, "success");
          } catch (err) { toast(err.message, "error"); }
          finally { e.target.disabled = false; }
        }) }));
        actions.push(el("button", { class: "btn small", text: "Report", onclick: async (e) => {
          e.target.disabled = true;
          try {
            showCampaignReport(await api(`/campaigns/${c.campaign_id}/report`));
          } catch (err) { toast(err.message, "error"); }
          finally { e.target.disabled = false; }
        } }));
        actions.push(el("button", { class: "btn small", text: "Add alert", onclick: async (e) => {
          const values = await promptDialog({
            title: `Alert subscription for "${c.title}"`,
            description: "Campaign state changes are posted to this destination.",
            fields: [
              { name: "channel", label: "Channel", type: "select", value: "webhook",
                options: [{ value: "webhook", label: "Webhook" }, { value: "ntfy", label: "ntfy" }] },
              { name: "destination", label: "Destination URL", type: "url", required: true,
                placeholder: "https://ntfy.example.com/my-private-topic",
                help: "Must be HTTPS and within the configured alert domain allowlist." },
            ],
            submitLabel: "Create subscription",
          });
          if (!values) return;
          e.target.disabled = true;
          try {
            const result = await api("/alerts/subscriptions", { method: "POST", body: JSON.stringify({
              campaign_id: c.campaign_id, channel: values.channel, destination_url: values.destination,
            }) });
            if (result.signing_secret) {
              showCopyable({
                title: "Signing secret",
                description: "Save this now — it is shown once and cannot be retrieved later. Use it to verify alert payload signatures.",
                value: result.signing_secret,
              });
            }
            toast("Alert subscription created", "success");
          } catch (err) { toast(err.message, "error"); }
          finally { e.target.disabled = false; }
        } }));
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

  function approvalAct(campaign, approvalType, decision) {
    return async (e) => {
      const approving = decision === "approved";
      const values = await promptDialog({
        title: `${approving ? "Approve" : "Reject"}: ${approvalType} review`,
        description: `Campaign "${campaign.title}". This decision is recorded in the audit chain against your identity.`,
        fields: [
          { name: "rationale", label: "Rationale", type: "textarea", required: true,
            placeholder: approving ? "Why this campaign is safe to run" : "What must change before this can run",
            help: "You cannot approve a campaign you created, and security and privacy approvals must come from different people." },
        ],
        submitLabel: approving ? "Record approval" : "Record rejection",
      });
      if (!values) return;
      const rationale = values.rationale;
      const btn = e.target; btn.disabled = true;
      try {
        await api(`/campaigns/${campaign.campaign_id}/approvals/${approvalType}`, {
          method: "POST",
          body: JSON.stringify({ decision, rationale: rationale.trim() }),
        });
        toast(`${approvalType} review recorded as ${decision}`, "success");
        location.reload();
      } catch (err) { toast(err.message, "error"); }
      finally { btn.disabled = false; }
    };
  }

  function scheduleAct(campaign) {
    return async (e) => {
      const ok = await confirmDialog({
        title: `Schedule "${campaign.title}"?`,
        message: "Once scheduled, deliveries are queued and will send at the start time.",
        detail: {
          Start: formatInstant(campaign.schedule_start),
          End: formatInstant(campaign.schedule_end),
          "Time zone": browserTimeZone(),
        },
        confirmLabel: "Schedule campaign",
      });
      if (!ok) return;
      return act(`/campaigns/${campaign.campaign_id}/schedule`, "Scheduled")(e);
    };
  }
};

/* ---------- sending domains & rules of engagement ----------
   The authorization boundary, operated from here: prove DNS control of a
   domain (onboarding wizard + lookalike generator), then sign the
   Rules-of-Engagement that delivery fails closed without. */
views.sending = async (root) => {
  root.appendChild(el("h2", { text: "Domains & Rules of Engagement" }));
  root.appendChild(el("p", { class: "sub", text: "Prove you control a domain via DNS, then sign the RoE that authorizes delivery to it." }));

  let domains, roes;
  try {
    const [d, r] = await Promise.all([api("/sending-domains"), api("/roe")]);
    domains = d.domains || [];
    roes = r.roes || [];
  } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` }));
    return;
  }
  const verifiedDomains = domains.filter((d) => d.active).map((d) => d.domain);

  const banner = el("div", { class: "policy-banner" });
  banner.appendChild(el("strong", { text: "Delivery fails closed. " }));
  banner.appendChild(document.createTextNode(
    "Recipients may only sit in DNS-verified domains named by an active signed RoE, and a campaign cannot be scheduled or delivered outside that boundary. Revoking an RoE stops its campaigns immediately.",
  ));
  root.appendChild(banner);

  function dnsRecordTextarea(record) {
    const ta = el("textarea", { class: "mono", rows: "2", readonly: "readonly" });
    ta.value = record.value;
    return ta;
  }

  function showRecordsDialog(title, description, records) {
    const { dlg, form } = dialogShell(title, description);
    for (const record of records) {
      form.appendChild(el("div", { class: "dns-record" }, [
        el("strong", { text: `${record.type} ${record.name}` }),
        dnsRecordTextarea(record),
        el("p", { class: "modal-help", text: record.note }),
        el("button", {
          class: "btn small", type: "button", text: "Copy",
          onclick: () => showCopyable({ title: `Copy ${record.type} record`, description: `${record.name}`, value: record.value }),
        }),
      ]));
    }
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Close", onclick: () => dlg.close() }),
    ]));
    openDialog(dlg);
  }

  async function verifyDomain(domain) {
    try {
      await api("/sending-domains/verify", { method: "POST", body: JSON.stringify({ domain }) });
      toast(`Domain ${domain} verified`, "success");
      location.reload();
    } catch (err) { toast(err.message, "error"); }
  }

  async function onboard() {
    const values = await promptDialog({
      title: "Onboard a sending domain",
      description: "You get the exact DNS records for your zone. The domain only becomes verified — and usable as a sending or target domain — after the challenge is observable in live DNS.",
      fields: [
        { name: "domain", label: "Domain", type: "text", required: true, placeholder: "corp-benefits.example" },
        { name: "relay", label: "Mail relay", type: "select", value: "smtp", options: [
          { value: "smtp", label: "Generic SMTP relay" },
          { value: "ses", label: "Amazon SES" },
          { value: "mailgun", label: "Mailgun" },
          { value: "postfix", label: "Postfix" },
        ] },
        { name: "relay_address", label: "Relay IP/address (SPF)", type: "text", placeholder: "optional, e.g. 203.0.113.10" },
        { name: "dmarc_address", label: "DMARC report mailbox", type: "text", placeholder: "optional, e.g. dmarc@example.com" },
      ],
      submitLabel: "Get DNS records",
    });
    if (!values) return;
    try {
      const challenge = await api("/sending-domains/challenge", {
        method: "POST",
        body: JSON.stringify({
          domain: values.domain,
          relay: values.relay,
          relay_address: values.relay_address || null,
          dmarc_address: values.dmarc_address || null,
        }),
      });
      const { dlg, form } = dialogShell("DNS records to publish", `Paste these into your DNS zone for ${challenge.domain}, then click Verify.`);
      for (const record of challenge.dns_records) {
        form.appendChild(el("div", { class: "dns-record" }, [
          el("strong", { text: `${record.type} ${record.name}` }),
          dnsRecordTextarea(record),
          el("p", { class: "modal-help", text: record.note }),
          el("button", {
            class: "btn small", type: "button", text: "Copy",
            onclick: () => showCopyable({ title: `Copy ${record.type} record`, description: record.name, value: record.value }),
          }),
        ]));
      }
      form.appendChild(el("div", { class: "modal-actions" }, [
        el("button", { class: "btn", type: "button", text: "Close", onclick: () => dlg.close() }),
        el("button", { class: "btn primary", type: "button", text: "Verify now", onclick: async () => {
          dlg.close();
          await verifyDomain(challenge.domain);
        } }),
      ]));
      openDialog(dlg);
    } catch (err) { toast(err.message, "error"); }
  }

  async function lookalike() {
    const values = await promptDialog({
      title: "Lookalike generator",
      description: "Candidate sending hostnames under a domain you control, each with ready-to-paste DNS records. Registerable by definition; they join the pool only after verification.",
      fields: [
        { name: "brand", label: "Brand the lure imitates", type: "text", required: true, placeholder: "Okta" },
        { name: "base_domain", label: "Base domain you control", type: "text", required: true, placeholder: "corp-training.example" },
        { name: "relay", label: "Mail relay", type: "select", value: "smtp", options: [
          { value: "smtp", label: "Generic SMTP relay" },
          { value: "ses", label: "Amazon SES" },
          { value: "mailgun", label: "Mailgun" },
          { value: "postfix", label: "Postfix" },
        ] },
        { name: "limit", label: "How many candidates", type: "number", value: "6" },
      ],
      submitLabel: "Generate candidates",
    });
    if (!values) return;
    try {
      const resp = await api(`/sending-domains/generate?brand=${encodeURIComponent(values.brand)}&base_domain=${encodeURIComponent(values.base_domain)}&relay=${encodeURIComponent(values.relay)}&limit=${encodeURIComponent(values.limit || "6")}`);
      const candidates = resp.candidates || [];
      if (!candidates.length) { toast("No candidates generated", "error"); return; }
      const { dlg, form } = dialogShell("Lookalike candidates", `Pick a candidate, publish its DNS records, then verify it in the list below.`);
      for (const candidate of candidates) {
        form.appendChild(el("section", { class: "dns-record" }, [
          el("h4", { text: candidate.domain }),
          ...candidate.dns_records.map((record) => el("div", {}, [
            el("strong", { text: `${record.type} ${record.name}` }),
            dnsRecordTextarea(record),
            el("p", { class: "modal-help", text: record.note }),
          ])),
        ]));
      }
      form.appendChild(el("div", { class: "modal-actions" }, [
        el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => dlg.close() }),
      ]));
      openDialog(dlg);
    } catch (err) { toast(err.message, "error"); }
  }

  async function signRoe() {
    const values = await promptDialog({
      title: "Sign a Rules-of-Engagement",
      description: "The signature binds terms + signer + timestamp under the shared RoE key. Every target domain must already be DNS-verified, and the window must cover the campaigns it authorizes.",
      fields: [
        { name: "authorizing_party", label: "Authorizing party", type: "text", required: true, placeholder: "Example Corp" },
        { name: "terms", label: "Terms", type: "textarea", required: true, placeholder: "Q3 training: recipients confined to the verified target domains; lures disclosed as training." },
        { name: "window_start", label: "Window start (your local time)", type: "datetime-local", required: true },
        { name: "window_end", label: "Window end (your local time)", type: "datetime-local", required: true },
        { name: "target_domains", label: "Target domains (comma-separated, must be verified)", type: "text", required: true, value: verifiedDomains.join(", ") },
      ],
      submitLabel: "Sign RoE",
    });
    if (!values) return;
    try {
      const start = localDateTimeToIso(values.window_start, "Window start");
      const end = localDateTimeToIso(values.window_end, "Window end");
      if (new Date(end) <= new Date(start)) throw new Error("Window end must be after window start");
      const targets = values.target_domains.split(",").map((d) => d.trim()).filter(Boolean);
      if (!targets.length) throw new Error("At least one target domain is required");
      const roe = await api("/roe", {
        method: "POST",
        body: JSON.stringify({
          authorizing_party: values.authorizing_party,
          terms: values.terms,
          window_start: start,
          window_end: end,
          target_domains: targets,
        }),
      });
      toast(`RoE signed (${roe.terms_hash.slice(0, 12)}...)`, "success");
      location.reload();
    } catch (err) { toast(err.message, "error"); }
  }

  async function revokeRoe(roe) {
    const ok = await confirmDialog({
      title: `Revoke RoE for ${roe.authorizing_party}?`,
      message: "Its campaigns fail closed immediately — queued and future deliveries stop. The record is kept for the audit trail.",
      detail: { Signer: roe.signer, Window: `${formatInstant(roe.window_start)} → ${formatInstant(roe.window_end)}` },
      confirmLabel: "Revoke RoE", danger: true,
    });
    if (!ok) return;
    const values = await promptDialog({
      title: "Reason for revocation",
      fields: [{ name: "reason", label: "Reason (recorded in audit)", type: "textarea", placeholder: "Engagement complete" }],
      submitLabel: "Revoke",
    });
    if (!values) return;
    try {
      await api(`/roe/${roe.roe_id}/revoke`, { method: "POST", body: JSON.stringify({ reason: values.reason || null }) });
      toast("RoE revoked", "success");
      location.reload();
    } catch (err) { toast(err.message, "error"); }
  }

  /* --- verified domains --- */
  const domainRows = domains.length ? domains.map((d) => el("tr", {}, [
    el("td", { text: d.domain }),
    el("td", { class: "mono", text: formatInstant(d.verified_at) }),
    el("td", {}, [el("span", { class: `pill ${d.active ? "ok" : "down"}`, text: d.active ? "verified" : "revoked" })]),
  ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 3, text: "No verified domains yet. Onboard one below." })])];
  root.appendChild(el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [
      el("h3", { text: "Verified domains" }),
      el("div", { class: "btn-row" }, [
        el("button", { class: "btn", text: "Lookalike generator", onclick: lookalike }),
        el("button", { class: "btn primary", text: "Onboard a sending domain", onclick: onboard }),
      ]),
    ]),
    el("p", { class: "field-help", text: "A domain is verified only when its DNS-TXT challenge is observable in live DNS. Verified domains can be named in an RoE (recipients) and used as sending domains (KP_SENDING_DOMAINS)." }),
    el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", { text: "Domain" }), el("th", { text: "Verified at" }), el("th", { text: "Status" })])]), el("tbody", {}, domainRows)]),
  ]));

  /* --- rules of engagement --- */
  const nowMs = Date.now();
  const roeActive = (roe) => !roe.revoked_at
    && Date.parse(roe.window_start) <= nowMs && nowMs <= Date.parse(roe.window_end);
  const roeRows = roes.length ? roes.map((roe) => el("tr", {}, [
    el("td", { text: roe.authorizing_party }),
    el("td", { text: roe.signer }),
    el("td", { class: "mono", text: `${formatInstant(roe.window_start)} → ${formatInstant(roe.window_end)}` }),
    el("td", { text: (roe.target_domains || []).join(", ") }),
    el("td", {}, [el("span", { class: `pill ${roe.revoked_at ? "down" : (roeActive(roe) ? "ok" : "down")}`, text: roe.revoked_at ? "revoked" : (roeActive(roe) ? "active" : "window passed") })]),
    el("td", {}, roe.revoked_at ? [el("span", { class: "empty", text: formatInstant(roe.revoked_at) })] : [el("button", { class: "btn small danger", text: "Revoke", onclick: () => revokeRoe(roe) })]),
  ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 6, text: "No Rules-of-Engagement signed yet. Delivery is blocked until one covers a campaign." })])];
  root.appendChild(el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [
      el("h3", { text: "Rules of Engagement" }),
      el("div", { class: "btn-row" }, [el("button", { class: "btn primary", text: "Sign RoE", onclick: signRoe })]),
    ]),
    el("p", { class: "field-help", text: "Scheduling and delivery require an unrevoked RoE whose window contains the campaign window and whose target domains cover every recipient." }),
    el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", { text: "Authorizing party" }), el("th", { text: "Signer" }), el("th", { text: "Window" }), el("th", { text: "Target domains" }), el("th", { text: "Status" }), el("th", { text: "" })])]), el("tbody", {}, roeRows)]),
  ]));
};

/* ---------- template review ----------
   The human gate on AI-generated content. Until a draft is approved here it
   cannot be scheduled, so this screen is what stops an unreviewed model output
   reaching a recipient. */
views.templates = async (root) => {
  root.appendChild(el("h2", { text: "Template review" }));
  root.appendChild(el("p", { class: "sub", text: "Generated drafts awaiting human approval." }));

  const banner = el("div", { class: "policy-banner" });
  banner.appendChild(el("strong", { text: "Nothing here has been sent. " }));
  banner.appendChild(document.createTextNode(
    "Drafts are produced from approved threat patterns, re-checked by the safety validator, and can only be used in a campaign once approved below. You cannot approve a draft whose generation you requested.",
  ));
  root.appendChild(banner);

  let pending;
  try { pending = await api("/templates/pending"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }

  if (!pending.length) {
    root.appendChild(el("div", { class: "card" }, [
      el("h3", { text: "Nothing awaiting review" }),
      el("p", { class: "modal-help", text: "Approving a threat pattern queues a draft for generation; it will appear here once the generation worker has produced it." }),
    ]));
    return;
  }

  for (const draft of pending) {
    const card = el("div", { class: "card" }, [
      el("h3", { text: draft.subject || "(no subject)" }),
      el("p", { class: "modal-help", text: `Model: ${draft.model_id || "unknown"}` }),
    ]);

    if (draft.context_untrusted) {
      // The threat text this was written from tripped the injection
      // neutralizer. The draft is still reviewable, but the reviewer should
      // know the source was manipulated before trusting the framing.
      const warn = el("p", { class: "modal-warn" });
      warn.appendChild(el("strong", { text: "Source context was flagged. " }));
      warn.appendChild(document.createTextNode(
        "The threat report this was generated from contained text the injection filter had to neutralize. Read the wording especially carefully.",
      ));
      card.appendChild(warn);
      if ((draft.neutralization_reasons || []).length) {
        const list = el("ul", { class: "modal-errors" });
        for (const reason of draft.neutralization_reasons) list.appendChild(el("li", { text: reason }));
        card.appendChild(list);
      }
    }

    const body = el("pre", { class: "template-body", text: draft.plain_text || "" });
    card.appendChild(body);

    card.appendChild(el("div", { class: "btn-row" }, [
      el("button", { class: "btn small primary", text: "Approve", onclick: decide(draft, "approved") }),
      el("button", { class: "btn small danger", text: "Reject", onclick: decide(draft, "rejected") }),
    ]));
    root.appendChild(card);
  }

  function decide(draft, decision) {
    return async (e) => {
      const approving = decision === "approved";
      const values = await promptDialog({
        title: `${approving ? "Approve" : "Reject"} generated template`,
        description: draft.subject || "",
        fields: [
          { name: "rationale", label: "Rationale", type: "textarea", required: true,
            placeholder: approving ? "Why this content is safe to use in a simulation" : "What is wrong with it",
            help: "Recorded in the audit chain against your identity." },
        ],
        submitLabel: approving ? "Approve template" : "Reject template",
      });
      if (!values) return;
      const btn = e.target; btn.disabled = true;
      try {
        await api(`/templates/${draft.template_version_id}/decision`, {
          method: "POST",
          body: JSON.stringify({ decision, rationale: values.rationale }),
        });
        toast(`Template ${decision}`, "success");
        render();
      } catch (err) { toast(err.message, "error"); }
      finally { btn.disabled = false; }
    };
  }
};

/* ---------- recipients ---------- */
views.recipients = async (root) => {
  root.appendChild(el("h2", { text: "Recipients" }));
  root.appendChild(el("p", { class: "sub", text: "Import and review training recipients." }));
  root.appendChild(el("div", { class: "btn-row" }, [
    el("button", { class: "btn", type: "button", text: "Sync connected directory", onclick: async (event) => {
      event.target.disabled = true;
      try {
        await api("/recipients/sync-directory", { method: "POST" });
        toast("Directory sync queued. Refresh shortly to see imported recipients.", "success");
      } catch (e) { toast(e.message, "error"); }
      finally { event.target.disabled = false; }
    } }),
  ]));
  let recipients;
  try { recipients = await api("/recipients"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  const csvArea = el("textarea", { id: "r-csv", placeholder: "user@example.com, Jane Doe, Engineering" });
  const filePicker = el("input", { id: "r-file", type: "file", accept: ".csv,text/csv,text/plain" });
  filePicker.addEventListener("change", async () => {
    const file = filePicker.files && filePicker.files[0];
    if (!file) return;
    try {
      csvArea.value = await file.text();
      toast(`Loaded ${file.name}`, "success");
    } catch (err) { toast(`Could not read ${file.name}: ${err.message}`, "error"); }
  });

  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Import CSV" }),
    el("label", { for: "r-file", text: "Choose a CSV file" }),
    filePicker,
    el("p", { class: "modal-help", text: "The file is read in your browser and placed in the box below; nothing is uploaded until you press Import." }),
    el("label", { for: "r-csv", text: "CSV text (mailbox, name, department)" }),
    csvArea,
    el("label", { for: "r-dept", text: "Default department" }),
    el("input", { id: "r-dept", value: "Engineering" }),
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Import", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          const res = await api("/recipients/import", { method: "POST", body: JSON.stringify({
            csv_text: csvArea.value,
            department: document.getElementById("r-dept").value,
          }) });
          showImportResult(res);
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

/* ---------- privacy ---------- */
const PRIVACY_TYPES = ["search", "access_export", "correction", "deletion", "exception"];
const PRIVACY_STATES = ["opened", "in_progress", "fulfilled", "rejected"];

views.privacy = async (root) => {
  root.appendChild(el("h2", { text: "Privacy" }));
  root.appendChild(el("p", { class: "sub", text: "Privacy notice and data-subject requests (CCPA)." }));
  let notice, requests;
  try {
    [notice, requests] = await Promise.all([api("/privacy/notice"), api("/privacy/requests")]);
  } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }

  const noticeCard = el("div", { class: "card" }, [
    el("h3", { text: "Current privacy notice" }),
    el("p", { text: notice ? notice.notice_text : "No current notice published." }),
    el("small", { text: notice ? `version ${notice.version} · effective ${notice.effective_at}` : "" }),
  ]);

  const form = el("div", { class: "card" }, [
    el("h3", { text: "New data-subject request" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [
        el("label", { text: "Request type" }),
        el("select", { id: "pr-type" }, PRIVACY_TYPES.map((t) => el("option", { value: t, text: t }))),
      ]),
      el("div", {}, [
        el("label", { text: "Requester mailbox" }), el("input", { id: "pr-mailbox", type: "email" }),
        el("label", { text: "Campaign ID (optional)" }), el("input", { id: "pr-campaign" }),
      ]),
    ]),
    el("div", { class: "btn-row" }, [
      el("button", { class: "btn primary", text: "Submit request", onclick: async (e) => {
        const btn = e.target; btn.disabled = true;
        try {
          await api("/privacy/requests", { method: "POST", body: JSON.stringify({
            request_type: document.getElementById("pr-type").value,
            requester_mailbox: document.getElementById("pr-mailbox").value,
            campaign_id: document.getElementById("pr-campaign").value || null,
          }) });
          toast("Request submitted", "success");
          location.reload();
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ]),
  ]);

  const rows = requests.map((r) => {
    const actions = el("td", {});
    if (r.status === "opened") {
      actions.appendChild(el("button", { class: "btn small", text: "Verify", onclick: async (e) => {
        const values = await promptDialog({
          title: "Verify data-subject identity",
          description: "Record how this requester's identity was confirmed before any personal data is released.",
          fields: [
            { name: "evidence", label: "Evidence reference", required: true,
              placeholder: "Ticket, IdP sign-in event, or case ID",
              help: "Stored in the audit chain as the justification for releasing or erasing personal data." },
          ],
          submitLabel: "Record verification",
        });
        if (!values) return;
        const evidence = values.evidence;
        e.target.disabled = true;
        try { await api(`/privacy/requests/${r.privacy_request_id}/verify`, { method: "POST", body: JSON.stringify({ method: "operator_verified", evidence_ref: evidence }) }); toast("Verified", "success"); location.reload(); }
        catch (err) { toast(err.message, "error"); }
      } }));
    }
    if (["verified", "in_progress"].includes(r.status) && r.request_type === "access_export") {
      actions.appendChild(el("button", { class: "btn small", text: "Export", onclick: async (e) => {
        e.target.disabled = true;
        try {
          const res = await api(`/privacy/requests/${r.privacy_request_id}/export`);
          const blob = new Blob([JSON.stringify(res, null, 2)], { type: "application/json" });
          const link = document.createElement("a"); link.href = URL.createObjectURL(blob);
          link.download = `privacy-request-${r.privacy_request_id}.json`; link.click(); URL.revokeObjectURL(link.href);
          toast(`Downloaded ${(res.records || []).length} recipient record(s)`, "success");
        } catch (err) { toast(err.message, "error"); }
      } }));
    }
    if (["verified", "in_progress"].includes(r.status) && r.request_type === "deletion") {
      actions.appendChild(el("button", { class: "btn small primary", text: "Fulfill", onclick: async (e) => {
        e.target.disabled = true;
        try { await api(`/privacy/requests/${r.privacy_request_id}/fulfill`, { method: "POST", body: JSON.stringify({}) }); toast("Request fulfilled", "success"); location.reload(); }
        catch (err) { toast(err.message, "error"); }
      } }));
    }
    return el("tr", {}, [
      el("td", { text: r.request_type }),
      el("td", { text: r.requester_mailbox }),
      el("td", { text: r.status }),
      el("td", { text: r.sla_deadline || "" }),
      actions,
    ]);
  });
  const table = el("table", {}, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Type" }), el("th", { text: "Mailbox" }),
      el("th", { text: "Status" }), el("th", { text: "SLA deadline" }), el("th", { text: "Actions" }),
    ])]),
    el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", { class: "empty", colspan: 5, text: "No data-subject requests." })])]),
  ]);

  root.appendChild(noticeCard);
  root.appendChild(form);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Requests" }), table]));
};

/* ---------- sources ---------- */
views.sources = async (root) => {
  root.appendChild(el("h2", { text: "Sources" }));
  root.appendChild(el("p", { class: "sub", text: "Register, enable, and monitor RSS intelligence sources." }));
  let sources;
  try { sources = await api("/sources"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "New source" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [
        el("label", { text: "Name" }), el("input", { id: "s-name" }),
        el("label", { text: "Base domain" }), el("input", { id: "s-domain", value: "example.com" }),
      ]),
      el("div", {}, [
        el("label", { for: "s-type", text: "Source type" }),
        el("select", { id: "s-type" }, ["rss", "stix", "bulk_download"].map((t) => el("option", { value: t, text: t }))),
        el("label", { for: "s-path", text: "Feed path" }), el("input", { id: "s-path", value: "/" }),
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
            fetch_path: document.getElementById("s-path").value,
          }) });
          toast("Source created", "success"); location.reload();
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ]),
  ]));
  const rows = sources.map((source) => el("tr", {}, [
    el("td", { text: source.name }), el("td", { text: `${source.base_domain}${source.fetch_path || "/"}` }),
    el("td", { text: source.enabled ? "enabled" : "disabled" }),
    el("td", { text: source.last_success_at || "never" }),
    el("td", {}, source.enabled ? [] : [el("button", { class: "btn small primary", text: "Enable & ingest", onclick: async (e) => {
      e.target.disabled = true;
      try { await api(`/sources/${source.source_id}/enable`, { method: "POST" }); toast("Ingestion queued", "success"); location.reload(); }
      catch (err) { toast(err.message, "error"); }
    } })]),
  ]));
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Configured sources" }), el("table", {}, [
    el("thead", {}, [el("tr", {}, ["Name", "Domain", "Status", "Last success", "Actions"].map((name) => el("th", { text: name })))]),
    el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", { class: "empty", colspan: 5, text: "No sources." })])]),
  ])]));
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
  let events, kill;
  try { [events, kill] = await Promise.all([api("/audit"), api("/kill-switch")]); }
  catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  const engaged = !!(kill && kill.engaged);
  root.appendChild(el("div", { class: "btn-row" }, [
    el("button", { class: "btn", text: "Verify chain", onclick: async (e) => {
      e.target.disabled = true;
      try {
        const res = await api("/audit/verify", { method: "POST" });
        toast(res.ok ? "Chain OK" : `Problems: ${JSON.stringify(res.problems)}`, res.ok ? "success" : "error");
      } catch (err) { toast(err.message, "error"); }
      finally { e.target.disabled = false; }
    } }),
    el("button", { class: "btn danger", text: engaged ? "Kill switch engaged" : "Engage kill switch", disabled: engaged,
      onclick: async (e) => {
      const ok = await confirmDialog({
        title: "Engage the GLOBAL kill switch?",
        message: "This cancels every queued delivery and revokes every tracking token across all campaigns. It cannot be undone.",
        confirmLabel: "Engage global kill switch", danger: true,
      });
      if (!ok) return;
      e.target.disabled = true;
      try {
        const res = await api("/kill-switch", { method: "POST", body: JSON.stringify({ confirm: true }) });
        toast(`Kill switch engaged: ${res.cancelled} cancelled, ${res.tokens_revoked} tokens revoked`, "success");
        location.reload();
      } catch (err) { toast(err.message, "error"); }
      finally { e.target.disabled = false; }
    } }),
  ]));
  if (engaged) {
    root.appendChild(el("p", { class: "ok", text: `Kill switch engaged by ${kill.actor || "?"}${kill.engaged_at ? ` at ${String(kill.engaged_at).slice(0, 19)}` : ""} — last run cancelled ${kill.last_cancelled ?? 0}, revoked ${kill.last_tokens_revoked ?? 0}.` }));
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
      input.placeholder = "leave blank to keep current";
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
        for (const [key, input] of Object.entries(inputs)) {
          if (cfg.masked[key] && !input.value) continue; // blank secret = keep current
          values[key] = input.value;
        }
        try {
          const res = await api("/console/config", { method: "PUT", body: JSON.stringify({ values }) });
          toast(`Saved. Changed: ${res.changed.length ? res.changed.join(", ") : "none"}`, "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
      el("button", { class: "btn", text: "Reload from disk", onclick: () => { location.reload(); } }),
      el("button", { class: "btn", text: "Restart services", onclick: async (e) => {
        const ok = await confirmDialog({
          title: "Restart all services?",
          message: "The API, workers and tracking endpoint bounce together. In-flight requests are dropped; queued work resumes afterwards.",
          confirmLabel: "Restart services",
        });
        if (!ok) return;
        const btn = e.target; btn.disabled = true;
        try {
          await api("/console/restart", { method: "POST" });
          toast("Restart requested. Services will bounce momentarily.", "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
      el("button", { class: "btn danger", text: "Stop services", onclick: async (e) => {
        const ok = await confirmDialog({
          title: "Stop the whole stack?",
          message: "Everything shuts down, including this console. Nothing in the browser can start it again — you will need shell access on the host to bring it back up.",
          confirmLabel: "Stop services", danger: true,
        });
        if (!ok) return;
        const btn = e.target; btn.disabled = true;
        try {
          await api("/console/stop", { method: "POST" });
          toast("Stop requested. The stack will shut down.", "success");
        } catch (err) { toast(err.message, "error"); }
        finally { btn.disabled = false; }
      } }),
    ]),
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
let oidcSessionChecked = false;
async function render() {
  if (!token() && !oidcSessionChecked) {
    oidcSessionChecked = true;
    try {
      const resp = await fetch(`${API}/console/session`, { credentials: "same-origin" });
      if (resp.ok) {
        const data = await resp.json();
        setSessionInfo({ authMode: data.auth_mode, principalId: data.principal_id, approvalLimited: false, approvalPolicy: data.approval_policy || "single-admin" });
        onboardingChecked = false;
      }
    } catch { /* Render login below. */ }
  }
  if (!token() && !sessionInfo()) { views.login(document.getElementById("app")); return; }
  if (!onboardingChecked) {
    onboardingChecked = true;
    try {
      const onboarding = await api("/console/onboarding");
      if (!onboarding.complete) location.hash = "onboarding";
    } catch (e) { toast(`Unable to check setup status: ${e.message}`, "error"); }
    if (!token() && !sessionInfo()) return;
  }
  shell();
}

/* ---------- live refresh ----------
   Campaign state advances on its own: workers deliver, recipients open and
   click, the reconciler closes windows. Without this an operator watches a
   frozen page and cannot tell "nothing happened" from "nothing refreshed".
   Refresh pauses while a dialog is open so it cannot yank a form away
   mid-edit, and while the tab is hidden so a backgrounded console is not
   polling all night. */
const LIVE_VIEWS = new Set(["dashboard", "campaigns"]);
const REFRESH_MS = 30000;
let refreshTimer = null;

function currentView() {
  return (location.hash || "#dashboard").slice(1).split("?")[0];
}

function stampLastUpdated() {
  const node = document.getElementById("last-updated");
  if (node) node.textContent = `Updated ${new Date().toLocaleTimeString()}`;
}

function scheduleRefresh() {
  if (refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(() => {
    if (!LIVE_VIEWS.has(currentView())) return;
    if (document.hidden) return;
    if (document.querySelector("dialog[open]")) return;
    if (!token() && !sessionInfo()) return;
    render();
  }, REFRESH_MS);
}

window.addEventListener("hashchange", render);
document.addEventListener("visibilitychange", () => { if (!document.hidden && LIVE_VIEWS.has(currentView())) render(); });
scheduleRefresh();
render();

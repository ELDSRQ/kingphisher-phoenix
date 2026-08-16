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
      });
      toast("Signed in", "success");
      render();
    } catch (e) { err.textContent = e.message; }
  };
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
      el("td", { class: "mono", text: formatInstant(c.schedule_start) }),
      el("td", { class: "mono", text: formatInstant(c.schedule_end) }),
    ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 4, text: "No campaigns yet." })])]),
  ]);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Campaigns" }), table]));
};

/* ---------- campaigns ---------- */
views.campaigns = async (root) => {
  root.appendChild(el("h2", { text: "Campaigns" }));
  root.appendChild(el("p", { class: "sub", text: "Create, approve, schedule and manage campaigns." }));
  if (sessionInfo()?.approvalLimited) {
    root.appendChild(el("div", { class: "notice", role: "note" }, [
      el("strong", { text: "Development identity limitation. " }),
      el("span", { text: "Password login uses one fixed identity. It cannot approve a campaign it created. Use separately authenticated security and privacy approvers through the configured identity provider; self-approval remains prohibited." }),
    ]));
  }

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
        el("label", { for: "c-tdomain", text: "Training domain" }), el("input", { id: "c-tdomain", value: "training.local" }),
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
      el("th", { text: "Title" }), el("th", { text: "State" }), el("th", { text: "Actions" }),
    ])]),
    el("tbody", {}, campaigns.map((c) => el("tr", {}, [
      el("td", { text: c.title }),
      el("td", { text: c.state }),
      el("td", {}, (() => {
        const actions = [];
        if (c.state === "draft") actions.push(el("button", { class: "btn small", text: "Submit", onclick: act(`/campaigns/${c.campaign_id}/submit`, "Submitted") }));
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
          if (!confirm(`Scoped kill switch for "${c.title}"? Revokes this campaign's queued deliveries and tracking tokens.`)) return;
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
            const report = await api(`/campaigns/${c.campaign_id}/report`);
            const sent = report.send_counts.delivered || 0;
            const opened = report.event_counts.opened || 0;
            const clicked = report.event_counts.clicked || 0;
            toast(`Delivered ${sent} · Opened ${opened} · Clicked ${clicked}`, "success");
          } catch (err) { toast(err.message, "error"); }
          finally { e.target.disabled = false; }
        } }));
        actions.push(el("button", { class: "btn small", text: "Add alert", onclick: async (e) => {
          const channel = prompt("Alert channel: webhook", "webhook");
          if (!channel) return;
          const destination = prompt("HTTPS webhook destination URL:");
          if (!destination) return;
          e.target.disabled = true;
          try {
            const result = await api("/alerts/subscriptions", { method: "POST", body: JSON.stringify({
              campaign_id: c.campaign_id, channel: channel.trim().toLowerCase(), destination_url: destination.trim(),
            }) });
            if (result.signing_secret) {
              prompt("Copy this signing secret now; it will not be displayed again:", result.signing_secret);
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
      const rationale = prompt(`${decision === "approved" ? "Approval" : "Rejection"} rationale for ${approvalType} review:`);
      if (rationale === null) return;
      if (!rationale.trim()) { toast("A rationale is required", "error"); return; }
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
      const start = formatInstant(campaign.schedule_start);
      const end = formatInstant(campaign.schedule_end);
      if (!confirm(`Schedule "${campaign.title}"?\n\nStart: ${start}\nEnd: ${end}\n\nThese are shown in ${browserTimeZone()}.`)) return;
      return act(`/campaigns/${campaign.campaign_id}/schedule`, "Scheduled")(e);
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
        const evidence = prompt("Verification evidence reference (ticket, IdP event, or case ID):");
        if (!evidence || !evidence.trim()) { toast("Verification evidence is required", "error"); return; }
        e.target.disabled = true;
        try { await api(`/privacy/requests/${r.privacy_request_id}/verify`, { method: "POST", body: JSON.stringify({ method: "operator_verified", evidence_ref: evidence.trim() }) }); toast("Verified", "success"); location.reload(); }
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
      if (!confirm("Engage the global kill switch? This cancels ALL queued deliveries and revokes ALL tracking tokens.")) return;
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
        setSessionInfo({ authMode: data.auth_mode, principalId: data.principal_id, approvalLimited: false });
        shell();
        return;
      }
    } catch { /* Render login below. */ }
  }
  if (!token() && !sessionInfo()) { views.login(document.getElementById("app")); return; }
  shell();
}

window.addEventListener("hashchange", render);
render();

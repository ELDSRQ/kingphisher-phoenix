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
  lastRenderedView = null;
}

const CAPABILITY = Object.freeze({
  APPROVE_SECURITY: "approve_security:campaign",
  APPROVE_PRIVACY: "approve_privacy:campaign",
  CREATE_CAMPAIGN: "create:campaign",
  SCHEDULE_CAMPAIGN: "schedule:campaign",
  STOP_CAMPAIGN: "stop:campaign",
  SEND_CAMPAIGN: "send:campaign",
  MANAGE_SOURCES: "manage:source",
  SUBMIT_SOURCE: "submit:source",
  VIEW_NAMED_RESULTS: "view_named:results",
  VIEW_AGGREGATE: "view_aggregate:results",
  EXPORT_BULK: "export_bulk:results",
  VIEW_AUDIT: "view:audit",
  MANAGE_RECIPIENTS: "manage:recipients",
  MANAGE_EXCLUSIONS: "manage:exclusions",
  HANDLE_PRIVACY: "handle:privacy_requests",
  DELETE_DATA: "delete:data",
  APPROVE_PATTERN: "approve:pattern",
  APPROVE_TEMPLATE: "approve:template",
  MANAGE_ROLES: "manage:roles",
  USE_KILL_SWITCH: "use:kill_switch",
  SUBSCRIBE_ALERTS: "subscribe:alerts",
  VERIFY_DOMAIN: "verify:sending_domain",
  SIGN_ROE: "sign:rules_of_engagement",
  MANAGE_QUEUE: "manage:job_queue",
});
const KNOWN_CAPABILITIES = new Set(Object.values(CAPABILITY));
const KNOWN_ROLES = new Set([
  "source_curator", "campaign_author", "security_approver", "privacy_approver",
  "campaign_operator", "auditor", "administrator",
]);

function hasValidSessionAuthority(info = sessionInfo()) {
  return Boolean(info && Array.isArray(info.roles) && Array.isArray(info.capabilities)
    && info.roles.every((role) => typeof role === "string" && KNOWN_ROLES.has(role))
    && info.capabilities.every((capability) => (
      typeof capability === "string" && KNOWN_CAPABILITIES.has(capability)
    )));
}

function hasCapability(capability) {
  const info = sessionInfo();
  return hasValidSessionAuthority(info) && info.capabilities.includes(capability);
}

function hasAnyCapability(...capabilities) {
  return capabilities.some((capability) => hasCapability(capability));
}

function requireAnyCapability(root, ...capabilities) {
  if (hasAnyCapability(...capabilities)) return true;
  root.replaceChildren(el("div", { class: "card", role: "status" }, [
    el("h2", { text: "This view is not available for your role" }),
    el("p", { text: "The console hides actions your authenticated account cannot perform. Ask an administrator for the required role if this access is expected." }),
  ]));
  return false;
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const resp = await fetch(`${API}${path}`, { ...options, cache: "no-store", headers });
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
    const error = new Error(detail || `${resp.status} ${resp.statusText}`);
    error.status = resp.status;
    error.body = body;
    throw error;
  }
  return body;
}

const MAX_CSV_DOWNLOAD_BYTES = 5 * 1024 * 1024;
const MAX_RECIPIENT_CSV_BYTES = 512 * 1024;
const MAX_RECIPIENT_CSV_ROWS = 5000;

function validateRecipientCsvText(csvText) {
  if (!csvText.trim()) throw new Error("CSV text is required");
  if (new TextEncoder().encode(csvText).byteLength > MAX_RECIPIENT_CSV_BYTES) {
    throw new Error("Recipient CSV exceeds the 512 KiB browser limit");
  }
  if (csvText.split(/\r\n|\r|\n/).length > MAX_RECIPIENT_CSV_ROWS) {
    throw new Error("Recipient CSV exceeds the 5,000-row browser limit");
  }
  return csvText;
}

async function boundedCsvBlob(response) {
  const contentType = (response.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== "text/csv") throw new Error("Export returned an unexpected content type");
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    if (!/^\d{1,10}$/.test(declared) || Number(declared) > MAX_CSV_DOWNLOAD_BYTES) {
      throw new Error("Export exceeded the 5 MB download limit");
    }
  }
  if (!response.body) throw new Error("Export returned no downloadable content");
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > MAX_CSV_DOWNLOAD_BYTES) {
      await reader.cancel();
      throw new Error("Export exceeded the 5 MB download limit");
    }
    chunks.push(value);
  }
  return new Blob(chunks, { type: "text/csv" });
}

async function downloadApiCsv(path, filename) {
  if (!path.startsWith("/analytics/campaigns/") || !path.includes(".csv") || path.includes("://") || /[\r\n]/.test(path)) {
    throw new Error("Export path is not allowed");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.csv$/.test(filename)) {
    throw new Error("Export filename is not allowed");
  }
  const headers = { Accept: "text/csv" };
  if (token()) headers.Authorization = `Bearer ${token()}`;
  const response = await fetch(`${API}${path}`, { headers, credentials: "same-origin", cache: "no-store" });
  if (response.status === 401) {
    clearToken();
    render();
    throw new Error("Session expired");
  }
  if (!response.ok) throw new Error(`Export failed (${response.status})`);
  const blob = await boundedCsvBlob(response);
  const url = URL.createObjectURL(blob);
  try {
    const link = el("a", { href: url, download: filename });
    document.body.appendChild(link);
    link.click();
    link.remove();
  } finally {
    URL.revokeObjectURL(url);
  }
}

/* ---------- state ---------- */
let onboardingChecked = false;
let lastRenderedView = null;
const views = {};

function toast(message, type = "") {
  const notice = document.createElement("div");
  notice.className = `toast ${type}`;
  notice.setAttribute("role", type === "error" ? "alert" : "status");
  notice.setAttribute("aria-live", type === "error" ? "assertive" : "polite");
  notice.setAttribute("aria-atomic", "true");
  notice.appendChild(el("span", { text: message }));
  notice.appendChild(el("button", {
    class: "toast-dismiss", type: "button", text: "Dismiss",
    "aria-label": "Dismiss notification", onclick: () => notice.remove(),
  }));
  document.body.appendChild(notice);
  // Errors need to remain available for review instead of disappearing while
  // an operator is reading a campaign or deployment failure.
  if (type !== "error") setTimeout(() => notice.remove(), 5000);
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

const CAMPAIGN_ACTION_FLAGS = Object.freeze([
  "can_configure_audience", "can_configure_training", "can_submit", "can_approve_security",
  "can_approve_privacy", "can_schedule", "can_publish", "can_test_send", "can_recall",
]);
const PATTERN_ACTION_FLAGS = Object.freeze(["can_clone", "can_approve"]);
const STALE_ACTION_STATUSES = new Set([403, 409]);

function hasBooleanActionFlags(resource, requiredFlags) {
  return Boolean(resource && typeof resource === "object"
    && requiredFlags.every((flag) => typeof resource[flag] === "boolean"));
}

function actionAuthorityUnavailable(resourceType, refreshAction) {
  return el("div", { class: "modal-warn", role: "alert" }, [
    el("span", {
      text: `${resourceType} action authority could not be verified. Mutable actions are hidden. `,
    }),
    el("button", {
      class: "btn small", type: "button", text: "Refresh actions", onclick: refreshAction,
    }),
  ]);
}

async function refreshAfterStaleActionFailure(error, refreshAction) {
  if (!STALE_ACTION_STATUSES.has(error?.status)) return false;
  toast("Action authority or lifecycle changed. Refreshing the server-derived controls.", "error");
  await refreshAction();
  return true;
}

const COLLECTION_PAGE_SIZE = 100;
const COLLECTION_MAX_ITEMS = 1000;
const COLLECTION_MAX_REQUESTS = (COLLECTION_MAX_ITEMS / COLLECTION_PAGE_SIZE) + 1;

function collectionPagePath(path, offset) {
  const separator = path.indexOf("?");
  const pathname = separator === -1 ? path : path.slice(0, separator);
  const params = new URLSearchParams(separator === -1 ? "" : path.slice(separator + 1));
  params.set("limit", String(COLLECTION_PAGE_SIZE));
  params.set("offset", String(offset));
  return `${pathname}?${params.toString()}`;
}

async function boundedCollection(path, responseKey = null) {
  const items = [];
  for (let requestCount = 0; requestCount < COLLECTION_MAX_REQUESTS; requestCount += 1) {
    const offset = requestCount * COLLECTION_PAGE_SIZE;
    const payload = await api(collectionPagePath(path, offset));
    const page = responseKey === null ? payload : payload?.[responseKey];
    if (!Array.isArray(page) || page.length > COLLECTION_PAGE_SIZE) {
      throw new Error("The server returned an invalid bounded collection page");
    }
    if (offset >= COLLECTION_MAX_ITEMS) {
      if (page.length) {
        throw new Error(
          `This collection exceeds the ${COLLECTION_MAX_ITEMS}-item console boundary. Narrow the filters and retry.`,
        );
      }
      return items;
    }
    items.push(...page);
    if (page.length < COLLECTION_PAGE_SIZE) return items;
  }
  throw new Error("The bounded collection could not be completed");
}

function collectionLoadError(message, retryAction) {
  return el("div", { class: "modal-warn", role: "alert" }, [
    el("span", { text: `${message} ` }),
    el("button", { class: "btn small", type: "button", text: "Retry", onclick: retryAction }),
  ]);
}

/* ---------- dialogs ----------
   Real <dialog> modals instead of prompt()/confirm(): those cannot be styled,
   cannot show more than one field, cannot explain a rule, and are suppressed
   entirely by some browsers. Everything here is textContent only — no
   innerHTML anywhere in this console, ever. */

let dialogSequence = 0;

function openDialog(node) {
  const returnFocus = document.activeElement;
  document.body.appendChild(node);
  node.addEventListener("close", () => {
    node.remove();
    if (returnFocus instanceof HTMLElement && returnFocus.isConnected) returnFocus.focus();
  });
  node.showModal();
  const focusable = node.querySelector("input, select, textarea, button.primary, button");
  if (focusable) focusable.focus();
  return node;
}

function dialogShell(title, description) {
  dialogSequence += 1;
  const titleId = `dialog-title-${dialogSequence}`;
  const descriptionId = `dialog-description-${dialogSequence}`;
  const dlg = el("dialog", {
    class: "modal", "aria-labelledby": titleId,
    "aria-describedby": description ? descriptionId : null,
  });
  const form = el("form", { class: "modal-form" });
  form.appendChild(el("h3", { id: titleId, class: "modal-title", text: title }));
  if (description) form.appendChild(el("p", { id: descriptionId, class: "modal-desc", text: description }));
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

function guardUnsavedForm(container, label) {
  container.setAttribute("data-refresh-guard", label);
  container.setAttribute("data-dirty", "false");
  container.addEventListener("input", () => markFormDirty(container));
  container.addEventListener("change", () => markFormDirty(container));
  return container;
}

function markFormDirty(container) {
  container.setAttribute("data-dirty", "true");
  const status = document.getElementById("last-updated");
  if (status) status.textContent = "Unsaved changes — automatic refresh paused";
}

function markFormSaved(container) {
  container.setAttribute("data-dirty", "false");
  if (!currentUnsavedForm()) {
    const status = document.getElementById("last-updated");
    if (status) status.textContent = "Changes saved — automatic refresh available";
  }
}

function currentUnsavedForm() {
  return document.querySelector('[data-refresh-guard][data-dirty="true"]');
}

async function confirmDiscardUnsaved(container) {
  if (container?.getAttribute("data-dirty") !== "true") return true;
  const confirmed = await confirmDialog({
    title: "Discard unsaved changes?",
    message: "Values on this screen have not been saved. Leave only if you are ready to re-enter them.",
    confirmLabel: "Discard changes",
    danger: true,
  });
  if (confirmed) markFormSaved(container);
  return confirmed;
}

async function navigateTo(viewId) {
  if (currentView() === viewId) return;
  const dirtyForm = currentUnsavedForm();
  if (dirtyForm && !await confirmDiscardUnsaved(dirtyForm)) return;
  location.hash = viewId;
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
        input = el("textarea", { id, name: field.name, rows: "3", maxlength: field.maxLength, placeholder: field.placeholder || "" });
        input.value = field.value || "";
      } else {
        input = el("input", { id, name: field.name, type: field.type || "text", maxlength: field.maxLength, placeholder: field.placeholder || "" });
        input.value = field.value || "";
      }
      inputs[field.name] = input;
      form.appendChild(input);
      if (field.help) {
        const helpId = `${id}-help`;
        input.setAttribute("aria-describedby", helpId);
        form.appendChild(el("p", { id: helpId, class: "modal-help", text: field.help }));
      }
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
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      submit();
    });
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Cancel", onclick: cancel }),
      el("button", { class: "btn primary", type: "submit", text: submitLabel }),
    ]));
    dlg.addEventListener("close", () => { if (!decided) resolve(null); });
    openDialog(dlg);
  });
}

/* A value shown exactly once (a signing secret). prompt() was being used for
   this, which is not selectable on every browser and looks like an input. */
function showCopyable({ title, description, value }) {
  const { dlg, form } = dialogShell(title, description);
  const box = el("textarea", {
    class: "modal-copyable", rows: "3", readonly: "readonly",
    "aria-label": "One-time value to copy",
  });
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

/* ---------- campaign analytics ----------
   This surface uses the privacy-minimized reporting projection. Provider
   acceptance and destination-MTA handoff are transport evidence, never a
   claim of inbox placement or human engagement. */

const ANALYTICS_LABELS = {
  targeted: "Targeted assignments",
  sent: "Provider attempts",
  accepted: "Provider-accepted handoffs",
  delivered: "Destination MTA handoffs",
  failed: "Failed",
  indeterminate: "Indeterminate",
  opened: "Opened",
  clicked: "Clicked",
  reported: "Reported",
  training_assigned: "Training assigned",
  training_completed: "Training completed",
};

function analyticsQuery(evidenceStart, evidenceEnd) {
  if (Boolean(evidenceStart) !== Boolean(evidenceEnd)) {
    throw new Error("Enter both evidence-window timestamps, or leave both blank");
  }
  const params = new URLSearchParams();
  if (evidenceStart) {
    params.set("evidence_start", evidenceStart);
    params.set("evidence_end", evidenceEnd);
  }
  const query = params.toString();
  return query ? `?${query}` : "";
}

function analyticsTable(metrics, label) {
  return el("table", { class: "report-table", "aria-label": label }, [
    el("tbody", {}, metrics.map((metric) => el("tr", {}, [
      el("td", { text: ANALYTICS_LABELS[metric.name] || metric.name }),
      el("td", { class: "num", text: String(metric.value) }),
    ]))),
  ]);
}

function analyticsRateTable(rates) {
  return el("table", { class: "report-table", "aria-label": "Campaign rates and denominators" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Measure" }),
      el("th", { text: "Numerator" }),
      el("th", { text: "Denominator" }),
      el("th", { text: "Rate" }),
    ])]),
    el("tbody", {}, rates.map((rate) => el("tr", {}, [
      el("td", { text: ANALYTICS_LABELS[rate.name] || rate.name }),
      el("td", { class: "num", text: String(rate.numerator) }),
      el("td", {}, [
        el("div", { class: "num", text: String(rate.denominator) }),
        el("div", { class: "modal-help", text: rate.denominator_name }),
      ]),
      el("td", { class: "num", text: rate.value === null ? "N/A" : `${(rate.value * 100).toFixed(1)}%` }),
    ]))),
  ]);
}

function boundedRecipientPage(payload, requestedLimit) {
  const valid = payload && Array.isArray(payload.items)
    && Number.isInteger(payload.total) && payload.total >= 0
    && Number.isInteger(payload.limit) && payload.limit >= 1 && payload.limit <= requestedLimit
    && Number.isInteger(payload.offset) && payload.offset >= 0
    && typeof payload.truncated === "boolean"
    && payload.items.length <= payload.limit;
  if (!valid) throw new Error("The server returned an invalid bounded recipient page");
  return payload;
}

async function openCampaignAnalytics(campaign, evidenceStart = "", evidenceEnd = "") {
  const query = analyticsQuery(evidenceStart.trim(), evidenceEnd.trim());
  const canViewNamedResults = hasCapability(CAPABILITY.VIEW_NAMED_RESULTS);
  const [report, operational, namedResults] = await Promise.all([
    api(`/analytics/campaigns/${campaign.campaign_id}/funnel${query}`),
    api(`/campaigns/${campaign.campaign_id}/report`),
    canViewNamedResults
      ? api(`/campaigns/${campaign.campaign_id}/recipients?limit=500&offset=0`)
        .then((payload) => boundedRecipientPage(payload, 500))
      : Promise.resolve(null),
  ]);
  const { dlg, form } = dialogShell(
    campaign.title || "Campaign analytics",
    `Aggregate evidence generated ${new Date(report.generated_at).toLocaleString()}`,
  );

  const start = el("input", {
    type: "text", name: "evidence_start", placeholder: "2026-01-01T00:00:00Z",
    value: report.evidence_window?.start_inclusive || evidenceStart,
  });
  const end = el("input", {
    type: "text", name: "evidence_end", placeholder: "2026-02-01T00:00:00Z",
    value: report.evidence_window?.end_exclusive || evidenceEnd,
  });
  form.appendChild(el("h4", { class: "modal-section", text: "Evidence window (optional)" }));
  form.appendChild(el("p", { class: "modal-help", text: "Use RFC 3339 timestamps with a timezone. Start is inclusive; end is exclusive; maximum 366 days. The window limits engagement and training-completion evidence only. Transport remains a current snapshot." }));
  form.appendChild(el("div", { class: "form-grid" }, [
    el("label", {}, [el("span", { text: "Start (UTC recommended)" }), start]),
    el("label", {}, [el("span", { text: "End (UTC recommended)" }), end]),
  ]));
  form.appendChild(el("button", { class: "btn small", type: "button", text: "Apply evidence window", onclick: async (event) => {
    event.target.disabled = true;
    try {
      const nextStart = start.value.trim();
      const nextEnd = end.value.trim();
      analyticsQuery(nextStart, nextEnd);
      dlg.close();
      await openCampaignAnalytics(campaign, nextStart, nextEnd);
    } catch (err) {
      toast(err.message, "error");
      event.target.disabled = false;
    }
  } }));

  form.appendChild(el("h4", { class: "modal-section", text: "Transport states" }));
  form.appendChild(analyticsTable(report.transport, "Aggregate campaign transport states"));
  form.appendChild(el("p", { class: "modal-help", text: "Accepted means the provider acknowledged handoff. Delivered means destination MTA handoff; not inbox placement, display, or reading. Indeterminate outcomes are not silently treated as failures or retried." }));
  form.appendChild(el("h4", { class: "modal-section", text: "Engagement" }));
  form.appendChild(analyticsTable(report.engagement, "Aggregate campaign engagement"));
  form.appendChild(el("h4", { class: "modal-section", text: "Training" }));
  form.appendChild(analyticsTable(report.training, "Aggregate campaign training outcomes"));
  form.appendChild(el("h4", { class: "modal-section", text: "Rates and denominators" }));
  form.appendChild(analyticsRateTable(report.rates));
  form.appendChild(el("p", { class: "modal-help", text: "N/A means the denominator is zero. The API returns aggregate counts only; no recipient identifiers or recipient attributes are included." }));

  form.appendChild(el("h4", { class: "modal-section", text: "Operational delivery report" }));
  form.appendChild(el("table", { class: "report-table", "aria-label": "Aggregate operational campaign report" }, [
    el("tbody", {}, [
      el("tr", {}, [el("td", { text: "Campaign state" }), el("td", { text: operational.state })]),
      el("tr", {}, [el("td", { text: "Prepared recipients" }), el("td", { class: "num", text: String(operational.recipients) })]),
      el("tr", {}, [el("td", { text: "Reported-mail status" }), el("td", { text: operational.reported_mail_pipeline.mailbox_status })]),
      el("tr", {}, [el("td", { text: "Correlated deliveries" }), el("td", { class: "num", text: String(operational.reported_mail_pipeline.correlated_deliveries) })]),
      el("tr", {}, [el("td", { text: "Validated reports" }), el("td", { class: "num", text: String(operational.reported_mail_pipeline.reports_validated) })]),
    ]),
  ]));
  const sendStates = Object.entries(operational.send_counts || {});
  form.appendChild(el("h4", { class: "modal-section", text: "Send outcomes" }));
  form.appendChild(el("table", { class: "report-table", "aria-label": "Aggregate send outcomes" }, [
    el("tbody", {}, sendStates.map(([name, value]) => el("tr", {}, [
      el("td", { text: name.replaceAll("_", " ") }),
      el("td", { class: "num", text: String(value) }),
    ]))),
  ]));
  const failures = Object.entries(operational.failure_reasons || {});
  form.appendChild(el("h4", { class: "modal-section", text: "Failure reasons" }));
  form.appendChild(failures.length ? el("table", { class: "report-table", "aria-label": "Aggregate failure reasons" }, [
    el("tbody", {}, failures.map(([name, value]) => el("tr", {}, [
      el("td", { text: name.replaceAll("_", " ") }),
      el("td", { class: "num", text: String(value) }),
    ]))),
  ]) : el("p", { class: "empty", text: "No failed delivery reasons are recorded." }));

  if (canViewNamedResults && namedResults !== null) {
    const visibleResults = namedResults.items;
    form.appendChild(el("h4", { class: "modal-section", text: "Recipient outcomes" }));
    if (namedResults.truncated) form.appendChild(el("p", {
      class: "modal-warn", role: "status",
      text: `Showing the first ${visibleResults.length} of ${namedResults.total} recipient outcomes. Named browser reporting is deliberately limited to this bounded page.`,
    }));
    form.appendChild(el("table", { class: "report-table", "aria-label": "Capability-protected recipient outcomes" }, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "Recipient reference" }), el("th", { text: "Department" }),
        el("th", { text: "Send state" }), el("th", { text: "Failure" }),
        el("th", { text: "Opened" }), el("th", { text: "Clicked" }), el("th", { text: "Reported" }),
        el("th", { text: "Confirmed" }), el("th", { text: "Close disposition" }),
        el("th", { text: "Training" }),
      ])]),
      el("tbody", {}, visibleResults.length ? visibleResults.map((result) => el("tr", {}, [
        el("td", { class: "mono", text: String(result.recipient_id || "").slice(0, 8) }),
        el("td", { text: result.department || "No department" }),
        el("td", { text: result.send_state }),
        el("td", { text: result.failure_reason || "None" }),
        el("td", { text: result.opened ? "Yes" : "No" }),
        el("td", { text: result.clicked ? "Yes" : "No" }),
        el("td", { text: result.reported ? "Yes" : "No" }),
        el("td", { text: result.confirmed_interaction ? "Yes" : "No" }),
        el("td", {
          class: "num",
          text: result.close_disposition
            ? result.close_disposition.replaceAll("_", " ")
            : "Campaign not closed",
        }),
        el("td", { text: result.training_state || "Not assigned" }),
      ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 10, text: "No recipient outcomes are recorded." })])]),
    ]));
  }

  const actions = [];
  if (hasCapability(CAPABILITY.SCHEDULE_CAMPAIGN)) actions.push(
    el("button", { class: "btn", type: "button", text: "Send due reminders", onclick: async (event) => {
      event.target.disabled = true;
      try {
        const result = await api(`/campaigns/${campaign.campaign_id}/training/reminders`, { method: "POST" });
        toast(result.queued ? `Queued reminders for ${result.due} learner${result.due === 1 ? "" : "s"}` : "No reminders are due", "success");
      } catch (err) { toast(err.message, "error"); }
      finally { event.target.disabled = false; }
    } }),
  );
  if (hasCapability(CAPABILITY.EXPORT_BULK)) actions.push(
    el("button", { class: "btn", type: "button", text: "Download aggregate CSV", onclick: async (event) => {
      event.target.disabled = true;
      try { await downloadAnalyticsCsv(campaign.campaign_id, start.value.trim(), end.value.trim()); }
      catch (err) { toast(err.message, "error"); }
      finally { event.target.disabled = false; }
    } }),
  );
  actions.push(el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => dlg.close() }));
  form.appendChild(el("div", { class: "modal-actions" }, actions));
  openDialog(dlg);
}

/* The CSV route is authenticated, so a plain link would 401. */
async function downloadAnalyticsCsv(campaignId, evidenceStart, evidenceEnd) {
  const query = analyticsQuery(evidenceStart, evidenceEnd);
  await downloadApiCsv(
    `/analytics/campaigns/${campaignId}/funnel.csv${query}`,
    `campaign-${campaignId}-analytics.csv`,
  );
}

/* Reviewed import outcomes contain counts and bounded row-number/error codes,
   never CSV values or recipient PII. */
function showImportResult(res) {
  const counts = res.counts || {};
  const errors = res.errors || [];
  const { dlg, form } = dialogShell("Import complete", null);

  form.appendChild(el("table", { class: "report-table" }, [
    el("tbody", {}, [
      el("tr", {}, [el("td", { text: "Created" }), el("td", { class: "num", text: String(counts.created || 0) })]),
      el("tr", {}, [el("td", { text: "Updated" }), el("td", { class: "num", text: String(counts.updateable || 0) })]),
      el("tr", {}, [el("td", { text: "Already present" }), el("td", { class: "num", text: String(counts.existing || 0) })]),
      el("tr", {}, [el("td", { text: "Deactivated" }), el("td", { class: "num", text: String(counts.deactivateable || 0) })]),
      el("tr", {}, [el("td", { text: "Blocked by domain policy" }), el("td", { class: "num", text: String(counts.blocked || 0) })]),
    ]),
  ]));

  if (counts.blocked) {
    form.appendChild(el("p", { class: "modal-warn", text: "Blocked rows are outside the recipient domains this deployment is allowed to mail. Nothing was sent to them and no record was created." }));
  }
  if (errors.length) {
    form.appendChild(el("h4", { class: "modal-section", text: "Rows not imported" }));
    const list = el("ul", { class: "modal-errors" });
    for (const issue of errors) list.appendChild(el("li", { text: `Row ${issue.row}: ${issue.code}` }));
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

function formatUtcInstant(value) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return "Invalid UTC date";
  return parsed.toISOString();
}

/* ---------- login ---------- */
views.login = async (root) => {
  document.title = "Sign in — Kingphisher-Phoenix Operator Console";
  const err = el("div", {
    id: "login-error", class: "login-error", role: "alert", "aria-live": "assertive",
  });
  const password = el("input", {
    id: "console-password", type: "password", required: "required",
    placeholder: "Console password", autocomplete: "current-password",
    "aria-describedby": "login-error login-hint",
  });
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
        roles: data.roles,
        capabilities: data.capabilities,
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
  const hint = el("p", { id: "login-hint", class: "login-hint", hidden: true, text: "Local development uses KP_CONSOLE_PASSWORD from .env. Managed Azure uses Microsoft identity sign-in and disables password login. See RUNBOOK section 2.1." });
  let authMode;
  try {
    const resp = await fetch(`${API}/console/auth-mode`);
    if (!resp.ok) throw new Error("Authentication mode is unavailable");
    authMode = (await resp.json()).auth_mode;
    if (!new Set(["dev", "oidc"]).has(authMode)) throw new Error("Authentication mode is invalid");
  } catch {
    root.replaceChildren(el("div", { class: "login-wrap" }, [
      el("div", { class: "login-card", "aria-labelledby": "login-title" }, [
        el("h1", { id: "login-title", text: "Kingphisher-Phoenix" }),
        el("p", { text: "Unable to determine the configured sign-in method. No password was submitted." }),
        el("button", { class: "btn primary", type: "button", onclick: render, text: "Retry" }),
      ]),
    ]));
    return;
  }
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
    el("div", { class: "login-card", "aria-labelledby": "login-title" }, [
      el("h1", { id: "login-title", text: "Kingphisher-Phoenix" }),
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
  ["programs", "Programs"],
  ["trends", "Executive trends"],
  ["sending", "Domains & RoE"],
  ["recipients", "Recipients"],
  ["sources", "Sources"],
  ["patterns", "Patterns"],
  ["templates", "Template review"],
  ["training", "Training lessons"],
  ["privacy", "Privacy"],
  ["queues", "Failed jobs"],
  ["audit", "Audit"],
  ["settings", "Settings"],
];

const NAV_CAPABILITIES = Object.freeze({
  onboarding: [CAPABILITY.MANAGE_ROLES],
  "azure-deployment": [CAPABILITY.MANAGE_ROLES],
  help: [CAPABILITY.VIEW_AGGREGATE],
  dashboard: [CAPABILITY.VIEW_AGGREGATE, CAPABILITY.VIEW_AUDIT],
  campaigns: [CAPABILITY.VIEW_AGGREGATE],
  programs: [CAPABILITY.VIEW_AGGREGATE],
  trends: [CAPABILITY.VIEW_AGGREGATE],
  sending: [CAPABILITY.VERIFY_DOMAIN, CAPABILITY.SIGN_ROE],
  recipients: [CAPABILITY.VIEW_NAMED_RESULTS, CAPABILITY.MANAGE_RECIPIENTS, CAPABILITY.MANAGE_EXCLUSIONS],
  sources: [CAPABILITY.MANAGE_SOURCES],
  patterns: [CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_PATTERN],
  templates: [CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_TEMPLATE],
  training: [CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_TEMPLATE],
  privacy: [CAPABILITY.HANDLE_PRIVACY],
  queues: [CAPABILITY.MANAGE_QUEUE],
  audit: [CAPABILITY.VIEW_AUDIT],
  settings: [CAPABILITY.MANAGE_ROLES],
});

function visibleNavigation() {
  return NAV.filter(([id]) => canNavigateTo(id));
}

function canNavigateTo(viewId) {
  if (!NAV.some(([id]) => id === viewId)) return false;
  const required = NAV_CAPABILITIES[viewId];
  return !required || hasAnyCapability(...required);
}

function shell() {
  const visible = visibleNavigation();
  const requested = location.hash.slice(1) || "dashboard";
  const active = visible.find(([id]) => id === requested)?.[0]
    || visible.find(([id]) => id === "help")?.[0]
    || visible[0]?.[0];
  const activeLabel = visible.find(([id]) => id === active)?.[1] || "Operator console";
  document.title = `${activeLabel} — Kingphisher-Phoenix Operator Console`;
  const viewChanged = active !== lastRenderedView;
  lastRenderedView = active;
  const nav = el("nav", { "aria-label": "Operator sections" });
  for (const [id, label] of visible) {
    nav.appendChild(el("button", {
      type: "button",
      class: id === active ? "active" : "",
      "aria-current": id === active ? "page" : null,
      text: label,
      onclick: () => navigateTo(id),
    }));
  }
  const content = el("div", {
    id: "console-view", class: "content", role: "region", tabindex: "-1", "aria-label": `${activeLabel} view`,
  });
  const info = sessionInfo();
  const root = el("div", { class: "shell" }, [
    el("aside", { class: "sidebar", "aria-label": "Operator console navigation" }, [
      el("div", { class: "brand" }, [
        el("img", { src: "/console/logo.png", alt: "", class: "brand-logo", width: "36", height: "36" }),
        el("span", { text: "Kingphisher" }), el("small", { text: "Operator console" }),
      ]),
      nav,
      el("div", { class: "footer" }, [
        el("div", { text: info?.authMode === "dev" ? "Signed in as development operator" : "Signed in with OIDC" }),
        el("div", { id: "last-updated", class: "last-updated", role: "status", "aria-live": "polite" }),
        el("button", { type: "button", text: "Refresh current view", onclick: async () => {
          const dirtyForm = currentUnsavedForm();
          if (dirtyForm && !await confirmDiscardUnsaved(dirtyForm)) return;
          await render();
        } }),
        el("button", { type: "button", text: "Sign out", onclick: async () => {
          const dirtyForm = currentUnsavedForm();
          if (dirtyForm && !await confirmDiscardUnsaved(dirtyForm)) return;
          let serverLogoutConfirmed = false;
          try {
            const response = await fetch(`${API}/console/logout`, { method: "POST", credentials: "same-origin" });
            serverLogoutConfirmed = response.ok;
          } catch { /* Local session state must still be cleared. */ }
          clearToken();
          onboardingChecked = false;
          oidcSessionChecked = true;
          lastRenderedView = null;
          render();
          if (!serverLogoutConfirmed) {
            toast("Local session cleared, but server sign-out could not be confirmed. Close the browser tab on a shared device.", "error");
          }
        } }),
      ]),
    ]),
    content,
  ]);
  document.getElementById("app").replaceChildren(root);
  if (active && views[active]) {
    Promise.resolve(views[active](content)).then(() => {
      if (!viewChanged || !content.isConnected) return;
      const heading = content.querySelector("h1, h2");
      if (heading) {
        heading.setAttribute("tabindex", "-1");
        heading.focus();
      } else {
        content.focus();
      }
    }).catch((error) => {
      if (!content.isConnected) return;
      content.replaceChildren(el("div", { class: "card", role: "alert" }, [
        el("h2", { tabindex: "-1", text: `${activeLabel} could not be displayed` }),
        el("p", { text: error?.message || "An unexpected console error occurred." }),
        el("button", { class: "btn", type: "button", text: "Retry this view", onclick: render }),
      ]));
      content.querySelector("h2").focus();
    });
  }
  if (LIVE_VIEWS.has(active)) stampLastUpdated();
}

/* ---------- shared UI helpers ---------- */
function runtimeCapabilities(status, config = null) {
  const managed = status?.runtime_control === "azure_control_plane"
    || status?.config_store === "managed"
    || config?.mutable === false;
  const advertised = status?.capabilities || {};
  return {
    managed,
    configMutation: advertised.config_mutation ?? !managed,
    processRestart: advertised.process_restart ?? !managed,
  };
}

function statusPills(state) {
  const row = el("div", { class: "status-row" });
  if (runtimeCapabilities(state).managed) {
    row.appendChild(el("span", { class: "pill", text: "runtime: Azure managed" }));
  }
  const defs = [
    ["operator-api", state.operator_api],
    ["tracking-api", state.tracking_api],
    ["postgres", state.postgres],
    ["redis", state.redis],
  ];
  for (const [name, value] of defs) {
    const known = typeof value === "boolean";
    const label = known ? (value ? "up" : "down") : "unknown";
    const stateClass = known ? (value ? "ok" : "down") : "";
    row.appendChild(el("span", {
      class: `pill ${stateClass}`.trim(),
      text: `${name}: ${label}`,
      title: known ? null : (state.status_message || "Status is owned by the external runtime control plane."),
    }));
  }
  return row;
}

function setWizardFeedback(node, state, message) {
  const failed = state === "error";
  node.className = `wizard-feedback ${state || ""}`.trim();
  node.setAttribute("role", failed ? "alert" : "status");
  node.setAttribute("aria-live", failed ? "assertive" : "polite");
  node.textContent = message;
}

/* ---------- onboarding ---------- */
views.onboarding = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.MANAGE_ROLES)) return;
  root.appendChild(el("h2", { text: "Let’s set up Kingphisher" }));
  root.appendChild(el("p", { class: "sub", text: "A guided, plain-language setup for each service Kingphisher uses." }));

  let onboarding;
  try { onboarding = await api("/console/onboarding"); } catch (e) {
    root.appendChild(el("div", { class: "card", role: "alert", text: `Failed to load setup: ${e.message}` }));
    return;
  }
  let runtimeStatus;
  try { runtimeStatus = await api("/console/status"); } catch (e) {
    root.appendChild(el("div", {
      class: "card", role: "alert",
      text: `Runtime controls could not be verified: ${e.message}. Setup changes are disabled until status is available.`,
    }));
    return;
  }
  const capabilities = runtimeCapabilities(runtimeStatus);
  if (!capabilities.configMutation) {
    root.appendChild(el("div", { class: "card", role: "status" }, [
      el("h3", { text: "Configuration is managed in Azure" }),
      el("p", { text: runtimeStatus?.status_message || "This console cannot change configuration for the managed runtime." }),
      el("p", { text: "Use the Azure deployment workflow to review and apply configuration changes. No local files or processes will be changed from this page." }),
      el("button", { class: "btn", type: "button", text: "Open Azure deployment setup", onclick: () => navigateTo("azure-deployment") }),
    ]));
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
          el("button", { class: "btn", type: "button", text: "Browse help first", onclick: () => navigateTo("help") }),
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
          ...(restartNeeded && capabilities.processRestart ? [el("button", { class: "btn", type: "button", text: "Restart services now", onclick: async (event) => {
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
    const fieldRows = {};
    const requirementLabels = {};
    const form = el("form", { class: "wizard-form" });
    guardUnsavedForm(form, `Setup step: ${step.title}`);
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
      const requirement = el("span", { class: `requirement ${field.required ? "required" : "optional"}`, text: field.required ? "Required" : "Optional" });
      const row = el("div", { class: "wizard-field" }, [
        el("label", { for: id }, [el("span", { text: field.label }), requirement]), input,
        ...((field.help || field.explanation || field.example) ? [el("div", { id: `${id}-help`, class: "field-help", text: [field.explanation || field.help, field.example ? `Example: ${field.example}` : ""].filter(Boolean).join(" · ") })] : []),
        ...(field.where_to_find ? [el("details", { class: "field-location" }, [el("summary", { text: "Where do I find this?" }), el("p", { text: field.where_to_find })])] : []),
      ]);
      fieldRows[field.key] = row;
      requirementLabels[field.key] = requirement;
      form.appendChild(row);
    });
    const providerInput = step.provider_key ? inputs[step.provider_key] : null;
    const updateProviderFields = () => {
      const provider = providerInput?.value || "";
      (step.fields || []).forEach((field) => {
        const providers = Array.isArray(field.providers) ? field.providers : [];
        const active = !providers.length || providers.includes(provider);
        const requiredFor = Array.isArray(field.required_for) ? field.required_for : [];
        const required = active && (requiredFor.length ? requiredFor.includes(provider) : Boolean(field.required));
        const input = inputs[field.key];
        if (!input) return;
        fieldRows[field.key].hidden = !active;
        input.disabled = !active;
        input.required = required && !(field.secret && step.configured);
        const marker = requirementLabels[field.key];
        marker.className = `requirement ${required ? "required" : "optional"}`;
        marker.textContent = required ? "Required" : "Optional";
      });
    };
    providerInput?.addEventListener("input", updateProviderFields);
    updateProviderFields();
    const feedback = el("div", { class: "wizard-feedback", role: "status", "aria-live": "polite" });
    const values = () => Object.fromEntries(Object.entries(inputs).filter(([, input]) => !input.disabled && input.value !== "").map(([key, input]) => [key, input.value]));
    const changedValues = () => Object.fromEntries((step.fields || []).filter((field) => {
      const input = inputs[field.key];
      if (!input || input.disabled) return false;
      const entered = input.value || "";
      return field.secret ? Boolean(entered) : entered !== (field.value ?? "");
    }).map((field) => [field.key, inputs[field.key].value]));
    const saveButton = el("button", { class: "btn primary", type: "submit", text: step.configured ? "Continue" : "Test, save and continue" });
    const updateSaveLabel = () => { saveButton.textContent = Object.keys(changedValues()).length ? "Test, save and continue" : (step.configured ? "Continue" : "Test, save and continue"); };
    Object.values(inputs).forEach((input) => input.addEventListener("input", updateSaveLabel));
    const save = async () => {
      if (!form.reportValidity()) return false;
      const submitted = values();
      const changed = changedValues();
      if (step.configured && !Object.keys(changed).length) {
        markFormSaved(form);
        return true;
      }
      const result = await api("/console/onboarding", { method: "PUT", body: JSON.stringify({ values: submitted }) });
      savedValues[step.id] = { ...(savedValues[step.id] || {}), ...submitted };
      step.configured = true;
      restartNeeded = restartNeeded || Boolean(result?.restart_required ?? result?.changed?.length);
      markFormSaved(form);
      return true;
    };
    const testConnection = async () => {
      if (!form.reportValidity()) return null;
      setWizardFeedback(feedback, "testing", "Testing securely… This can take a few seconds.");
      try {
        const result = await api("/console/onboarding/test", { method: "POST", body: JSON.stringify({ component: step.id, values: values() }) });
        // The API now categorises the failure (auth / dns / timeout / tls /
        // refused / config), so show what to actually go and fix instead of a
        // generic "check the address and credentials".
        const label = CONNECTION_LABELS[result.error_kind];
        const outcome = result.outcome || (result.ok ? "verified" : "failed");
        setWizardFeedback(feedback, outcome === "verified" ? "success" : (outcome === "reachable_unverified" ? "warning" : "error"), [
          label ? `${label}:` : null,
          result.message || (result.ok ? "Connected successfully. You can save and continue." : "We couldn’t connect."),
        ].filter(Boolean).join(" "));
        return result;
      } catch (e) {
        setWizardFeedback(feedback, "error", `${e.message} Check the values above and your provider’s access settings, then try again.`);
        return null;
      }
    };
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = event.submitter; if (button) button.disabled = true;
      try {
        const hasChanges = Boolean(Object.keys(changedValues()).length);
        let testResult = null;
        if (hasChanges) {
          testResult = await testConnection();
          if (!testResult || testResult.save_allowed !== true) return;
        }
        if (await save()) {
          const action = testResult?.outcome === "reachable_unverified" ? "validated and saved" : "tested and saved";
          toast(hasChanges ? `${step.title} ${action}` : `${step.title} unchanged`, "success"); current++; renderStep();
        }
      } catch (e) { setWizardFeedback(feedback, "error", e.message); }
      finally { if (button?.isConnected) button.disabled = false; }
    });
    const testButton = el("button", { class: "btn", type: "button", text: "Test connection", onclick: async () => {
      testButton.disabled = true;
      await testConnection();
      testButton.disabled = false;
    } });
    const actions = [
      el("button", { class: "btn", type: "button", text: "Back", disabled: current === 0 ? "" : null, onclick: async () => {
        if (!await confirmDiscardUnsaved(form)) return;
        current--; renderStep();
      } }),
      testButton,
    ];
    if (step.optional) actions.push(el("button", { class: "btn", type: "button", text: "Skip for now", onclick: async () => {
      if (!await confirmDiscardUnsaved(form)) return;
      current++; renderStep();
    } }));
    actions.push(saveButton);
    form.append(feedback, el("div", { class: "btn-row wizard-actions" }, actions));
    const assistantAnswer = el("div", { class: "assistant-answer", role: "status", "aria-live": "polite", text: "Ask a question about this connection. Suggestions are only applied when you approve them." });
    const assistantQuestion = el("textarea", { rows: "2", placeholder: "For example: Where do I find my issuer URL?", "aria-label": `Question about ${step.title}` });
    const suggestionsBox = el("div", { class: "assistant-suggestions" });
    const askAssistant = el("button", { class: "btn small", type: "button", text: "Ask setup assistant", onclick: async () => {
      if (!assistantQuestion.value.trim()) { assistantQuestion.focus(); return; }
      askAssistant.disabled = true; assistantAnswer.textContent = "Thinking…"; suggestionsBox.replaceChildren();
      const safeValues = Object.fromEntries((step.fields || []).filter((field) => !field.secret && !inputs[field.key]?.disabled && inputs[field.key]?.value).map((field) => [field.key, inputs[field.key].value]));
      try {
        const result = await api("/console/onboarding/assist", { method: "POST", body: JSON.stringify({ component: step.id, question: assistantQuestion.value.trim(), values: safeValues }) });
        assistantAnswer.textContent = result.answer || "No guidance was returned.";
        if (result.warnings?.length) suggestionsBox.appendChild(el("div", { class: "notice", text: result.warnings.join(" ") }));
        const suggestions = Array.isArray(result.suggestions) ? result.suggestions : Object.entries(result.suggestions || {}).map(([field, value]) => ({ field, value }));
        suggestions.forEach((suggestion) => {
          const key = suggestion.field || suggestion.key;
          if (!key || !inputs[key] || inputs[key].disabled || (step.fields || []).find((field) => field.key === key)?.secret) return;
          suggestionsBox.appendChild(el("div", { class: "suggestion-preview" }, [
            el("span", { text: `${(step.fields || []).find((field) => field.key === key)?.label || key}: ${suggestion.value}` }),
            el("button", { class: "btn small", type: "button", text: "Apply to form", "aria-label": `Apply ${(step.fields || []).find((field) => field.key === key)?.label || key} suggestion to form`, onclick: () => { inputs[key].value = suggestion.value ?? ""; inputs[key].dispatchEvent(new Event("input")); toast("Suggestion applied to the form. Review it before saving.", "success"); } }),
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
      el("button", { class: "link-button", type: "button", text: "Open searchable help center", onclick: () => navigateTo("help") }),
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
  if (!requireAnyCapability(root, CAPABILITY.MANAGE_ROLES)) return;
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
  guardUnsavedForm(stage, "Azure deployment plan values");
  root.appendChild(stage);
  const deploymentStages = [
    ["foundation_bootstrap", "1. Bootstrap foundation"],
    ["foundation_finalize", "2. Finalize verified sender"],
    ["workloads", "3. Deploy workloads"],
  ];

  const stageTimeline = (plan) => {
    const status = plan?.stage_status;
    const valid = Boolean(status && typeof status === "object"
      && deploymentStages.some(([name]) => name === status.deployment_stage)
      && Number.isInteger(status.ordinal) && status.ordinal >= 1 && status.ordinal <= deploymentStages.length
      && status.total === deploymentStages.length
      && typeof status.completed === "boolean"
      && typeof status.evidence_status === "string" && status.evidence_status.length <= 64);
    return el("section", { class: "card", "aria-label": "Three-stage Azure deployment timeline" }, [
      el("h5", { text: "Azure deployment stages" }),
      el("ol", { class: "wizard-progress" }, deploymentStages.map(([name, label], index) => {
        const ordinal = index + 1;
        const phase = valid && ordinal < status.ordinal ? "done" : valid && ordinal === status.ordinal ? "current" : "";
        const suffix = valid && ordinal === status.ordinal
          ? ` — ${status.completed ? "evidence verified" : status.evidence_status.replaceAll("_", " ")}`
          : "";
        return el("li", { class: phase, "aria-current": phase === "current" ? "step" : null }, [
          el("span", { class: "step-number", text: ordinal }),
          el("span", { text: `${label}${suffix}` }),
        ]);
      })),
      valid ? el("p", { class: "field-help", text: "Each stage creates a new reviewed plan. A completed plan is never redispatched to advance." })
        : el("p", { class: "modal-warn", role: "alert", text: "Stage status is unavailable. Refresh before taking action." }),
    ]);
  };

  const releaseReadinessCard = (readiness) => {
    const value = readiness || {};
    const gates = Array.isArray(value.gates) ? value.gates : [];
    return el("section", { class: "card", "aria-label": "Production edge and recovery gates" }, [
      el("h4", { text: "Production edge & recovery gates" }),
      el("p", { class: "modal-warn", text: value.summary || "Production readiness has not been proven." }),
      el("p", { class: "field-help", text: `Evidence level: ${value.evidence_level || "unverified"}. These states come from the checked-in implementation and cannot be changed by an operator attestation.` }),
      el("ul", { class: "event-list" }, gates.map((gate) => el("li", {}, [
        el("strong", { text: `${gate.label}: ` }),
        el("span", { text: String(gate.status || "unverified").replaceAll("_", " ") }),
        el("span", { text: ` — ${gate.detail || "No evidence is available."}` }),
      ]))),
    ]);
  };

  const download = (name, content) => {
    const link = document.createElement("a");
    const url = URL.createObjectURL(new Blob([content], { type: "text/plain;charset=utf-8" }));
    try {
      link.href = url;
      link.download = name;
      document.body.appendChild(link);
      link.click();
      link.remove();
    } finally {
      URL.revokeObjectURL(url);
    }
  };
  const deploymentActionContract = (plan) => {
    const action = plan?.operator_action;
    const valid = Boolean(action && typeof action === "object"
      && typeof action.next_action === "string" && action.next_action.length > 0 && action.next_action.length <= 400
      && typeof action.retry_allowed === "boolean"
      && typeof action.reconcile_only === "boolean"
      && typeof action.destructive_cleanup_allowed === "boolean");
    return {
      valid,
      nextAction: valid ? action.next_action : "Refresh this plan before taking another deployment action.",
      retryAllowed: valid && action.retry_allowed === true,
      reconcileRequired: valid && action.reconcile_only === true,
      preservationSafe: valid && action.destructive_cleanup_allowed === false,
    };
  };
  const submitPlan = async (plan, retry = false) => {
    const action = deploymentActionContract(plan);
    const retryableState = plan?.state === "dispatch_failed";
    if (!action.valid || !action.preservationSafe
      || (retry && (!action.retryAllowed || !retryableState))
      || (!retry && plan?.state !== "reviewed")) {
      throw new Error("This deployment action is not authorized by the current recovery state. Refresh the plan.");
    }
    const rationale = await promptDialog({
      title: retry ? "Retry rejected dispatch" : "Dispatch reviewed deployment",
      description: retry
        ? "GitHub rejected the prior dispatch before creating a run. State why one new protected dispatch is authorized; all existing state is preserved."
        : "State why this protected workflow run is authorized. The reason is written to the audit trail; do not include credentials.",
      fields: [{ name: "rationale", label: "Authorization reason", type: "textarea", required: true, placeholder: "Approved staging deployment after readiness review" }],
      submitLabel: "Review dispatch",
    });
    if (!rationale || rationale.rationale.length < 10) {
      if (rationale) toast("Enter an authorization reason of at least 10 characters.", "error");
      return null;
    }
    const confirmed = await confirmDialog({
      title: retry ? "Confirm rejected-dispatch retry" : "Confirm protected workflow dispatch",
      message: retry
        ? "This starts a new fixed workflow request only because GitHub created no prior run. Existing resources, volumes, databases, images, caches, and evidence remain preserved."
        : "This asks GitHub Actions to start the fixed checked-in Azure deployment workflow. GitHub environment approval is still required.",
      detail: {
        Environment: plan.review.environment,
        Network: plan.review.network_mode,
        Workflow: plan.workflow,
        "Review digest": plan.review_digest,
      },
      confirmLabel: retry ? "Retry rejected dispatch" : "Dispatch workflow",
      danger: true,
    });
    if (!confirmed) return null;
    return api(`/console/azure-deployment/orchestration/plans/${encodeURIComponent(plan.plan_id)}/${retry ? "retry" : "apply"}`, {
      method: "POST",
      body: JSON.stringify({ confirm: true, review_digest: plan.review_digest, rationale: rationale.rationale }),
    });
  };
  const renderPlan = (plan, container) => {
    const knownStates = new Set(["reviewed", "dispatching", "dispatch_accepted", "dispatch_indeterminate", "queued", "running", "dispatch_failed", "run_failed", "evidence_unverified", "review_required", "workflow_succeeded"]);
    const review = plan.review || {};
    const rawState = typeof plan.state === "string" && knownStates.has(plan.state) ? plan.state : "unknown";
    const state = rawState.replaceAll("_", " ");
    const action = deploymentActionContract(plan);
    const rawStageAction = plan?.stage_action;
    const stageAction = rawStageAction && typeof rawStageAction === "object"
      && ["dispatch", "wait", "advance", "reconcile", "review_required", "complete"].includes(rawStageAction.kind)
      && typeof rawStageAction.enabled === "boolean"
      && typeof rawStageAction.label === "string" && rawStageAction.label.length > 0 && rawStageAction.label.length <= 120
      && (rawStageAction.next_stage === null || deploymentStages.some(([name]) => name === rawStageAction.next_stage))
      ? rawStageAction : null;
    const rawAcsEvidence = plan?.acs_evidence;
    const acsEvidenceValid = Boolean(rawAcsEvidence && typeof rawAcsEvidence === "object"
      && ["awaiting_workflow", "evidence_unverified", "verified"].includes(rawAcsEvidence.status)
      && rawAcsEvidence.schema === "kp.acs-stage-result.v1"
      && deploymentStages.some(([name]) => name === rawAcsEvidence.deployment_stage));
    const evidenceStatuses = acsEvidenceValid && rawAcsEvidence.statuses && typeof rawAcsEvidence.statuses === "object"
      && !Array.isArray(rawAcsEvidence.statuses) && Object.keys(rawAcsEvidence.statuses).length <= 6
      ? Object.entries(rawAcsEvidence.statuses).filter(([name, value]) => (
        ["domain", "spf", "dkim", "dkim2", "sender", "association"].includes(name)
        && typeof value === "string" && /^[a-z_]{2,32}$/.test(value)
      )) : [];
    const evidenceScopes = acsEvidenceValid && rawAcsEvidence.scope_limits && typeof rawAcsEvidence.scope_limits === "object"
      && !Array.isArray(rawAcsEvidence.scope_limits) && Object.keys(rawAcsEvidence.scope_limits).length <= 8
      ? Object.entries(rawAcsEvidence.scope_limits).filter(([name, value]) => (
        /^[a-z][a-z0-9_]{1,63}$/.test(name) && typeof value === "boolean"
      )) : [];
    const evidenceDigests = acsEvidenceValid ? [
      ["Stage evidence", rawAcsEvidence.evidence_digest],
      ["Artifact", rawAcsEvidence.artifact_sha256],
    ].filter(([, value]) => typeof value === "string" && /^sha256:[0-9a-f]{64}$/.test(value)) : [];
    const acsEvidencePanel = el("section", { class: "card", "aria-label": "Bounded ACS deployment evidence" }, [
      el("h5", { text: "ACS control-plane evidence" }),
      el("p", { class: acsEvidenceValid && rawAcsEvidence.status === "verified" ? "notice" : "modal-warn", text: acsEvidenceValid
        ? `Artifact status: ${rawAcsEvidence.status.replaceAll("_", " ")}. DNS: ${String(rawAcsEvidence.dns_status || "awaiting protected workflow").replaceAll("_", " ")}.`
        : "The bounded ACS artifact contract is unavailable; stage advance is blocked." }),
      el("dl", { class: "wizard-summary" }, evidenceDigests.flatMap(([label, value]) => [
        el("dt", { text: label }), el("dd", { text: value }),
      ])),
      el("ul", { class: "event-list", "aria-label": "Authenticated ACS statuses" }, evidenceStatuses.map(([name, value]) => (
        el("li", { text: `${name.toUpperCase()}: ${value.replaceAll("_", " ")}` })
      ))),
      el("ul", { class: "event-list", "aria-label": "ACS evidence scope limits" }, evidenceScopes.map(([name, value]) => (
        el("li", { text: `${name.replaceAll("_", " ")}: ${value ? "proven" : "not proven"}` })
      ))),
      el("p", { class: "field-help", text: acsEvidenceValid && rawAcsEvidence.observed_at
        ? `Authenticated read observed at ${String(rawAcsEvidence.observed_at).slice(0, 64)}. Mail delivery, inbox placement, and human mailbox validation remain separate gates.`
        : "No authenticated ACS readback is available yet." }),
    ]);
    const recovery = plan.recovery && typeof plan.recovery === "object" ? plan.recovery : null;
    const policy = recovery?.policy && typeof recovery.policy === "object" ? recovery.policy : null;
    const rawPreservationItems = policy && Array.isArray(policy.preservation_required)
      ? policy.preservation_required
      : [];
    const preservationItems = rawPreservationItems.filter((item) => (
      typeof item === "string" && /^[a-z][a-z0-9_]{1,47}$/.test(item)
    )).slice(0, 20);
    const evidenceContract = recovery?.verification;
    const missingActivity = Array.isArray(evidenceContract?.missing_required_activity)
      ? evidenceContract.missing_required_activity.filter((item) => typeof item === "string" && item.length > 0 && item.length <= 256).slice(0, 48)
      : [];
    const failedActivity = Array.isArray(evidenceContract?.failed_required_activity)
      ? evidenceContract.failed_required_activity.filter((item) => typeof item === "string" && item.length > 0 && item.length <= 256).slice(0, 48)
      : [];
    const rawEvidenceChecks = evidenceContract?.checks && typeof evidenceContract.checks === "object"
      && !Array.isArray(evidenceContract.checks)
      ? Object.entries(evidenceContract.checks)
      : [];
    const evidenceChecks = rawEvidenceChecks.filter(([name, check]) => (
      /^[a-z][a-z0-9_]{1,31}$/.test(name) && check && typeof check === "object" && !Array.isArray(check)
    )).slice(0, 12);
    const preservationContractValid = rawPreservationItems.length > 0 && rawPreservationItems.length <= 20
      && rawPreservationItems.every((item) => typeof item === "string" && /^[a-z][a-z0-9_]{1,47}$/.test(item))
      && new Set(rawPreservationItems).size === rawPreservationItems.length
      && Array.isArray(policy?.prohibited_automatic_actions)
      && policy.prohibited_automatic_actions.length > 0 && policy.prohibited_automatic_actions.length <= 20
      && policy.prohibited_automatic_actions.every((item) => typeof item === "string" && /^[a-z][a-z0-9_]{1,47}$/.test(item));
    const evidenceChecksValid = rawEvidenceChecks.length > 0 && rawEvidenceChecks.length <= 12
      && rawEvidenceChecks.every(([name, check]) => (
        /^[a-z][a-z0-9_]{1,31}$/.test(name)
        && check && typeof check === "object" && !Array.isArray(check)
        && check.blocking === true
        && typeof check.status === "string" && check.status.length > 0 && check.status.length <= 80
        && Array.isArray(check.required_fields)
        && check.required_fields.length > 0 && check.required_fields.length <= 16
        && check.required_fields.every((field) => typeof field === "string" && /^[a-z][a-z0-9_]{1,63}$/.test(field))
      ));
    const evidenceStatus = evidenceContract?.status;
    const evidenceListsValid = [evidenceContract?.missing_required_activity, evidenceContract?.failed_required_activity]
      .every((items) => Array.isArray(items) && items.length <= 48
        && items.every((item) => typeof item === "string" && item.length > 0 && item.length <= 256));
    const evidenceSummaryValid = ["awaiting_protected_workflow", "evidence_unverified", "verified"].includes(evidenceStatus)
      && typeof evidenceContract?.connector_verified === "boolean"
      && (evidenceContract.connector_verified === (evidenceStatus === "verified"))
      && Number.isInteger(evidenceContract?.required_activity_count) && evidenceContract.required_activity_count > 0
      && Number.isInteger(evidenceContract?.observed_activity_count) && evidenceContract.observed_activity_count >= 0
      && evidenceContract.observed_activity_count <= evidenceContract.required_activity_count
      && evidenceContract?.source === "bounded_github_run_job_step_activity"
      && evidenceListsValid;
    const recoveryValid = Boolean(policy
      && policy.strategy === "reconcile_existing_operation"
      && policy.automatic_cleanup_allowed === false
      && preservationContractValid
      && evidenceSummaryValid
      && evidenceChecksValid);
    const preservation = el("section", { class: "card", "aria-label": "Preservation-required deployment state" }, [
      el("h5", { text: "Preservation-required state" }),
      el("p", { class: recoveryValid ? "notice" : "modal-warn", role: recoveryValid ? "note" : "alert", text: recoveryValid
        ? "Automatic resource cleanup is prohibited. The deployment reconciles the existing operation and preserves the assets listed by the server."
        : "The server recovery contract is missing or malformed. Refresh before dispatching or retrying." }),
      el("ul", { class: "event-list", "aria-label": "Assets that must be preserved" }, preservationItems.map((item) => (
        el("li", { text: item.replaceAll("_", " ") })
      ))),
    ]);
    const evidence = el("section", { class: "card", "aria-label": "Required deployment preflight evidence" }, [
      el("h5", { text: "Required preflight evidence" }),
      el("p", { class: "field-help", text: `Evidence status: ${recoveryValid ? evidenceContract.status.replaceAll("_", " ") : "unavailable"}. Verification comes only from bounded exact job and step results for the pinned protected workflow.` }),
      el("ul", { class: "event-list" }, evidenceChecks.map(([name, check]) => {
        const checkStatus = typeof check.status === "string" && check.status.length <= 80 ? check.status : "unavailable";
        const fields = Array.isArray(check.required_fields)
          ? check.required_fields.filter((field) => typeof field === "string" && /^[a-z][a-z0-9_]{1,63}$/.test(field)).slice(0, 16)
          : [];
        return el("li", {}, [
          el("strong", { text: `${name.replaceAll("_", " ")}: ` }),
          el("span", { text: checkStatus.replaceAll("_", " ") }),
          el("span", { text: ` — ${check.blocking === true ? "blocking" : "status unavailable"}` }),
          el("span", { text: fields.length ? `. Required record: ${fields.map((field) => field.replaceAll("_", " ")).join(", ")}.` : ". Required record unavailable." }),
        ]);
      })),
      el("p", { class: "field-help", text: recoveryValid ? `${evidenceContract.observed_activity_count} of ${evidenceContract.required_activity_count} required job and step results verified.` : "Required activity verification is unavailable." }),
      el("ul", { class: "event-list", "aria-label": "Unverified required workflow activity" }, [
        ...missingActivity.map((item) => el("li", { text: `Missing: ${item}` })),
        ...failedActivity.map((item) => el("li", { text: `Not successful: ${item}` })),
      ]),
    ]);
    const rawCheckpointRows = Array.isArray(plan.checkpoints) ? plan.checkpoints : [];
    const checkpointRows = rawCheckpointRows.slice(0, 64);
    let previousDigest = null;
    let checkpointIntegrity = rawCheckpointRows.length > 0 && rawCheckpointRows.length <= 64;
    const checkpoints = el("ol", { class: "event-list", "aria-label": "Tamper-evident deployment checkpoints" });
    checkpointRows.forEach((checkpoint, index) => {
      const valid = checkpoint && typeof checkpoint === "object"
        && checkpoint.sequence === index + 1
        && typeof checkpoint.phase === "string" && /^[a-z][a-z0-9_]{1,47}$/.test(checkpoint.phase)
        && typeof checkpoint.recorded_at === "string" && checkpoint.recorded_at.length > 0 && checkpoint.recorded_at.length <= 64
        && Number.isInteger(checkpoint.attempt) && checkpoint.attempt >= 0
        && typeof checkpoint.digest === "string" && /^[0-9a-f]{64}$/.test(checkpoint.digest)
        && checkpoint.previous_digest === previousDigest;
      checkpointIntegrity = checkpointIntegrity && valid;
      if (valid) previousDigest = checkpoint.digest;
      checkpoints.appendChild(el("li", { text: valid
        ? `Checkpoint ${checkpoint.sequence}: ${checkpoint.phase.replaceAll("_", " ")} — attempt ${checkpoint.attempt} at ${checkpoint.recorded_at}; digest ${checkpoint.digest.slice(0, 12)}…`
        : `Checkpoint ${index + 1}: integrity unavailable; refresh required.` }));
    });
    if (!checkpointRows.length) checkpoints.appendChild(el("li", { text: "No server-validated checkpoints are available. Refresh before taking action." }));
    const checkpointPanel = el("section", { class: "card", "aria-label": "Deployment checkpoint integrity" }, [
      el("h5", { text: "Operation checkpoints" }),
      el("p", { class: checkpointIntegrity ? "field-help" : "modal-warn", role: checkpointIntegrity ? "status" : "alert", text: checkpointIntegrity
        ? `Checkpoint integrity: tamper-evident server-validated chain with ${checkpointRows.length} intact sequence link${checkpointRows.length === 1 ? "" : "s"}.`
        : "Checkpoint integrity is unavailable. Only refresh and workflow inspection are safe." }),
      checkpoints,
    ]);
    const summary = el("dl", { class: "wizard-summary" });
    Object.entries({
      Environment: review.environment,
      Network: review.network_mode,
      Stage: review.deployment_stage,
      "Directory sync": review.directory_sync ? "Enabled" : "Disabled",
      "Reported mailbox": review.reported_mailbox ? "Enabled" : "Disabled",
      "ACS mode": review.acs_resource_mode,
      "Terraform state": review.terraform_state_identity ? `${review.terraform_state_identity.resource_group} / ${review.terraform_state_identity.storage_account} / ${review.terraform_state_identity.container}` : "—",
      State: state,
      Attempt: plan.attempt,
    }).forEach(([key, value]) => summary.append(el("dt", { text: key }), el("dd", { text: value ?? "—" })));
    const prerequisites = el("ul", {}, (plan.external_prerequisites || []).map((item) => el("li", { text: item })));
    const limitations = el("ul", {}, (plan.limitations || []).map((item) => el("li", { text: item })));
    const activity = el("ul", { class: "event-list", "aria-label": "Bounded deployment activity" },
      (plan.activity || []).map((item) => el("li", { text: `${item.kind}: ${item.name} — ${item.status}${item.conclusion ? ` / ${item.conclusion}` : ""}` })));
    if (!(plan.activity || []).length) activity.appendChild(el("li", { text: "No linked workflow activity yet. Refresh after GitHub creates the run." }));
    const lastError = plan.last_error === null || plan.last_error === undefined
      ? null
      : (typeof plan.last_error === "string" && plan.last_error.length <= 600
        ? plan.last_error
        : "Deployment status details are unavailable; inspect the protected workflow.");
    const status = el("div", { class: lastError ? "wizard-feedback error" : "wizard-feedback", role: lastError ? "alert" : "status", "aria-live": lastError ? "assertive" : "polite", text: lastError || `Deployment state: ${state}.` });
    const nextAction = el("div", { class: "notice", role: "status", "aria-live": "polite" }, [
      el("strong", { text: "Safe next action: " }),
      el("span", { text: action.nextAction }),
      action.reconcileRequired ? el("span", { text: " Reconciliation is required; a new dispatch is blocked." }) : el("span"),
    ]);
    const actions = el("div", { class: "btn-row wizard-actions" });
    const mutationContractValid = action.valid && action.preservationSafe && recoveryValid && checkpointIntegrity;
    if (rawState === "reviewed" && mutationContractValid && !action.retryAllowed && !action.reconcileRequired) actions.appendChild(el("button", { class: "btn primary", type: "button", text: "Dispatch protected workflow", onclick: async () => {
      try { const updated = await submitPlan(plan); if (updated) renderPlan(updated, container); } catch (e) { toast(e.message, "error"); }
    } }));
    if (rawState === "dispatch_failed" && mutationContractValid && action.retryAllowed && !action.reconcileRequired) actions.appendChild(el("button", { class: "btn primary", type: "button", text: "Retry rejected dispatch", onclick: async () => {
      try { const updated = await submitPlan(plan, true); if (updated) renderPlan(updated, container); } catch (e) { toast(e.message, "error"); }
    } }));
    if (rawState === "workflow_succeeded" && mutationContractValid && stageAction?.kind === "advance" && stageAction.enabled === true && rawAcsEvidence?.status === "verified") actions.appendChild(el("button", { class: "btn primary", type: "button", text: stageAction.label, onclick: async () => {
      const confirmed = await confirmDialog({
        title: "Advance to the next Azure stage",
        message: "This creates a new reviewed plan from server-held non-secret configuration and verified evidence. It does not redispatch the completed plan.",
        detail: { "Completed stage": plan.stage_status.deployment_stage, "Next stage": stageAction.next_stage, "Evidence digest": rawAcsEvidence.evidence_digest },
        confirmLabel: "Create next reviewed stage",
      });
      if (!confirmed) return;
      try {
        const advanced = await api(`/console/azure-deployment/orchestration/plans/${encodeURIComponent(plan.plan_id)}/advance`, {
          method: "POST", body: JSON.stringify({ confirm: true, review_digest: plan.review_digest }),
        });
        renderPlan(advanced, container);
      } catch (e) { toast(e.message, "error"); }
    } }));
    actions.appendChild(el("button", { class: "btn", type: "button", text: action.reconcileRequired ? "Reconcile existing operation" : "Refresh status", onclick: async () => {
      try {
        const updated = await api(`/console/azure-deployment/orchestration/plans/${encodeURIComponent(plan.plan_id)}`);
        renderPlan(updated, container);
      } catch (e) { toast(e.message, "error"); }
    } }));
    if (plan.workflow_url) actions.appendChild(el("a", { class: "btn", href: plan.workflow_url, target: "_blank", rel: "noopener noreferrer", text: "Open protected workflow" }));
    container.replaceChildren(
      el("h4", { text: "Reviewed workflow plan" }),
      el("p", { text: "Only the fixed workflow and inputs shown here can be dispatched. No command, path, option, or credential comes from this page." }),
      summary,
      stageTimeline(plan),
      releaseReadinessCard(schema.release_readiness),
      preservation,
      evidence,
      acsEvidencePanel,
      checkpointPanel,
      el("h5", { text: "External prerequisites" }), prerequisites,
      el("h5", { text: "Limitations" }), limitations,
      status,
      nextAction,
      el("h5", { text: "Redacted activity" }), activity,
      actions,
    );
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
          el("li", { text: "Preflight verifies the selected GitHub environment has required reviewers; apply is blocked unless that protection is present" }),
          el("li", { text: "Rollback is not automated in this GUI slice; use the protected Azure recovery procedure" }),
        ]),
        el("div", { class: "notice", role: "note", text: schema.safety_note }),
        el("div", { class: "btn-row" }, [
          el("button", { class: "btn primary", type: "button", text: "Start Azure deployment setup", onclick: () => { current = 0; render(); } }),
          el("button", { class: "btn", type: "button", text: "Read deployment guide", onclick: () => navigateTo("help") }),
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
      const readinessPanel = el("div", {}, [releaseReadinessCard(schema.release_readiness)]);
      const exports = el("div", { class: "btn-row" });
      const orchestration = el("div", { class: "card" });
      const validateButton = el("button", { class: "btn primary", type: "button", text: "Validate configuration", onclick: async () => {
        validateButton.disabled = true; exports.replaceChildren(); resultBox.textContent = "Validating non-secret deployment values…";
        try {
          const result = await api("/console/azure-deployment/validate", { method: "POST", body: JSON.stringify({ values: collected }) });
          if (!result.ok) {
            setWizardFeedback(resultBox, "error", Object.entries(result.errors || {}).map(([key, message]) => `${key}: ${message}`).join(" "));
            return;
          }
          setWizardFeedback(resultBox, "success", ["Inputs are structurally valid; production readiness is not proven.", ...(result.warnings || [])].join(" "));
          readinessPanel.replaceChildren(releaseReadinessCard(result.release_readiness));
          const terraformValues = {
            subscription_id: collected.subscription_id,
            environment: collected.environment,
            location: collected.location,
            name_prefix: collected.name_prefix,
            operator_fqdn: collected.operator_fqdn,
            tracking_fqdn: collected.tracking_fqdn,
            entra_tenant_id: collected.entra_tenant_id,
            entra_client_id: collected.entra_client_id,
            communication_data_location: collected.communication_data_location,
            acs_resource_mode: collected.acs_resource_mode,
            acs_existing_communication_service_id: collected.acs_existing_communication_service_id || "",
            acs_existing_email_endpoint: collected.acs_existing_email_endpoint || "",
            acs_existing_email_domain_id: collected.acs_existing_email_domain_id || "",
            acs_sending_domain: collected.acs_sending_domain,
            acs_sender_local_part: collected.acs_sender_local_part,
            acs_sender_display_name: collected.acs_sender_display_name,
            acs_dns_zone_id: collected.acs_dns_zone_id || "",
            acs_daily_message_limit: Number(collected.acs_daily_message_limit),
            acs_messages_per_minute: Number(collected.acs_messages_per_minute),
            acs_ramp_batch_size: Number(collected.acs_ramp_batch_size),
            acs_ramp_interval_seconds: Number(collected.acs_ramp_interval_seconds),
            ai_endpoint: collected.ai_endpoint || "",
            graph_endpoint: collected.enable_directory_sync === "true" ? "https://graph.microsoft.com/v1.0" : "",
            directory_group_ids: collected.directory_group_ids || "",
            reported_mailbox_endpoint: collected.enable_reported_mailbox === "true" ? "https://graph.microsoft.com/v1.0" : "",
            reported_mailbox_address: collected.reported_mailbox_address || "",
            reported_mailbox_folder: collected.reported_mailbox_folder || "inbox",
            alert_webhook_domains: collected.alert_webhook_domains || "",
            allowed_recipient_domains: collected.allowed_recipient_domains,
            ciphertext_active_key_id: collected.ciphertext_active_key_id,
            ciphertext_prior_key_ids: collected.ciphertext_prior_key_ids || "",
            ciphertext_prior_keys_secret_id: collected.ciphertext_prior_keys_secret_id || "",
          };
          const tfvars = Object.entries(terraformValues).map(([key, value]) => `${key} = ${JSON.stringify(value)}`).join("\n") + "\n";
          const workflowValues = {
            AZURE_SUBSCRIPTION_ID: collected.subscription_id,
            AZURE_TENANT_ID: collected.entra_tenant_id,
            AZURE_CLIENT_ID: collected.azure_deployment_client_id,
            TF_STATE_RESOURCE_GROUP: collected.tf_state_resource_group,
            TF_STATE_STORAGE_ACCOUNT: collected.tf_state_storage_account,
            TF_STATE_CONTAINER: collected.tf_state_container,
            DEPLOYMENT_ORCHESTRATION_MODE: "disabled",
            DEPLOYMENT_GITHUB_REPOSITORY: "",
            DEPLOYMENT_GITHUB_REF: "main",
            DEPLOYMENT_GITHUB_TOKEN_SECRET_ID: "",
          };
          exports.append(
            el("button", { class: "btn", type: "button", text: "Download Terraform values", onclick: () => download(`${collected.environment}.auto.tfvars`, tfvars) }),
            el("button", { class: "btn", type: "button", text: "Download GitHub variables", onclick: () => download("github-environment-variables.json", JSON.stringify(workflowValues, null, 2) + "\n") }),
          );
          const productionBlocked = collected.environment === "production"
            && result.release_readiness?.production_plan_allowed !== true;
          if (productionBlocked) {
            orchestration.replaceChildren(el("p", { class: "modal-warn", role: "alert", text: "Production workflow planning is blocked until the custom-domain, certificate, edge restriction, live HSTS, backup/restore, and rollback gates are verifiable. Use staging to bootstrap the required Azure resources." }));
          } else if (schema.orchestration?.configured) {
            exports.appendChild(el("button", { class: "btn primary", type: "button", text: "Create reviewed workflow plan", onclick: async () => {
              try {
                const plan = await api("/console/azure-deployment/orchestration/plan", { method: "POST", body: JSON.stringify({ values: collected }) });
                if (plan.ok === false) throw new Error("Configuration changed or is no longer valid.");
                markFormSaved(stage);
                renderPlan(plan, orchestration);
              } catch (e) { toast(e.message, "error"); }
            } }));
            orchestration.replaceChildren(el("p", { class: "notice", text: `GUI dispatch is connected to ${schema.orchestration.repository} at ${schema.orchestration.ref}. Creating a plan does not start a workflow.` }));
          } else {
            orchestration.replaceChildren(el("p", { class: "notice", text: `GUI dispatch is unavailable: ${schema.orchestration?.reason || "the protected workflow connector is not configured"}. You can still export the reviewed values.` }));
          }
        } catch (e) { setWizardFeedback(resultBox, "error", e.message); }
        finally { validateButton.disabled = false; }
      } });
      const summary = el("dl", { class: "wizard-summary" });
      steps.forEach((step) => {
        summary.append(el("dt", { text: step.title }), el("dd", { text: (step.fields || []).map((field) => `${field.label}: ${collected[field.key] || "Not entered"}`).join(" · ") }));
      });
      stage.replaceChildren(progress, el("section", { class: "card wizard-card", "aria-labelledby": "azure-wizard-title" }, [
        el("h3", { id: "azure-wizard-title", tabindex: "-1", text: "Validate and hand off deployment" }),
        el("p", { text: "Review the non-secret values below. Validation does not contact Azure or deploy resources." }),
        summary, resultBox, readinessPanel, exports, orchestration,
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
    guardUnsavedForm(form, `Azure deployment step: ${step.title}`);
    const renderField = (field, index) => {
      const id = `azure-${current}-${index}`;
      const attrs = { id, name: field.key, required: field.required ? "" : null, disabled: field.server_controlled === true ? "" : null, placeholder: field.placeholder || "", autocomplete: "off", "aria-describedby": `${id}-help` };
      const input = field.choices?.length
        ? el("select", attrs, field.choices.map((choice) => el("option", { value: choice.value, text: choice.label })))
        : el("input", { ...attrs, type: field.type === "url" ? "url" : "text" });
      const rest = collected[field.key] !== undefined ? collected[field.key]
        : field.suggested_default ?? field.choices?.[0]?.value ?? "";
      input.value = rest; inputs[field.key] = input;
      return el("div", { class: "wizard-field" }, [
        el("label", { for: id }, [el("span", { text: field.label }), el("span", { class: `requirement ${field.required ? "required" : "optional"}`, text: field.required ? "Required" : "Optional" })]), input,
        el("details", { id: `${id}-help`, class: "field-location" }, [el("summary", { text: "Where do I find this?" }), el("p", { text: field.where_to_find })]),
      ]);
    };
    const normalFields = (step.fields || []).filter((field) => field.advanced !== true);
    const advancedFields = (step.fields || []).filter((field) => field.advanced === true);
    normalFields.forEach((field, index) => form.appendChild(renderField(field, index)));
    if (advancedFields.length) {
      const startIndex = normalFields.length;
      form.appendChild(el("details", { class: "azure-advanced" }, [
        el("summary", { text: `Advanced options (${advancedFields.length})` }),
        el("p", { class: "field-help", text: "These resource IDs, quotas, and GitHub/Terraform hooks use reviewed defaults for a standard deployment. Most operators never change them." }),
        ...advancedFields.map((field, offset) => renderField(field, startIndex + offset)),
      ]));
    }
    form.addEventListener("submit", (event) => {
      event.preventDefault(); if (!form.reportValidity()) return;
      Object.entries(inputs).forEach(([key, input]) => { collected[key] = input.value.trim(); });
      markFormDirty(stage);
      markFormSaved(form);
      current++; render();
    });
    form.appendChild(el("div", { class: "btn-row wizard-actions" }, [
      el("button", { class: "btn", type: "button", text: "Back", onclick: async () => {
        if (!await confirmDiscardUnsaved(form)) return;
        current--; render();
      } }),
      el("button", { class: "btn primary", type: "submit", text: "Save in this wizard and continue" }),
    ]));
    const answer = el("div", { class: "assistant-answer", role: "status", "aria-live": "polite", text: "Ask where to find a value or why it is required. Nothing is changed automatically." });
    const suggestionsBox = el("div", { class: "assistant-suggestions", "aria-label": "AI suggestions requiring review" });
    const question = el("textarea", { rows: "2", placeholder: "For example: Where do I find my tenant ID?", "aria-label": `Question about ${step.title}` });
    const ask = el("button", { class: "btn small", type: "button", text: "Ask setup assistant", onclick: async () => {
      if (!question.value.trim()) { question.focus(); return; } ask.disabled = true; answer.textContent = "Thinking…";
      const values = Object.fromEntries(Object.entries(inputs).filter(([, input]) => input.value).map(([key, input]) => [key, input.value]));
      try {
        const result = await api("/console/onboarding/assist", { method: "POST", body: JSON.stringify({ component: step.id, question: question.value.trim(), values }) });
        answer.textContent = [result.answer, ...(result.warnings || [])].filter(Boolean).join(" ");
        suggestionsBox.replaceChildren();
        Object.entries(result.suggestions || {}).filter(([key, value]) => (
          Object.hasOwn(inputs, key) && typeof value === "string" && value.length <= 2048
        )).slice(0, 16).forEach(([key, value]) => {
          suggestionsBox.appendChild(el("div", { class: "suggestion-row" }, [
            el("span", { text: `${(step.fields || []).find((field) => field.key === key)?.label || key}: ${value}` }),
            el("button", { class: "btn small", type: "button", text: "Apply to form", "aria-label": `Apply ${(step.fields || []).find((field) => field.key === key)?.label || key} suggestion to form`, onclick: () => {
              inputs[key].value = value;
              inputs[key].dispatchEvent(new Event("input"));
              toast("Suggestion applied to the form. Review it before creating a plan.", "success");
            } }),
          ]));
        });
      } catch (e) { answer.textContent = `Assistant unavailable: ${e.message}`; }
      finally { ask.disabled = false; }
    } });
    const assistant = el("details", { class: "setup-assistant" }, [
      el("summary", { text: "Ask the AI setup assistant" }),
      el("p", { class: "field-help", text: "Only the non-secret fields on this page are eligible for assistance. AI cannot deploy or save settings." }),
      question, el("div", { class: "btn-row" }, [ask]), answer, suggestionsBox,
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
  const restoredPlan = el("div", { class: "onboarding-stage", "aria-live": "polite" });
  root.appendChild(restoredPlan);
  try {
    const latest = await Promise.all(["staging", "production"].map(async (environment) => {
      const response = await api(`/console/azure-deployment/orchestration/latest?environment=${encodeURIComponent(environment)}`);
      return response?.plan || null;
    }));
    const plans = latest.filter((plan) => plan && typeof plan.created_at === "string" && plan.created_at.length <= 64)
      .sort((left, right) => right.created_at.localeCompare(left.created_at));
    if (plans.length) {
      restoredPlan.appendChild(el("p", { class: "notice", text: "Restored your latest active Azure deployment plan after reload." }));
      const planContainer = el("section", { class: "card", "aria-label": "Restored Azure deployment plan" });
      restoredPlan.appendChild(planContainer);
      renderPlan(plans[0], planContainer);
    }
  } catch (error) {
    restoredPlan.replaceChildren(el("p", { class: "modal-warn", role: "alert", text: `Latest deployment plan could not be restored: ${error.message}. Do not create a replacement plan until storage is available.` }));
  }
};

/* ---------- help ---------- */
views.help = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)) return;
  root.appendChild(el("h2", { text: "Help center" }));
  root.appendChild(el("p", { class: "sub", text: "Plain-language setup guides and definitions, all in one place." }));
  const search = el("input", {
    type: "search", class: "help-search", placeholder: "Search topics and terms (for example, OIDC)",
    "aria-label": "Search help", "aria-controls": "help-results",
  });
  const resultCount = el("p", { class: "field-help", role: "status", "aria-live": "polite" });
  const results = el("div", { id: "help-results", class: "help-results" });
  root.append(search, resultCount, results);
  let help;
  try { help = await api("/console/help"); }
  catch (e) { results.replaceChildren(el("div", { class: "card", role: "alert", text: `Help is unavailable: ${e.message}` })); return; }
  const topics = Array.isArray(help?.topics) ? help.topics : Object.entries(help?.topics || {}).map(([title, body]) => ({ title, body }));
  const glossary = Array.isArray(help?.glossary) ? help.glossary : Object.entries(help?.glossary || {}).map(([term, definition]) => ({ term, definition }));
  const draw = () => {
    const query = search.value.trim().toLowerCase();
    const topicMatches = topics.filter((topic) => `${topic.title || topic.name || ""} ${topic.summary || topic.body || topic.content || ""}`.toLowerCase().includes(query));
    const termMatches = glossary.filter((item) => `${item.term || item.name || ""} ${item.meaning || item.definition || item.description || ""}`.toLowerCase().includes(query));
    resultCount.textContent = `${topicMatches.length} setup topic${topicMatches.length === 1 ? "" : "s"} and ${termMatches.length} glossary term${termMatches.length === 1 ? "" : "s"} shown.`;
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
  if (!requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE, CAPABILITY.VIEW_AUDIT)) return;
  const canViewAggregate = hasCapability(CAPABILITY.VIEW_AGGREGATE);
  const canViewAudit = hasCapability(CAPABILITY.VIEW_AUDIT);
  root.appendChild(el("h2", { text: "Dashboard" }));
  root.appendChild(el("p", { class: "sub", text: "System health and recent campaign activity." }));
  let status, campaigns, audit;
  try {
    [status, campaigns, audit] = await Promise.all([
      canViewAggregate ? api("/console/status") : Promise.resolve(null),
      canViewAggregate ? boundedCollection("/campaigns") : Promise.resolve([]),
      canViewAudit ? api("/audit/verify", { method: "POST" }) : Promise.resolve(null),
    ]);
  } catch (e) {
    root.appendChild(collectionLoadError(`Failed to load dashboard: ${e.message}`, () => render()));
    return;
  }
  if (status) root.appendChild(statusPills(status));
  if (status && runtimeCapabilities(status).managed && status.status_message) {
    root.appendChild(el("div", { class: "notice", role: "status", text: status.status_message }));
  }
  const workerNames = Object.entries(status?.workers || {});
  const workerRow = el("div", { class: "status-row" });
  for (const [name, value] of workerNames) {
    const known = typeof value === "boolean";
    const stateClass = known ? (value ? "ok" : "down") : "";
    const label = known ? (value ? "running" : "stopped") : "unknown";
    workerRow.appendChild(el("span", { class: `pill ${stateClass}`.trim(), text: `worker ${name}: ${label}` }));
  }
  if (workerNames.length) root.appendChild(workerRow);

  if (canViewAudit) {
    root.appendChild(el("div", { class: "card" }, [
      el("h3", { text: "Audit chain" }),
      el("p", { text: audit && audit.ok ? "Chain integrity verified." : `Chain problems: ${JSON.stringify(audit && audit.problems)}` }),
    ]));
  }

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
  if (canViewAggregate) {
    root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Campaigns" }), table]));
  }
};

/* ---------- campaigns ---------- */
async function campaignReadinessContext() {
  const [runtimeResult, onboardingResult, integrationResult, killResult, domainsResult, roesResult] =
    await Promise.allSettled([
      api("/console/status"),
      hasCapability(CAPABILITY.MANAGE_ROLES) ? api("/console/onboarding") : Promise.resolve(null),
      api("/integrations/microsoft365/status"),
      hasCapability(CAPABILITY.USE_KILL_SWITCH) ? api("/kill-switch") : Promise.resolve(null),
      hasCapability(CAPABILITY.VERIFY_DOMAIN)
        ? boundedCollection("/sending-domains", "domains").then((domains) => ({ domains }))
        : Promise.resolve(null),
      hasCapability(CAPABILITY.SIGN_ROE)
        ? boundedCollection("/roe", "roes").then((roes) => ({ roes }))
        : Promise.resolve(null),
    ]);
  const value = (result) => result.status === "fulfilled" ? result.value : null;
  const runtime = value(runtimeResult);
  const onboarding = value(onboardingResult);
  const integration = value(integrationResult);
  const steps = new Map((onboarding?.steps || []).map((step) => [step.id, step]));
  return {
    runtime,
    managed: runtime ? runtimeCapabilities(runtime).managed : null,
    mailer: steps.get("smtp") || null,
    training: steps.get("training") || null,
    integration,
    kill: value(killResult),
    domains: value(domainsResult)?.domains || null,
    roes: value(roesResult)?.roes || null,
  };
}

function readinessForCampaign(campaign, context, enforcing) {
  const frozen = Boolean(campaign.audience_frozen && !campaign.audience_legacy);
  const approvedStates = new Set(["approved", "scheduled", "sending", "active", "completed"]);
  const approvalsReady = enforcing ? approvedStates.has(campaign.state) : campaign.state !== "pending_approval";
  const windowStart = Date.parse(campaign.schedule_start || "");
  const windowEnd = Date.parse(campaign.schedule_end || "");
  const coveringRoes = context.roes === null ? null : context.roes.filter((roe) => {
    const starts = Date.parse(roe.window_start || "");
    const ends = Date.parse(roe.window_end || "");
    return !roe.revoked_at && Number.isFinite(windowStart) && Number.isFinite(windowEnd)
      && Number.isFinite(starts) && Number.isFinite(ends) && starts <= windowStart && ends >= windowEnd;
  });
  const activeDomainCount = context.domains === null
    ? null : context.domains.filter((domain) => domain.active).length;
  const managed = context.managed === true;
  const localDeliveryWorker = managed ? null : context.runtime?.workers?.delivery;
  let mailerReady = null;
  if (!managed && (context.mailer?.ready === false || localDeliveryWorker === false)) mailerReady = false;
  if (!managed && context.mailer?.ready === true && localDeliveryWorker === true) mailerReady = true;
  const mailbox = context.integration?.reported_mailbox;
  const reportingReady = mailbox
    ? Boolean(mailbox.configured && mailbox.status === "healthy")
    : null;

  return [
    {
      key: "audience", label: "Exact audience", required: true, ready: frozen,
      detail: frozen
        ? `Frozen manifest v${campaign.audience_version}; the server rechecks it before queueing.`
        : campaign.audience_legacy
          ? "Legacy campaign has no usable exact manifest. Configure, preview, and freeze it again."
          : "Configure, preview, and freeze at least one exact recipient before approval.",
      destination: "campaigns",
    },
    {
      key: "lesson", label: "Exact training lesson", required: true,
      ready: campaign.training_lesson?.ready === true,
      detail: campaign.training_lesson?.ready
        ? `${campaign.training_lesson.title}, version ${campaign.training_lesson.bound_version}, content ${campaign.training_lesson.bound_content_digest.slice(0, 12)}…. The server rechecks approval, version and content before scheduling and assignment.`
        : campaign.training_lesson?.error || "Choose an approved training lesson and review the campaign again.",
      destination: "campaigns",
    },
    {
      key: "canary", label: "Canary evidence", required: campaign.state === "scheduled",
      ready: campaign.launch_gate?.state === "canary_succeeded"
        || campaign.launch_gate?.state === "full_published",
      detail: campaign.launch_gate?.state === "canary_succeeded"
        ? `Successful server-derived ${campaign.launch_gate.provider || "provider"} evidence is bound to this launch manifest.`
        : campaign.launch_gate?.state === "full_published"
          ? "The successful canary evidence was consumed by full publication."
          : "Run the locked canary cohort and wait for provider evidence before full publication.",
      destination: "campaigns",
    },
    {
      key: "approvals", label: "Approvals", required: true, ready: approvalsReady,
      detail: enforcing
        ? (approvalsReady
          ? "Security and privacy review is complete according to the campaign state."
          : campaign.state === "draft"
            ? "Submit the frozen draft, then have one independent authorized operator complete both security and privacy review facets."
            : "Security and privacy approval is still pending; the creator cannot approve either facet, while one independent authorized operator may complete both.")
        : "Single-admin development mode does not require separate campaign approvals.",
      destination: "campaigns",
    },
    {
      key: "roe", label: "RoE and target domains", required: true,
      ready: coveringRoes === null ? null : Boolean(frozen && coveringRoes.length),
      detail: coveringRoes === null
        ? "This console could not read RoE evidence. The scheduling API will revalidate it and fail closed."
        : coveringRoes.length
          ? `${coveringRoes.length} unrevoked RoE record${coveringRoes.length === 1 ? "" : "s"} cover the campaign window; ${activeDomainCount ?? "unknown"} domain proof${activeDomainCount === 1 ? " is" : "s are"} currently active. The scheduling API validates the signature and exact recipient-domain coverage.`
          : "No active signed RoE covers the entire campaign window. Verify the target domain and sign an RoE before scheduling.",
      destination: "sending",
    },
    {
      key: "mailer", label: "Mailer and delivery worker", required: true, ready: mailerReady,
      detail: managed
        ? "Azure-managed mail configuration is not exposed to this console; server and worker checks remain authoritative."
        : mailerReady
          ? "The mailer is configured and the local delivery worker is running."
          : mailerReady === false
            ? (localDeliveryWorker === false
              ? "The local delivery worker is stopped. Start it from the setup workflow before scheduling."
              : "Complete the required Email delivery step in the setup wizard.")
            : "Mailer readiness could not be read. The delivery worker will fail closed if it is unavailable.",
      destination: "onboarding",
    },
    {
      key: "training", label: "Training destination", required: true,
      ready: managed ? null : context.training?.ready ?? null,
      detail: managed
        ? "Azure-managed training configuration is not exposed here; tracking validates the destination at use time."
        : context.training?.ready
          ? "A training URL and exact training-domain allowlist are configured."
          : context.training
            ? "Complete the required Training experience step before scheduling."
            : "Training readiness could not be read; the API remains authoritative.",
      destination: "onboarding",
    },
    {
      key: "reporting", label: "Reported-mail pipeline", required: false, ready: reportingReady,
      detail: reportingReady
        ? "The dedicated reported-message mailbox integration is healthy."
        : reportingReady === false
          ? (context.integration?.mailbox_poll_unavailable_reason || "Reported-mail integration is not healthy. Campaigns can run, but report-rate evidence will be incomplete.")
          : "Reported-mail readiness is unavailable. This does not authorize or block delivery.",
      destination: "recipients",
    },
    {
      key: "kill", label: "Emergency stop", required: true,
      ready: context.kill === null ? null : !context.kill.engaged,
      detail: context.kill === null
        ? "Emergency-stop state could not be read. The scheduling API checks it transactionally."
        : context.kill.engaged
          ? `Global emergency stop generation ${context.kill.generation} is engaged. Reset it from Audit only after resolving the incident.`
          : `Global emergency stop is clear (generation ${context.kill.generation}).`,
      destination: "audit",
    },
  ];
}

function campaignReadinessView(checks, campaignTitle) {
  const blockers = checks.filter((check) => check.required && check.ready === false);
  const serverChecks = checks.filter((check) => check.required && check.ready === null);
  const details = el("details", { class: "readiness", "data-readiness-blockers": String(blockers.length) });
  details.appendChild(el("summary", {
    text: blockers.length
      ? `${blockers.length} blocker${blockers.length === 1 ? "" : "s"}`
      : `${serverChecks.length ? `${serverChecks.length} server verification${serverChecks.length === 1 ? "" : "s"} · ` : ""}Ready for server check`,
    "aria-label": blockers.length
      ? `${campaignTitle}: ${blockers.length} readiness blocker${blockers.length === 1 ? "" : "s"}`
      : `${campaignTitle}: ready for authoritative server check`,
    title: blockers.length ? blockers.map((check) => check.label).join(", ") : "Known client-side checks passed",
  }));
  const list = el("ul", { "aria-label": "Campaign readiness checks" });
  for (const check of checks) {
    const state = check.ready === true ? "Ready" : check.ready === false ? (check.required ? "Blocked" : "Needs attention") : "Verify";
    const item = el("li", { "data-readiness-key": check.key });
    item.appendChild(el("strong", { text: `${state}: ${check.label}. ` }));
    item.appendChild(document.createTextNode(check.detail));
    if (check.ready !== true && check.destination !== "campaigns" && canNavigateTo(check.destination)) {
      item.appendChild(document.createTextNode(" "));
      item.appendChild(el("button", {
        class: "btn small", type: "button", text: "Open",
        "aria-label": `Open ${check.label} configuration`,
        onclick: () => navigateTo(check.destination),
      }));
    } else if (check.ready !== true && check.destination !== "campaigns") {
      item.appendChild(document.createTextNode(" An operator with access to that configuration must complete this check."));
    }
    list.appendChild(item);
  }
  details.appendChild(list);
  return details;
}

views.campaigns = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)) return;
  const canCreateCampaign = hasCapability(CAPABILITY.CREATE_CAMPAIGN);
  const canViewNamedResults = hasCapability(CAPABILITY.VIEW_NAMED_RESULTS);
  const canSubscribeAlerts = hasCapability(CAPABILITY.SUBSCRIBE_ALERTS);
  const policy = (sessionInfo() || {}).approvalPolicy || "single-admin";
  const enforcing = policy === "enforce";

  root.appendChild(el("h2", { text: "Campaigns" }));
  root.appendChild(el("p", { class: "sub", text: "Create, review and run awareness campaigns." }));

  // The approval rule is the single most confusing thing about this screen, so
  // state it up front rather than letting an operator discover it as a 409.
  const banner = el("div", { class: "policy-banner" });
  banner.appendChild(el("strong", { text: enforcing ? "Two-person approval is required. " : "Single-admin mode. " }));
  banner.appendChild(document.createTextNode(enforcing
    ? "A campaign must collect separate security and privacy approval facets before it can be scheduled. The creator cannot approve either facet; one different authorized operator may complete both, though the facets may also be split between authorized reviewers. Submit a draft for approval to start that process."
    : "One administrator can schedule a campaign without separate approvals. This is intended for the offline evaluation stack; deployments using an identity provider always require two-person approval."));
  root.appendChild(banner);

  let campaigns;
  try {
    campaigns = await boundedCollection("/campaigns");
    if (!Array.isArray(campaigns)) throw new Error("The server returned an invalid campaign list");
  } catch (e) {
    root.appendChild(collectionLoadError(`Failed to load campaigns: ${e.message}`, () => render())); return;
  }

  const dependencyResults = await Promise.allSettled([
    canCreateCampaign ? boundedCollection("/patterns") : Promise.resolve([]),
    canCreateCampaign ? boundedCollection("/templates") : Promise.resolve([]),
    api("/audience-groups"),
    canViewNamedResults
      ? api("/recipients?limit=500&offset=0").then((payload) => boundedRecipientPage(payload, 500))
      : Promise.resolve({ items: [], total: 0, limit: 500, offset: 0, truncated: false }),
    campaignReadinessContext(),
    canSubscribeAlerts ? boundedCollection("/alerts/subscriptions") : Promise.resolve([]),
    canCreateCampaign
      ? boundedCollection("/training-resources?approval_state=approved")
      : Promise.resolve([]),
  ]);
  const fallback = (index, value) => dependencyResults[index].status === "fulfilled"
    ? dependencyResults[index].value : value;
  const patternPayload = fallback(0, []);
  const templatePayload = fallback(1, []);
  const groupPayload = fallback(2, { groups: [] });
  const recipientPage = fallback(3, { items: [], total: 0, limit: 500, offset: 0, truncated: false });
  const recipients = recipientPage.items;
  const readinessContext = fallback(4, {
    runtime: null, managed: null, mailer: null, training: null, integration: null,
    kill: null, domains: null, roes: null,
  });
  const alertPayload = fallback(5, []);
  const trainingResourcePayload = fallback(6, []);
  const patternsLoaded = dependencyResults[0].status === "fulfilled" && Array.isArray(patternPayload);
  const templatesLoaded = dependencyResults[1].status === "fulfilled" && Array.isArray(templatePayload);
  const groupsLoaded = dependencyResults[2].status === "fulfilled"
    && groupPayload && Array.isArray(groupPayload.groups);
  const recipientPageLoaded = dependencyResults[3].status === "fulfilled";
  const namedRecipientSelectionComplete = canViewNamedResults
    && recipientPageLoaded && recipientPage.truncated === false;
  const alertsLoaded = dependencyResults[5].status === "fulfilled" && Array.isArray(alertPayload);
  const trainingResourcesLoaded = dependencyResults[6].status === "fulfilled"
    && Array.isArray(trainingResourcePayload);
  const patterns = patternsLoaded ? patternPayload : [];
  const templates = templatesLoaded ? templatePayload : [];
  const alertSubscriptions = alertsLoaded ? alertPayload : [];
  const approvedTrainingResources = trainingResourcesLoaded ? trainingResourcePayload : [];
  const dependencyLabels = [
    "patterns", "templates", "audience groups", "named recipients", "readiness", "alert subscriptions",
    "approved training lessons",
  ];
  const dependencyFailures = dependencyResults
    .map((result, index) => result.status === "rejected" ? `${dependencyLabels[index]}: ${result.reason.message}` : null)
    .filter(Boolean);
  if (dependencyResults[0].status === "fulfilled" && !patternsLoaded) dependencyFailures.push("patterns: invalid response");
  if (dependencyResults[1].status === "fulfilled" && !templatesLoaded) dependencyFailures.push("templates: invalid response");
  if (dependencyResults[2].status === "fulfilled" && !groupsLoaded) dependencyFailures.push("audience groups: invalid response");
  if (dependencyResults[5].status === "fulfilled" && !alertsLoaded) dependencyFailures.push("alert subscriptions: invalid response");
  if (dependencyResults[6].status === "fulfilled" && !trainingResourcesLoaded) dependencyFailures.push("approved training lessons: invalid response");
  if (dependencyFailures.length) {
    root.appendChild(collectionLoadError(
      `Some campaign data could not be loaded. No successful fallback is assumed. ${dependencyFailures.join(" ")}`,
      () => render(),
    ));
  }
  if (canViewNamedResults && recipientPage.truncated) {
    root.appendChild(el("div", {
      class: "modal-warn", role: "status",
      text: `Recipient selectors show the first ${recipients.length} of ${recipientPage.total} authorized records. Use an audience group when the intended recipient is not on this bounded page.`,
    }));
  }
  const approvedPatterns = patterns.filter((pattern) => pattern.approval_state === "approved");
  const approvedTemplates = templates.filter((template) => template.approval_state === "approved");
  const groups = groupsLoaded ? groupPayload.groups : [];
  const departments = [...new Set(recipients.map((r) => r.department).filter(Boolean))].sort();

  async function manageAlerts(campaign) {
    const campaignSubscriptions = alertSubscriptions.filter(
      (subscription) => subscription.campaign_id === campaign.campaign_id,
    );
    const { dlg, form: alertForm } = dialogShell(
      `Alerts for "${campaign.title}"`,
      "Only subscriptions owned by your signed-in account are shown and can be disabled.",
    );
    const rows = campaignSubscriptions.map((subscription) => {
      const disableButton = el("button", {
        class: "btn small danger", type: "button", text: "Disable",
        disabled: subscription.active ? null : "disabled",
      });
      disableButton.addEventListener("click", async () => {
        const confirmed = await confirmDialog({
          title: "Disable this alert subscription?",
          message: "Future campaign-state alerts will no longer be delivered through this channel.",
          detail: { Campaign: campaign.title, Channel: subscription.channel },
          confirmLabel: "Disable subscription",
          danger: true,
        });
        if (!confirmed) return;
        disableButton.disabled = true;
        try {
          await api(`/alerts/subscriptions/${encodeURIComponent(subscription.alert_subscription_id)}`, {
            method: "DELETE",
          });
          dlg.close();
          toast("Alert subscription disabled", "success");
          await render();
        } catch (err) {
          toast(err.message, "error");
          if (disableButton.isConnected) disableButton.disabled = false;
        }
      });
      return el("tr", {}, [
        el("td", { text: subscription.channel }),
        el("td", { text: subscription.destination_configured ? "Configured" : "In-app" }),
        el("td", { text: subscription.active ? "Active" : "Disabled" }),
        el("td", { text: subscription.last_delivery_at ? new Date(subscription.last_delivery_at).toLocaleString() : "Never" }),
        el("td", { class: "num", text: String(subscription.consecutive_failures || 0) }),
        el("td", {}, [disableButton]),
      ]);
    });
    alertForm.appendChild(el("table", { class: "report-table", "aria-label": "My campaign alert subscriptions" }, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "Channel" }), el("th", { text: "Destination" }),
        el("th", { text: "State" }), el("th", { text: "Last delivery" }),
        el("th", { text: "Failures" }), el("th", { text: "Action" }),
      ])]),
      el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", {
        class: "empty", colspan: 6, text: "You have no alert subscriptions for this campaign.",
      })])]),
    ]));
    const createButton = el("button", { class: "btn primary", type: "button", text: "Create subscription" });
    createButton.addEventListener("click", async () => {
      const values = await promptDialog({
        title: `New alert for "${campaign.title}"`,
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
      createButton.disabled = true;
      try {
        const result = await api("/alerts/subscriptions", { method: "POST", body: JSON.stringify({
          campaign_id: campaign.campaign_id, channel: values.channel, destination_url: values.destination,
        }) });
        dlg.close();
        toast("Alert subscription created", "success");
        await render();
        if (result.signing_secret) {
          showCopyable({
            title: "Signing secret",
            description: "Save this now — it is shown once and cannot be retrieved later. Use it to verify alert payload signatures.",
            value: result.signing_secret,
          });
        }
      } catch (err) {
        toast(err.message, "error");
        if (createButton.isConnected) createButton.disabled = false;
      }
    });
    alertForm.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Close", onclick: () => dlg.close() }),
      createButton,
    ]));
    openDialog(dlg);
  }

  const creationPrerequisites = [
    !approvedPatterns.length ? ["Approved pattern", "patterns", "Open patterns"] : null,
    !approvedTemplates.length ? ["Approved template", "templates", "Open template review"] : null,
    !approvedTrainingResources.length ? ["Approved training lesson", "training", "Open training lessons"] : null,
  ].filter(Boolean);
  if (canCreateCampaign && creationPrerequisites.length) {
    root.appendChild(el("section", {
      class: "card prerequisite-card", role: "status", "aria-labelledby": "campaign-prerequisite-title",
    }, [
      el("h3", { id: "campaign-prerequisite-title", text: "Before you create a campaign" }),
      el("p", { text: "Creation stays locked until the reviewed content below is available. Complete each item, then return and refresh Campaigns." }),
      el("ul", { class: "prerequisite-list" }, creationPrerequisites.map(([label, destination, action]) => el("li", {}, [
        el("span", { text: `${label} is missing. ` }),
        el("button", { class: "btn small", type: "button", text: action, onclick: () => navigateTo(destination) }),
      ]))),
    ]));
  }

  const form = el("fieldset", { disabled: canCreateCampaign ? null : "disabled" }, [
    el("legend", { text: "New campaign" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [
        el("label", { for: "c-title", text: "Title" }), el("input", { id: "c-title", required: "required", maxlength: "255" }),
        el("label", { for: "c-sender", text: "Sender mailbox" }), el("input", {
          id: "c-sender", type: "email", required: "required", maxlength: "255",
          placeholder: "security-awareness@your-verified-domain.example",
        }),
        el("label", { for: "c-sender-display", text: "Sender display name (persona)" }),
        el("input", { id: "c-sender-display", placeholder: "e.g. Account Security", "aria-describedby": "c-sender-help" }),
        el("p", { id: "c-sender-help", class: "field-help", text: "Shown in the From header; honored only when the mailbox is on a registered sending domain (KP_SENDING_DOMAINS), otherwise delivery falls back to the configured sender." }),
        el("label", { for: "c-tdomain", text: "Training domain" }), el("input", {
          id: "c-tdomain", required: "required", maxlength: "253", placeholder: "training.your-domain.example",
        }),
        el("label", { for: "c-max", text: "Max recipients" }), el("input", { id: "c-max", type: "number", min: "1", max: "10000", value: "1000" }),
      ]),
      el("div", {}, [
        el("label", { for: "c-pattern", text: "Pattern" }),
        el("select", { id: "c-pattern", disabled: approvedPatterns.length ? null : "disabled" }, approvedPatterns.map((p) => el("option", { value: p.campaign_pattern_id, text: p.lure_category }))),
        el("label", { for: "c-template", text: "Template version" }),
        el("select", { id: "c-template", disabled: approvedTemplates.length ? null : "disabled" }, approvedTemplates.map((t) => el("option", { value: t.template_version_id, text: `${t.version} ${t.subject}` }))),
        el("label", { for: "c-training-resource", text: "Training lesson" }),
        el("select", {
          id: "c-training-resource",
          required: "required",
          disabled: approvedTrainingResources.length ? null : "disabled",
        }, [
          el("option", { value: "", text: "Choose an approved lesson…", selected: "selected" }),
          ...approvedTrainingResources.map((resource) => el("option", {
            value: resource.training_resource_id,
            text: `${resource.title} · version ${resource.version}`,
          })),
        ]),
        (!approvedPatterns.length || !approvedTemplates.length || !approvedTrainingResources.length) ? el("p", {
          class: "modal-warn", role: "status",
          text: "Campaign creation is disabled until at least one pattern and one template are approved, and an approved training lesson is available in the GUI.",
        }) : null,
        el("label", { for: "c-start", text: "Start (your local time)" }), el("input", {
          id: "c-start", type: "datetime-local", required: "required", "aria-describedby": "c-time-help",
        }),
        el("label", { for: "c-end", text: "End (your local time)" }), el("input", {
          id: "c-end", type: "datetime-local", required: "required", "aria-describedby": "c-time-help",
        }),
        el("p", { id: "c-time-help", class: "field-help", text: `Times will be stored as absolute instants. Browser timezone: ${browserTimeZone()}.` }),
      ].filter(Boolean)),
    ]),
    el("div", { id: "campaign-create-error", class: "modal-error", role: "alert", tabindex: "-1" }),
    el("div", { class: "btn-row" }, [
      el("button", {
        class: "btn primary", type: "button", text: "Create campaign",
        disabled: canCreateCampaign && approvedPatterns.length && approvedTemplates.length && approvedTrainingResources.length ? null : "disabled",
        title: canCreateCampaign
          ? (approvedPatterns.length && approvedTemplates.length && approvedTrainingResources.length
            ? null
            : (!approvedPatterns.length || !approvedTemplates.length
              ? "Approve a pattern and a template first."
              : "Approve a training lesson first."))
          : "Campaign creation capability is required.",
        onclick: async (e) => {
        const btn = e.currentTarget;
        const createError = document.getElementById("campaign-create-error");
        createError.textContent = "";
        const invalidField = form.querySelector(":invalid");
        if (invalidField) {
          invalidField.reportValidity();
          invalidField.focus();
          createError.textContent = "Complete the highlighted required field before creating the campaign.";
          return;
        }
        btn.disabled = true;
        btn.setAttribute("aria-busy", "true");
        try {
          const title = document.getElementById("c-title").value.trim();
          const senderMailbox = document.getElementById("c-sender").value.trim();
          const trainingDomain = document.getElementById("c-tdomain").value.trim();
          const trainingResourceId = document.getElementById("c-training-resource").value;
          if (!title || !senderMailbox || !trainingDomain || !trainingResourceId) {
            throw new Error(
              "Title, sender mailbox, and training domain are required, along with an approved training lesson",
            );
          }
          const start = localDateTimeToIso(document.getElementById("c-start").value, "Start");
          const end = localDateTimeToIso(document.getElementById("c-end").value, "End");
          if (new Date(end) <= new Date(start)) throw new Error("End must be after start");
          await api("/campaigns", { method: "POST", body: JSON.stringify({
            pattern_id: document.getElementById("c-pattern").value,
            title,
            sender_mailbox: senderMailbox,
            sender_display_name: document.getElementById("c-sender-display").value.trim() || null,
            training_domain: trainingDomain,
            schedule_start: start,
            schedule_end: end,
            timezone: browserTimeZone(),
            max_recipients: Number(document.getElementById("c-max").value),
            template_version_id: document.getElementById("c-template").value,
            training_resource_id: trainingResourceId,
          }) });
          markFormSaved(form);
          toast("Campaign created", "success");
          location.reload();
        } catch (e) {
          createError.textContent = e.message;
          createError.focus();
        }
        finally { btn.disabled = false; btn.removeAttribute("aria-busy"); }
        },
      }),
    ]),
  ]);
  guardUnsavedForm(form, "New campaign draft");

  function selectedValues(select) {
    return [...select.selectedOptions].map((option) => option.value);
  }

  function groupEditor(existing = null) {
    const { dlg, form: dialogForm } = dialogShell(
      existing ? `Edit group: ${existing.name}` : "Create static audience group",
      "Static membership changes invalidate every frozen campaign that uses this group. A connected Entra group updates only through explicit directory preview and apply.",
    );
    const name = el("input", {
      id: "audience-group-name", value: existing ? existing.name : "", maxlength: "120", required: "required",
    });
    name.value = existing ? existing.name : "";
    const directoryRef = el("input", {
      id: "audience-group-directory-ref", value: existing ? (existing.directory_group_ref || "") : "",
      maxlength: "256", "aria-describedby": "audience-group-directory-help",
    });
    directoryRef.value = existing ? (existing.directory_group_ref || "") : "";
    const memberSelect = el("select", {
      id: "audience-group-members", multiple: "multiple", size: "10",
      "aria-describedby": "audience-group-members-help",
    });
    const existingIds = new Set(existing ? existing.recipient_ids || [] : []);
    for (const recipient of recipients) {
      memberSelect.appendChild(el("option", {
        value: recipient.recipient_id,
        selected: existingIds.has(recipient.recipient_id),
        text: `${recipient.department || "No department"} · ${recipient.recipient_id.slice(0, 8)} · ${recipient.status}`,
      }));
    }
    memberSelect.disabled = !namedRecipientSelectionComplete;
    dialogForm.appendChild(el("label", { for: "audience-group-name", text: "Group name" })); dialogForm.appendChild(name);
    dialogForm.appendChild(el("label", { for: "audience-group-directory-ref", text: "Future Entra group reference (optional)" })); dialogForm.appendChild(directoryRef);
    dialogForm.appendChild(el("p", { id: "audience-group-directory-help", class: "modal-help", text: "Membership changes only after a reviewed directory preview is explicitly applied." }));
    dialogForm.appendChild(el("label", { for: "audience-group-members", text: "Static members" })); dialogForm.appendChild(memberSelect);
    dialogForm.appendChild(el("p", {
      id: "audience-group-members-help",
      class: namedRecipientSelectionComplete ? "modal-help" : "modal-warn",
      text: namedRecipientSelectionComplete
        ? "Use Ctrl/Cmd-click to select more than one recipient."
        : "Static membership is locked because a complete, authorized recipient list is unavailable. Existing members will be preserved; a new group will start with no static members.",
    }));
    const error = el("div", { class: "modal-error", role: "alert" }); dialogForm.appendChild(error);
    dialogForm.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Cancel", onclick: () => dlg.close() }),
      el("button", { class: "btn primary", type: "button", text: "Save group", onclick: async (e) => {
        if (!name.value.trim()) { error.textContent = "Group name is required."; name.focus(); return; }
        e.currentTarget.disabled = true;
        try {
          const path = existing ? `/audience-groups/${existing.audience_group_id}` : "/audience-groups";
          await api(path, { method: existing ? "PUT" : "POST", body: JSON.stringify({
            name: name.value.trim(),
            directory_group_ref: directoryRef.value.trim() || null,
            recipient_ids: namedRecipientSelectionComplete
              ? selectedValues(memberSelect)
              : (Array.isArray(existing?.recipient_ids) ? existing.recipient_ids : []),
          }) });
          toast(existing ? "Audience group updated" : "Audience group created", "success");
          dlg.close(); location.reload();
        } catch (err) { error.textContent = err.message; e.currentTarget.disabled = false; }
      } }),
    ]));
    openDialog(dlg);
  }

  async function audienceEditor(campaign) {
    let current;
    try { current = await api(`/campaigns/${campaign.campaign_id}/audience`); }
    catch (err) {
      if (!await refreshAfterStaleActionFailure(err, render)) toast(err.message, "error");
      return;
    }
    const { dlg, form: dialogForm } = dialogShell(
      `Audience: ${campaign.title}`,
      "Choose explicit static selectors, preview the masked exact recipients, then freeze that manifest before approval. No free-form queries are accepted.",
    );
    const makeMulti = (items, selected, size = 6) => {
      const select = el("select", { multiple: "multiple", size: String(size) });
      const chosen = new Set(selected || []);
      for (const item of items) select.appendChild(el("option", { value: item.value, text: item.label, selected: chosen.has(item.value) }));
      return select;
    };
    const groupSelect = makeMulti(groups.map((g) => ({ value: g.audience_group_id, label: `${g.name} (${g.member_count})` })), current.group_ids);
    const departmentSelect = makeMulti(departments.map((d) => ({ value: d, label: d })), current.departments);
    const recipientOptions = recipients.map((r) => ({
      value: r.recipient_id,
      label: `${r.department || "No department"} · ${r.recipient_id.slice(0, 8)} · ${r.status}`,
    }));
    const includeSelect = makeMulti(recipientOptions, current.include_recipient_ids, 8);
    const excludeSelect = makeMulti(recipientOptions, current.exclude_recipient_ids, 8);
    groupSelect.disabled = !groupsLoaded;
    departmentSelect.disabled = !namedRecipientSelectionComplete;
    includeSelect.disabled = !namedRecipientSelectionComplete;
    excludeSelect.disabled = !namedRecipientSelectionComplete;
    const statusSelect = makeMulti([
      { value: "active", label: "Active" }, { value: "excluded", label: "Excluded" }, { value: "departed", label: "Departed" },
    ], current.statuses || ["active"], 3);
    const sampleSize = el("input", { type: "number", min: "1", max: "10000", value: current.sample_size || "" });
    sampleSize.value = current.sample_size || "";
    const sampleSeed = el("input", { maxlength: "128", value: current.sample_seed || "" }); sampleSeed.value = current.sample_seed || "";
    const fields = [
      ["Static groups", groupSelect], ["Departments", departmentSelect], ["Recipient status filter", statusSelect],
      ["Explicit recipients to include", includeSelect], ["Recipients to exclude", excludeSelect],
      ["Random sample size (optional)", sampleSize], ["Random sample seed (required with sample)", sampleSeed],
    ];
    fields.forEach(([label, input], index) => {
      const id = `audience-selector-${index}`;
      input.id = id;
      dialogForm.appendChild(el("label", { for: id, text: label }));
      dialogForm.appendChild(input);
    });
    dialogForm.appendChild(el("p", { class: "modal-help", text: "Selectors are deterministic. Active exclusions, domain policy and the signed RoE are always applied before sampling." }));
    if (!groupsLoaded || !namedRecipientSelectionComplete) {
      dialogForm.appendChild(el("p", {
        class: "modal-warn", role: "status",
        text: "Unavailable selectors are locked and their saved values will be preserved. The console never replaces missing or truncated dependency data with an empty selection.",
      }));
    }
    const previewBox = el("pre", {
      class: "mono", tabindex: "0", "aria-label": "Masked exact audience preview", text: "Preview not run.",
    });
    const previewGuidance = el("p", {
      id: "audience-preview-guidance", class: "modal-help", role: "status", "aria-live": "polite",
      text: "Save and preview to verify the exact masked audience before freezing.",
    });
    dialogForm.append(previewBox, previewGuidance);
    const error = el("div", { class: "modal-error", role: "alert" }); dialogForm.appendChild(error);
    let latestPreview = null;
    const freezeButton = el("button", {
      class: "btn primary", type: "button", text: "Freeze exact audience", disabled: "disabled",
      "aria-describedby": "audience-preview-guidance", onclick: async (e) => {
      if (!latestPreview) return;
      e.currentTarget.disabled = true;
      try {
        const frozen = await api(`/campaigns/${campaign.campaign_id}/audience/freeze`, {
          method: "POST", body: JSON.stringify({ preview_hash: latestPreview.preview_hash }),
        });
        toast(`Audience frozen: ${frozen.recipient_count} exact recipients`, "success");
        dlg.close(); location.reload();
      } catch (err) {
        if (STALE_ACTION_STATUSES.has(err?.status)) dlg.close();
        if (!await refreshAfterStaleActionFailure(err, render)) {
          error.textContent = err.message;
          e.currentTarget.disabled = false;
        }
      }
    } });
    const previewButton = el("button", { class: "btn", type: "button", text: "Save & preview", onclick: async (e) => {
      e.currentTarget.disabled = true; freezeButton.disabled = true; latestPreview = null; error.textContent = "";
      previewGuidance.textContent = "Building the exact audience preview…";
      try {
        const sample = sampleSize.value ? Number(sampleSize.value) : null;
        await api(`/campaigns/${campaign.campaign_id}/audience`, { method: "PUT", body: JSON.stringify({
          group_ids: groupsLoaded ? selectedValues(groupSelect) : (current.group_ids || []),
          departments: namedRecipientSelectionComplete ? selectedValues(departmentSelect) : (current.departments || []),
          statuses: selectedValues(statusSelect),
          include_recipient_ids: namedRecipientSelectionComplete
            ? selectedValues(includeSelect) : (current.include_recipient_ids || []),
          exclude_recipient_ids: namedRecipientSelectionComplete
            ? selectedValues(excludeSelect) : (current.exclude_recipient_ids || []),
          sample_size: sample,
          sample_seed: sampleSeed.value.trim() || null,
        }) });
        latestPreview = await api(`/campaigns/${campaign.campaign_id}/audience/preview`);
        previewBox.textContent = [
          `Selected: ${latestPreview.selected_count}`,
          `Included: ${latestPreview.included_count}`,
          `Excluded: ${latestPreview.excluded_count} ${JSON.stringify(latestPreview.excluded_counts)}`,
          `Diff: +${latestPreview.diff.added} / -${latestPreview.diff.removed} / =${latestPreview.diff.unchanged}`,
          `Sample: ${latestPreview.sample_size || "all"}; seed: ${latestPreview.sample_seed || "none"}`,
          `RoE: ${latestPreview.roe_id || "none"}`,
          ...latestPreview.recipients.slice(0, 25).map((r) => `${r.mailbox} · ${r.department || "No department"}`),
          ...(latestPreview.recipients.length > 25 ? [`… ${latestPreview.recipients.length - 25} more masked recipients`] : []),
        ].join("\n");
        const freezeBlockers = [
          latestPreview.included_count < 1 ? "at least one eligible recipient is required" : null,
          latestPreview.over_limit ? "the result exceeds this campaign's recipient limit" : null,
          !latestPreview.roe_id ? "a signed Rules of Engagement must cover this campaign window" : null,
        ].filter(Boolean);
        freezeButton.disabled = Boolean(freezeBlockers.length);
        previewGuidance.textContent = freezeBlockers.length
          ? `Cannot freeze yet: ${freezeBlockers.join("; ")}.`
          : "Preview is eligible to freeze. Review the masked recipients, then select Freeze exact audience.";
      } catch (err) {
        if (STALE_ACTION_STATUSES.has(err?.status)) dlg.close();
        if (!await refreshAfterStaleActionFailure(err, render)) {
          error.textContent = err.message;
          previewGuidance.textContent = "Preview failed. Correct the reported problem and retry; no audience was frozen.";
        }
      }
      finally { if (e.currentTarget.isConnected) e.currentTarget.disabled = false; }
    } });
    dialogForm.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Cancel", onclick: () => dlg.close() }), previewButton, freezeButton,
    ]));
    openDialog(dlg);
  }

  async function openCampaignReview(campaign) {
    let review;
    try { review = await api(`/campaigns/${campaign.campaign_id}/review`); }
    catch (err) { toast(err.message, "error"); return; }
    const lesson = review.training_lesson || {};
    const { dlg, form: reviewForm } = dialogShell(
      `Campaign review: ${campaign.title}`,
      "This is the exact training lesson binding included in the campaign review manifest.",
    );
    reviewForm.appendChild(el("dl", { class: "modal-detail" }, [
      el("dt", { text: "Binding" }), el("dd", { text: lesson.ready ? "Valid" : "Blocked" }),
      el("dt", { text: "Lesson" }), el("dd", { text: lesson.title || "Missing" }),
      el("dt", { text: "Version" }), el("dd", { text: lesson.bound_version || "Missing" }),
      el("dt", { text: "Content digest" }), el("dd", { class: "mono", text: lesson.bound_content_digest || "Missing" }),
      el("dt", { text: "Campaign manifest" }), el("dd", { class: "mono", text: review.manifest_hash || "Missing" }),
      el("dt", { text: "Launch review" }), el("dd", { class: "mono", text: review.launch_review?.review_manifest_hash || "Not bound" }),
      el("dt", { text: "Canary cohort" }), el("dd", { text: `${review.launch_review?.canary_recipient_count || 0} locked test account(s)` }),
      el("dt", { text: "Launch phase" }), el("dd", { text: review.launch_review?.state || "unreviewed" }),
    ]));
    if (!lesson.ready) reviewForm.appendChild(el("div", {
      class: "modal-warn", role: "alert", text: lesson.error || "Training lesson binding is invalid.",
    }));
    if (!review.launch_review?.ready) reviewForm.appendChild(el("div", {
      class: "modal-warn", role: "alert",
      text: review.launch_review?.error || "The immutable launch review is not yet bound.",
    }));
    reviewForm.appendChild(el("h4", { class: "modal-section", text: "Recipient lesson content" }));
    reviewForm.appendChild(el("pre", {
      class: "mono", tabindex: "0", "aria-label": "Exact recipient training lesson content",
      text: lesson.content || "No lesson content is available.",
    }));
    if (lesson.knowledge_check && typeof lesson.knowledge_check === "object") {
      reviewForm.appendChild(el("h4", { class: "modal-section", text: "Campaign-bound knowledge check" }));
      reviewForm.appendChild(el("p", { text: String(lesson.knowledge_check.question || "") }));
      const checkList = el("ol", {});
      (Array.isArray(lesson.knowledge_check.options) ? lesson.knowledge_check.options : [])
        .forEach((option, index) => {
          checkList.appendChild(el("li", {
            text: `${option}${Number.isInteger(lesson.knowledge_check.answer_index)
              && index === lesson.knowledge_check.answer_index ? " — correct answer" : ""}`,
          }));
        });
      reviewForm.appendChild(checkList);
    } else {
      reviewForm.appendChild(el("p", { class: "field-help", text: "This lesson has no campaign-bound knowledge check; recipients see the generic knowledge check." }));
    }
    reviewForm.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => dlg.close() }),
    ]));
    openDialog(dlg);
  }

  function trainingEditor(campaign) {
    const currentId = campaign.training_lesson?.ready
      ? campaign.training_lesson.training_resource_id : "";
    const { dlg, form: trainingForm } = dialogShell(
      `Training lesson: ${campaign.title}`,
      "Choose one approved lesson explicitly. Changing a reviewed campaign resets it to draft and removes its prior approvals.",
    );
    const select = el("select", { id: "campaign-training-resource", required: "required" }, [
      el("option", { value: "", text: "Choose an approved lesson…", selected: currentId ? null : "selected" }),
      ...approvedTrainingResources.map((resource) => el("option", {
        value: resource.training_resource_id,
        text: `${resource.title} · version ${resource.version}`,
        selected: resource.training_resource_id === currentId ? "selected" : null,
      })),
    ]);
    trainingForm.appendChild(el("label", { for: "campaign-training-resource", text: "Approved training lesson" }));
    trainingForm.appendChild(select);
    if (!trainingResourcesLoaded || !approvedTrainingResources.length) trainingForm.appendChild(el("div", {
      class: "modal-warn", role: "alert",
      text: trainingResourcesLoaded
        ? "No approved training lesson is available. Create and approve one in Training lessons first."
        : "Approved training lessons could not be loaded. Refresh before changing this binding.",
    }));
    if (trainingResourcesLoaded && !approvedTrainingResources.length && canNavigateTo("training")) {
      trainingForm.appendChild(el("button", {
        class: "btn small", type: "button", text: "Open training lessons",
        onclick: async () => { dlg.close(); await navigateTo("training"); },
      }));
    }
    const error = el("div", { class: "modal-error", role: "alert" });
    trainingForm.appendChild(error);
    trainingForm.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn", type: "button", text: "Cancel", onclick: () => dlg.close() }),
      el("button", {
        class: "btn primary", type: "button", text: "Bind exact lesson",
        disabled: approvedTrainingResources.length ? null : "disabled",
        onclick: async (event) => {
          if (!select.value) { error.textContent = "Choose an approved lesson."; return; }
          event.currentTarget.disabled = true;
          try {
            const result = await api(`/campaigns/${campaign.campaign_id}/training-resource`, {
              method: "PUT", body: JSON.stringify({ training_resource_id: select.value }),
            });
            toast(result.changed ? "Training lesson bound; campaign review reset" : "Training lesson unchanged", "success");
            dlg.close(); location.reload();
          } catch (err) {
            if (!await refreshAfterStaleActionFailure(err, render)) error.textContent = err.message;
            if (event.currentTarget.isConnected) event.currentTarget.disabled = false;
          }
        },
      }),
    ]));
    openDialog(dlg);
  }

  const groupCard = el("div", { class: "card" }, [
    el("h3", { text: "Static audience groups" }),
    el("p", { class: "field-help", text: "Reusable named membership. Connected Entra groups update through the reviewed directory preview/apply workflow." }),
    !namedRecipientSelectionComplete ? el("p", {
      class: "modal-warn", role: "status",
      text: "Static membership editing is locked until the complete authorized recipient set is available. Name and Entra reference changes preserve existing static members.",
    }) : null,
    canCreateCampaign
      ? el("div", { class: "btn-row" }, [el("button", { class: "btn", type: "button", text: "Create group", onclick: () => groupEditor() })])
      : el("p", { class: "modal-help", text: "Audience-group changes require campaign-author capability." }),
    el("ul", {}, groups.map((group) => el("li", {}, [
      el("span", { text: `${group.name}: ${group.member_count} member${group.member_count === 1 ? "" : "s"}` }),
      ...(canCreateCampaign ? [el("button", {
        class: "btn small", type: "button", text: "Edit",
        "aria-label": `Edit audience group ${group.name}`, onclick: () => groupEditor(group),
      })] : []),
    ]))),
  ].filter(Boolean));

  const list = el("table", { "aria-label": "Campaign status, readiness, and actions" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Title" }), el("th", { text: "Sender" }), el("th", { text: "Audience" }), el("th", { text: "Training lesson" }), el("th", { text: "RoE" }), el("th", { text: "State" }), el("th", { text: "Readiness" }), el("th", { text: "Actions" }),
    ])]),
    el("tbody", {}, campaigns.map((c) => {
      const readiness = readinessForCampaign(c, readinessContext, enforcing);
      const blockers = readiness.filter((check) => check.required && check.ready === false);
      const blockedReason = blockers.map((check) => `${check.label}: ${check.detail}`).join(" ");
      const actionAuthorityValid = hasBooleanActionFlags(c, CAMPAIGN_ACTION_FLAGS);
      return el("tr", {}, [
      el("td", { text: c.title }),
      el("td", { text: c.sender_display_name ? `${c.sender_display_name} <${c.sender_mailbox}>` : c.sender_mailbox }),
      el("td", {}, [el("span", { class: `pill ${c.audience_frozen ? "ok" : "down"}`, text: c.audience_frozen ? `frozen v${c.audience_version}` : "not frozen" })]),
      el("td", {}, [el("span", {
        class: `pill ${c.training_lesson?.ready ? "ok" : "down"}`,
        text: c.training_lesson?.ready
          ? `${c.training_lesson.title} · v${c.training_lesson.bound_version}`
          : "reconfiguration required",
        title: c.training_lesson?.ready
          ? `Content ${c.training_lesson.bound_content_digest}`
          : (c.training_lesson?.error || "No exact training lesson is bound."),
      })]),
      el("td", {}, [el("span", {
        class: `pill ${c.roe_bound ? "ok" : "down"}`,
        text: c.roe_bound ? "bound" : "missing",
        title: c.roe_bound
          ? "A signed Rules-of-Engagement covers this campaign's delivery."
          : "No Rules-of-Engagement is bound — delivery fails closed (no_roe). Re-schedule the campaign to bind one.",
      })]),
      el("td", { text: c.state }),
      el("td", {}, [campaignReadinessView(readiness, c.title)]),
      el("td", {}, (() => {
        const actions = [];
        if (!actionAuthorityValid) {
          actions.push(actionAuthorityUnavailable("Campaign", async (event) => {
            event.currentTarget.disabled = true;
            await render();
          }));
        } else {
          if (c.can_configure_audience === true) {
            actions.push(el("button", {
              class: "btn small", type: "button",
              text: c.audience_frozen ? "Review audience" : "Configure audience",
              "aria-label": `${c.audience_frozen ? "Review audience" : "Configure audience"} for ${c.title}`,
              onclick: () => audienceEditor(c),
            }));
          }
          if (c.can_configure_training === true) {
            actions.push(el("button", {
              class: "btn small", type: "button", text: "Choose lesson",
              "aria-label": `Choose training lesson for ${c.title}`,
              disabled: trainingResourcesLoaded && approvedTrainingResources.length ? null : "disabled",
              title: trainingResourcesLoaded
                ? (approvedTrainingResources.length ? null : "Approve a training lesson first.")
                : "Approved training lessons are unavailable; refresh before changing the binding.",
              onclick: () => trainingEditor(c),
            }));
          }
          if (c.can_submit === true) {
            actions.push(el("button", {
              class: "btn small primary", type: "button",
              text: enforcing ? "Submit for approval" : "Lock launch review",
              "aria-label": `${enforcing ? "Submit for approval" : "Lock launch review"}: ${c.title}`,
              onclick: act(`/campaigns/${c.campaign_id}/submit`, enforcing
                ? "Submitted for approval" : "Launch review locked"),
            }));
          }
          if (c.can_approve_security === true) {
            actions.push(el("button", { class: "btn small", type: "button", text: "Approve security", "aria-label": `Approve security review for ${c.title}`, onclick: approvalAct(c, "security", "approved") }));
            actions.push(el("button", { class: "btn small danger", type: "button", text: "Reject security", "aria-label": `Reject security review for ${c.title}`, onclick: approvalAct(c, "security", "rejected") }));
          }
          if (c.can_approve_privacy === true) {
            actions.push(el("button", { class: "btn small", type: "button", text: "Approve privacy", "aria-label": `Approve privacy review for ${c.title}`, onclick: approvalAct(c, "privacy", "approved") }));
            actions.push(el("button", { class: "btn small danger", type: "button", text: "Reject privacy", "aria-label": `Reject privacy review for ${c.title}`, onclick: approvalAct(c, "privacy", "rejected") }));
          }
          if (c.can_schedule === true) {
            const scheduleButton = el("button", {
              class: "btn small primary", type: "button",
              text: "Review & run canary",
              "aria-label": `Review and run locked canary for ${c.title}`,
              disabled: blockers.length ? "disabled" : null,
              title: blockers.length ? blockedReason : null,
              onclick: scheduleAct(c, readiness),
            });
            actions.push(scheduleButton);
          }
          if (c.can_publish === true) {
            actions.push(el("button", {
              class: "btn small primary", type: "button", text: "Publish full audience",
              "aria-label": `Publish exact full audience for ${c.title}`,
              disabled: blockers.length ? "disabled" : null,
              title: blockers.length ? blockedReason : "Uses the exact reviewed manifest and successful canary evidence.",
              onclick: publishAct(c),
            }));
          }
          if (c.can_recall === true) {
            actions.push(el("button", {
              class: "btn small danger", type: "button", text: "Recall",
              "aria-label": `Recall campaign ${c.title}`,
              onclick: act(`/campaigns/${c.campaign_id}/recall`, "Recall initiated"),
            }));
          }
        }
        actions.push(el("button", {
          class: "btn small", type: "button", text: "Review campaign",
          "aria-label": `Review campaign ${c.title}`,
          onclick: () => openCampaignReview(c),
        }));
        // Emergency stop, reports and owner-scoped alert subscriptions use
        // separate server controls and are intentionally not campaign flags.
        if (["scheduled", "sending", "active"].includes(c.state) && hasCapability(CAPABILITY.USE_KILL_SWITCH)) actions.push(el("button", { class: "btn small danger", type: "button", text: "Kill switch", "aria-label": `Engage kill switch for ${c.title}`, onclick: (async (e) => {
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
            await render();
          } catch (err) { toast(err.message, "error"); }
          finally { if (e.target.isConnected) e.target.disabled = false; }
        }) }));
        actions.push(el("button", { class: "btn small", type: "button", text: "Report", "aria-label": `Open aggregate report for ${c.title}`, onclick: async (e) => {
          e.target.disabled = true;
          try {
            await openCampaignAnalytics(c);
          } catch (err) { toast(err.message, "error"); }
          finally { e.target.disabled = false; }
        } }));
        if (canSubscribeAlerts) actions.push(el("button", {
          class: "btn small", type: "button", text: alertsLoaded ? "Manage alerts" : "Alerts unavailable",
          "aria-label": `${alertsLoaded ? "Manage alerts" : "Alerts unavailable"} for ${c.title}`,
          disabled: alertsLoaded ? null : "disabled",
          title: alertsLoaded ? "List, create, or disable your campaign alerts." : "Alert subscriptions could not be loaded.",
          onclick: () => manageAlerts(c),
        }));
        return [el("div", { class: "btn-row", role: "group", "aria-label": `Actions for ${c.title}` }, actions)];
      })()),
      ]);
    })),
  ]);

  root.appendChild(form);
  root.appendChild(groupCard);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "All campaigns" }), list]));

  function act(path, successMsg) {
    return async (e) => {
      const btn = e.currentTarget; btn.disabled = true;
      try { await api(path, { method: "POST" }); toast(successMsg, "success"); location.reload(); }
      catch (err) {
        if (!await refreshAfterStaleActionFailure(err, render)) toast(err.message, "error");
      }
      finally { if (btn.isConnected) btn.disabled = false; }
    };
  }

  function approvalAct(campaign, approvalType, decision) {
    return async (e) => {
      const approving = decision === "approved";
      let review;
      try { review = await api(`/campaigns/${campaign.campaign_id}/review`); }
      catch (err) { toast(err.message, "error"); return; }
      const lesson = review.training_lesson || {};
      if (!lesson.ready) {
        toast(lesson.error || "The exact training lesson binding is not reviewable.", "error");
        await render();
        return;
      }
      const values = await promptDialog({
        title: `${approving ? "Approve" : "Reject"}: ${approvalType} review`,
        description: `Campaign "${campaign.title}". Exact lesson: "${lesson.title}", version ${lesson.bound_version}, content digest ${lesson.bound_content_digest}. Use Review campaign to read the complete lesson. This decision is recorded in the audit chain against your identity.`,
        fields: [
          { name: "rationale", label: "Rationale", type: "textarea", required: true,
            placeholder: approving ? "Why this campaign is safe to run" : "What must change before this can run",
            help: "The campaign creator cannot approve either facet. One independent operator with both capabilities may complete both security and privacy facets, and each decision remains separately recorded." },
        ],
        submitLabel: approving ? "Record approval" : "Record rejection",
      });
      if (!values) return;
      const rationale = values.rationale;
      const btn = e.currentTarget; btn.disabled = true;
      try {
        await api(`/campaigns/${campaign.campaign_id}/approvals/${approvalType}`, {
          method: "POST",
          body: JSON.stringify({ decision, rationale: rationale.trim() }),
        });
        toast(`${approvalType} review recorded as ${decision}`, "success");
        location.reload();
      } catch (err) {
        if (!await refreshAfterStaleActionFailure(err, render)) toast(err.message, "error");
      }
      finally { if (btn.isConnected) btn.disabled = false; }
    };
  }

  function scheduleAct(campaign, readiness) {
    return async (e) => {
      const ok = await confirmDialog({
        title: `Run the locked canary for "${campaign.title}"?`,
        message: "The server will queue only the test accounts locked into the reviewed manifest. The full audience remains blocked until successful provider evidence is recorded.",
        detail: {
          "Frozen audience": `version ${campaign.audience_version}`,
          "Approval policy": enforcing ? "security + privacy" : "single-admin development",
          "Training lesson": campaign.training_lesson?.ready
            ? `${campaign.training_lesson.title} · version ${campaign.training_lesson.bound_version} · ${campaign.training_lesson.bound_content_digest}`
            : "Invalid binding — scheduling will fail closed",
          Start: formatInstant(campaign.schedule_start),
          End: formatInstant(campaign.schedule_end),
          "Time zone": browserTimeZone(),
          "Reported mail": readiness.find((check) => check.key === "reporting")?.ready === true ? "ready" : "not confirmed (non-blocking)",
          Canary: "Only the reviewed, server-marked test cohort is queued in this phase",
        },
        confirmLabel: "Queue locked canary",
      });
      if (!ok) return;
      const btn = e.currentTarget; btn.disabled = true;
      try {
        const res = await api(`/campaigns/${campaign.campaign_id}/schedule`, { method: "POST" });
        toast(`Canary queued: ${res.queued} locked test account${res.queued === 1 ? "" : "s"}`, "success");
        location.reload();
      }
      catch (err) {
        if (!await refreshAfterStaleActionFailure(err, render)) toast(err.message, "error");
      }
      finally { if (btn.isConnected) btn.disabled = false; }
    };
  }

  function publishAct(campaign) {
    return async (e) => {
      const ok = await confirmDialog({
        title: `Publish "${campaign.title}" to the full audience?`,
        message: "The server will recheck the reviewed manifest, approvals, RoE, emergency stop, provider configuration and unexpired canary evidence before queueing non-canary recipients.",
        detail: {
          "Campaign start": formatInstant(campaign.schedule_start),
          Provider: campaign.launch_gate?.provider || "Evidence unavailable",
          "Canary evidence": campaign.launch_gate?.canary_evidence_hash || "Missing",
        },
        confirmLabel: "Publish exact audience",
      });
      if (!ok) return;
      const btn = e.currentTarget; btn.disabled = true;
      try {
        const result = await api(`/campaigns/${campaign.campaign_id}/publish`, { method: "POST" });
        toast(`Full audience queued: ${result.queued} recipient${result.queued === 1 ? "" : "s"}`, "success");
      } catch (err) {
        if (!await refreshAfterStaleActionFailure(err, render)) toast(err.message, "error");
      }
      finally { if (btn.isConnected) btn.disabled = false; }
    };
  }
};

/* ---------- finite campaign programs ---------- */
views.programs = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)) return;
  const canCreateProgram = hasCapability(CAPABILITY.CREATE_CAMPAIGN);
  const canChangeProgramState = hasCapability(CAPABILITY.SCHEDULE_CAMPAIGN);
  root.appendChild(el("h2", { text: "Program planner" }));
  root.appendChild(el("p", {
    class: "sub",
    text: "Create a bounded timeline of independent campaign drafts from one reviewed, scheduled campaign.",
  }));
  root.appendChild(el("div", { class: "policy-banner" }, [
    el("strong", { text: "Independent review remains mandatory. " }),
    document.createTextNode("The first occurrence is the existing scheduled source. Every later occurrence is a separate draft with an unfrozen audience, no copied approvals and no Rules-of-Engagement binding. Review, freeze, approve and schedule each one from Campaigns."),
  ]));
  root.appendChild(el("p", {
    class: "modal-warn",
    text: "Pausing blocks future scheduling attempts. It does not recall or cancel work that is already scheduled or queued; use the campaign Recall or emergency-stop controls when those actions are required.",
  }));
  root.appendChild(el("p", {
    class: "field-help",
    text: "Cadence uses fixed elapsed days in UTC. A local wall-clock time can shift when daylight-saving time changes.",
  }));

  let programs;
  let campaigns;
  try {
    [programs, campaigns] = await Promise.all([
      boundedCollection("/programs"),
      boundedCollection("/campaigns"),
    ]);
  } catch (e) {
    root.appendChild(collectionLoadError(`Failed to load programs: ${e.message}`, () => render()));
    return;
  }

  const existingSources = new Set(programs.map((program) => program.source_campaign_id));
  const sources = campaigns.filter((campaign) => campaign.state === "scheduled"
    && campaign.audience_frozen && campaign.roe_bound
    && Date.parse(campaign.schedule_start || "") > Date.now()
    && !existingSources.has(campaign.campaign_id));
  const sourceSelect = el("select", { id: "program-source", disabled: sources.length ? null : "disabled" },
    sources.map((campaign) => el("option", {
      value: campaign.campaign_id,
      text: `${campaign.title} · ${formatUtcInstant(campaign.schedule_start)}`,
    })));
  const cadenceSelect = el("select", { id: "program-cadence" }, [
    el("option", { value: "7", text: "Every 7 days" }),
    el("option", { value: "14", text: "Every 14 days" }),
    el("option", { value: "28", text: "Every 28 days", selected: "selected" }),
    el("option", { value: "84", text: "Every 84 days" }),
  ]);
  const countInput = el("input", { id: "program-count", type: "number", min: "2", max: "12", value: "3" });
  const timelinePreview = el("div", { class: "field-help", role: "status" });

  function selectedSource() {
    return sources.find((campaign) => campaign.campaign_id === sourceSelect.value) || null;
  }

  function programTimeline() {
    const source = selectedSource();
    const count = Number(countInput.value);
    const cadenceDays = Number(cadenceSelect.value);
    if (!source || !Number.isInteger(count) || count < 2 || count > 12) return null;
    const firstStart = new Date(source.schedule_start);
    const firstEnd = new Date(source.schedule_end);
    if (Number.isNaN(firstStart.getTime()) || Number.isNaN(firstEnd.getTime())) return null;
    const interval = cadenceDays * 24 * 60 * 60 * 1000;
    const occurrences = Array.from({ length: count }, (_, index) => ({
      occurrenceNumber: index + 1,
      start: new Date(firstStart.getTime() + (interval * index)).toISOString(),
      end: new Date(firstEnd.getTime() + (interval * index)).toISOString(),
    }));
    return {
      source, count, cadenceDays, occurrences,
      firstStart: occurrences[0].start,
      finalEnd: occurrences[occurrences.length - 1].end,
    };
  }

  function updateTimelinePreview() {
    const timeline = programTimeline();
    timelinePreview.textContent = timeline
      ? `Exact UTC window: ${timeline.firstStart} through ${timeline.finalEnd}. ${timeline.count} total occurrences.`
      : "Choose an eligible source and enter 2–12 occurrences to review the exact UTC window.";
  }
  sourceSelect.addEventListener("change", updateTimelinePreview);
  cadenceSelect.addEventListener("change", updateTimelinePreview);
  countInput.addEventListener("input", updateTimelinePreview);
  updateTimelinePreview();

  const createButton = el("button", {
    class: "btn primary", type: "button", text: "Review & create finite program",
    disabled: canCreateProgram && sources.length ? null : "disabled",
    title: canCreateProgram ? null : "Campaign creation capability is required.",
    onclick: async (event) => {
      const timeline = programTimeline();
      if (!timeline) { toast("Choose a source and enter 2–12 occurrences.", "error"); return; }
      const reviewDetail = {
        "Source campaign": timeline.source.title,
        "Cadence": `${timeline.cadenceDays} fixed elapsed days (UTC)`,
      };
      for (const occurrence of timeline.occurrences) {
        reviewDetail[`Run ${occurrence.occurrenceNumber} (UTC)`] = `${occurrence.start} — ${occurrence.end}`;
      }
      reviewDetail["Future occurrences"] = "Draft, audience unfrozen, approvals absent, RoE unbound";
      const confirmed = await confirmDialog({
        title: `Create ${timeline.count}-occurrence program?`,
        message: "This creates the complete finite timeline now. Only the existing source remains scheduled; every later occurrence must pass the normal campaign review gates independently.",
        detail: reviewDetail,
        confirmLabel: "Create program drafts",
      });
      if (!confirmed) return;
      event.target.disabled = true;
      try {
        const result = await api("/programs", { method: "POST", body: JSON.stringify({
          source_campaign_id: timeline.source.campaign_id,
          cadence_days: timeline.cadenceDays,
          occurrence_count: timeline.count,
        }) });
        toast(result.created ? "Finite campaign program created" : "Existing matching program loaded", "success");
        location.reload();
      } catch (e) { toast(e.message, "error"); }
      finally { event.target.disabled = false; }
    },
  });
  root.appendChild(el("fieldset", { disabled: canCreateProgram ? null : "disabled" }, [
    el("legend", { text: "New finite program" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [el("label", { for: "program-source", text: "Reviewed scheduled source" }), sourceSelect]),
      el("div", {}, [
        el("label", { for: "program-cadence", text: "Cadence" }), cadenceSelect,
        el("label", { for: "program-count", text: "Total occurrences" }), countInput,
      ]),
    ]),
    timelinePreview,
    sources.length ? null : el("p", {
      class: "modal-warn",
      text: "No eligible source is available. Schedule a campaign with a frozen audience and bound Rules-of-Engagement first.",
    }),
    canCreateProgram ? null : el("p", {
      class: "modal-warn",
      text: "Your role can review programs but cannot create campaign drafts.",
    }),
    el("div", { class: "btn-row" }, [createButton]),
  ].filter(Boolean)));

  async function reviewTimeline(program) {
    let detail;
    try { detail = await api(`/programs/${program.campaign_program_id}`); }
    catch (e) { toast(e.message, "error"); return; }
    const { dlg, form } = dialogShell(
      `Program ${program.campaign_program_id.slice(0, 8)} timeline`,
      "Times below are exact UTC instants. Campaign IDs and lifecycle states are shown; recipient and message content are not included.",
    );
    form.appendChild(el("p", {
      class: "modal-warn",
      text: "Each draft occurrence requires its own audience freeze, approvals, Rules-of-Engagement binding and final schedule review.",
    }));
    form.appendChild(el("table", { class: "report-table" }, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "Run" }), el("th", { text: "Campaign ID" }), el("th", { text: "State" }),
        el("th", { text: "Start UTC" }), el("th", { text: "End UTC" }),
      ])]),
      el("tbody", {}, detail.occurrences.map((occurrence) => el("tr", {}, [
        el("td", { class: "num", text: String(occurrence.occurrence_number) }),
        el("td", { class: "mono", text: occurrence.campaign_id }),
        el("td", { text: occurrence.state }),
        el("td", { class: "mono", text: formatUtcInstant(occurrence.schedule_start) }),
        el("td", { class: "mono", text: formatUtcInstant(occurrence.schedule_end) }),
      ]))),
    ]));
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => dlg.close() }),
    ]));
    openDialog(dlg);
  }

  function changeState(program, target) {
    return async (event) => {
      const pausing = target === "pause";
      const values = await promptDialog({
        title: `${pausing ? "Pause" : "Resume"} program?`,
        description: pausing
          ? "Pausing blocks later scheduling attempts, but does not recall or cancel work already scheduled or queued."
          : "Resuming permits later occurrences to be scheduled only after each campaign passes its independent review gates.",
        fields: [{
          name: "rationale", label: "Audit rationale", type: "textarea", required: true, maxLength: 500,
          placeholder: pausing ? "Why future scheduling must stop" : "Why future scheduling may resume",
        }],
        submitLabel: pausing ? "Pause future scheduling" : "Resume future scheduling",
      });
      if (!values) return;
      event.target.disabled = true;
      try {
        await api(`/programs/${program.campaign_program_id}/${target}`, {
          method: "POST",
          body: JSON.stringify({ expected_version: program.version, rationale: values.rationale }),
        });
        toast(`Program ${pausing ? "paused" : "resumed"}`, "success");
        location.reload();
      } catch (e) { toast(e.message, "error"); }
      finally { event.target.disabled = false; }
    };
  }

  const table = el("table", {}, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Program" }), el("th", { text: "State" }), el("th", { text: "Cadence" }),
      el("th", { text: "Occurrences" }), el("th", { text: "Updated UTC" }), el("th", { text: "Actions" }),
    ])]),
    el("tbody", {}, programs.length ? programs.map((program) => {
      const actions = [el("button", {
        class: "btn small", type: "button", text: "Review exact UTC timeline", onclick: () => reviewTimeline(program),
      })];
      if (!program.complete && canChangeProgramState) actions.push(el("button", {
        class: program.state === "active" ? "btn small danger" : "btn small primary",
        type: "button",
        text: program.state === "active" ? "Pause" : "Resume",
        onclick: changeState(program, program.state === "active" ? "pause" : "resume"),
      }));
      return el("tr", {}, [
        el("td", { class: "mono", text: program.campaign_program_id }),
        el("td", {}, [el("span", {
          class: `pill ${program.complete ? "ok" : program.state === "active" ? "ok" : "down"}`,
          text: program.complete ? "complete" : program.state,
        })]),
        el("td", { text: `${program.cadence_days} days` }),
        el("td", { class: "num", text: String(program.occurrence_count) }),
        el("td", { class: "mono", text: formatUtcInstant(program.updated_at) }),
        el("td", {}, actions),
      ]);
    }) : [el("tr", {}, [el("td", { class: "empty", colspan: 6, text: "No campaign programs yet." })])]),
  ]);
  root.appendChild(el("div", { class: "card" }, [el("h3", { text: "Programs" }), table]));
};

/* ---------- sending domains & rules of engagement ----------
   The authorization boundary, operated from here: prove DNS control of a
   domain (onboarding wizard + lookalike generator), then sign the
   Rules-of-Engagement that delivery fails closed without. */
views.sending = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VERIFY_DOMAIN, CAPABILITY.SIGN_ROE)) return;
  const canVerifyDomains = hasCapability(CAPABILITY.VERIFY_DOMAIN);
  const canSignRoe = hasCapability(CAPABILITY.SIGN_ROE);
  root.appendChild(el("h2", { text: "Domains & Rules of Engagement" }));
  root.appendChild(el("p", { class: "sub", text: "Prove you control a domain via DNS, then sign the RoE that authorizes delivery to it." }));

  let domains, roes;
  try {
    const [d, r] = await Promise.all([
      canVerifyDomains
        ? boundedCollection("/sending-domains", "domains").then((items) => ({ domains: items }))
        : Promise.resolve({ domains: [] }),
      canSignRoe
        ? boundedCollection("/roe", "roes").then((items) => ({ roes: items }))
        : Promise.resolve({ roes: [] }),
    ]);
    domains = d.domains || [];
    roes = r.roes || [];
  } catch (e) {
    root.appendChild(collectionLoadError(`Failed to load domains or Rules of Engagement: ${e.message}`, () => render()));
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

  async function revokeDomain(d) {
    const ok = await confirmDialog({
      title: `Revoke verification for ${d.domain}?`,
      message: "The domain can no longer be named in a new Rules-of-Engagement. Campaigns under an existing RoE keep running until that RoE is revoked or its window ends.",
      detail: { Domain: d.domain, "Verified at": formatInstant(d.verified_at) },
      confirmLabel: "Revoke verification", danger: true,
    });
    if (!ok) return;
    try {
      await api(`/sending-domains/${encodeURIComponent(d.domain)}/revoke`, { method: "POST" });
      toast(`Verification for ${d.domain} revoked`, "success");
      location.reload();
    } catch (err) { toast(err.message, "error"); }
  }

  /* --- verified domains --- */
  const domainRows = domains.length ? domains.map((d) => el("tr", {}, [
    el("td", { text: d.domain }),
    el("td", { class: "mono", text: formatInstant(d.verified_at) }),
    el("td", {}, [el("span", { class: `pill ${d.active ? "ok" : "down"}`, text: d.active ? "verified" : "revoked" })]),
    el("td", {}, d.active ? [el("button", { class: "btn small danger", text: "Revoke", onclick: () => revokeDomain(d) })] : []),
  ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 4, text: "No verified domains yet. Onboard one below." })])];
  if (canVerifyDomains) root.appendChild(el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [
      el("h3", { text: "Verified domains" }),
      el("div", { class: "btn-row" }, [
        el("button", { class: "btn", text: "Lookalike generator", onclick: lookalike }),
        el("button", { class: "btn primary", text: "Onboard a sending domain", onclick: onboard }),
      ]),
    ]),
    el("p", { class: "field-help", text: "A domain is verified only when its DNS-TXT challenge is observable in live DNS. Verified domains can be named in an RoE (recipients) and used as sending domains (KP_SENDING_DOMAINS)." }),
    el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", { text: "Domain" }), el("th", { text: "Verified at" }), el("th", { text: "Status" }), el("th", { text: "" })])]), el("tbody", {}, domainRows)]),
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
  if (canSignRoe) root.appendChild(el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [
      el("h3", { text: "Rules of Engagement" }),
      el("div", { class: "btn-row" }, [el("button", { class: "btn primary", text: "Sign RoE", onclick: signRoe })]),
    ]),
    el("p", { class: "field-help", text: "Scheduling and delivery require an unrevoked RoE whose window contains the campaign window and whose target domains cover every recipient." }),
    el("table", {}, [el("thead", {}, [el("tr", {}, [el("th", { text: "Authorizing party" }), el("th", { text: "Signer" }), el("th", { text: "Window" }), el("th", { text: "Target domains" }), el("th", { text: "Status" }), el("th", { text: "" })])]), el("tbody", {}, roeRows)]),
  ]));
};

/* ---------- executive campaign trends ---------- */
views.trends = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VIEW_AGGREGATE)) return;
  const canExportTrend = hasCapability(CAPABILITY.EXPORT_BULK);
  root.appendChild(el("h2", { text: "Executive campaign trends" }));
  root.appendChild(el("p", {
    class: "sub",
    text: "A bounded portfolio view of up to 12 terminal campaigns, measured as campaign-assignment exposures.",
  }));
  root.appendChild(el("div", { class: "policy-banner" }, [
    el("strong", { text: "Interpretation boundary. " }),
    document.createTextNode("Destination MTA handoff is not inbox delivery, placement, display or reading. Current snapshots are not causal evidence. Normalizations and scanner or bot corrections are not silently applied."),
  ]));
  root.appendChild(el("p", {
    class: "field-help",
    text: "Counts are campaign-assignment exposures, not unique people. Weighted rates sum event numerators and denominators across campaigns; they do not average campaign percentages.",
  }));

  const now = new Date();
  const priorYear = new Date(now.getTime() - (365 * 24 * 60 * 60 * 1000));
  const startInput = el("input", {
    id: "trend-start", type: "datetime-local", step: "60", value: priorYear.toISOString().slice(0, 16),
  });
  const endInput = el("input", {
    id: "trend-end", type: "datetime-local", step: "60", value: now.toISOString().slice(0, 16),
  });
  const statusLine = el("p", { class: "field-help", role: "status", "aria-live": "polite" });
  const results = el("div", { "aria-live": "polite" });

  function selectedWindow() {
    const start = new Date(`${startInput.value}:00Z`);
    const end = new Date(`${endInput.value}:00Z`);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
      throw new Error("Enter valid UTC start and end times.");
    }
    if (start >= end) throw new Error("Trend end must be after trend start.");
    if (end.getTime() - start.getTime() > 366 * 24 * 60 * 60 * 1000) {
      throw new Error("Trend window cannot exceed 366 days.");
    }
    return { start: start.toISOString(), end: end.toISOString() };
  }

  function trendQuery() {
    const window = selectedWindow();
    return new URLSearchParams({
      schedule_start: window.start,
      schedule_end: window.end,
      limit: "12",
    });
  }

  function readableMetric(value) {
    return String(value || "").replaceAll("_", " ");
  }

  function rateValue(rate) {
    return rate.denominator === 0 || rate.value === null
      ? "N/A"
      : `${(rate.value * 100).toFixed(1)}%`;
  }

  function rateSummary(rate) {
    return `${rate.numerator} / ${rate.denominator} ${readableMetric(rate.denominator_name)} · ${rateValue(rate)}`;
  }

  function trendTable(report) {
    const portfolioRates = el("table", { class: "report-table", "aria-label": "Weighted portfolio rates" }, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "Event" }), el("th", { text: "Weighted event count" }),
        el("th", { text: "Denominator" }), el("th", { text: "Weighted rate" }),
      ])]),
      el("tbody", {}, report.portfolio.rates.map((rate) => el("tr", {}, [
        el("td", { text: readableMetric(rate.name) }),
        el("td", { class: "num", text: String(rate.numerator) }),
        el("td", { text: `${rate.denominator} ${readableMetric(rate.denominator_name)}` }),
        el("td", { class: "num", text: rateValue(rate) }),
      ]))),
    ]);
    const countSummary = report.portfolio.counts
      .map((metric) => `${readableMetric(metric.name)} ${metric.value}`)
      .join(" · ");
    const points = el("table", { class: "report-table", "aria-label": "Campaign exposure trend points" }, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "Campaign reference" }), el("th", { text: "Schedule start UTC" }),
        el("th", { text: "State" }), el("th", { text: "Clicked exposures" }),
        el("th", { text: "Reported exposures" }), el("th", { text: "Training completion exposures" }),
      ])]),
      el("tbody", {}, report.points.length ? report.points.map((point) => {
        const rates = new Map(point.rates.map((rate) => [rate.name, rate]));
        return el("tr", {}, [
          el("td", { class: "mono", text: point.campaign_id }),
          el("td", { class: "mono", text: formatUtcInstant(point.schedule_start) }),
          el("td", { text: point.state }),
          el("td", { text: rateSummary(rates.get("clicked")) }),
          el("td", { text: rateSummary(rates.get("reported")) }),
          el("td", { text: rateSummary(rates.get("training_completed")) }),
        ]);
      }) : [el("tr", {}, [el("td", {
        class: "empty", colspan: 6, text: "No terminal campaign exposures fall in this UTC schedule window.",
      })])]),
    ]);
    return el("div", {}, [
      el("p", { text: `Generated ${formatUtcInstant(report.generated_at)} · ${report.points.length} of at most 12 campaigns` }),
      report.truncated ? el("p", {
        class: "modal-warn", role: "alert",
        text: "More campaigns matched than can be shown. Narrow the UTC window; this view does not silently omit the warning.",
      }) : null,
      el("p", { class: "field-help", text: `Portfolio event counts: ${countSummary || "none"}.` }),
      el("h3", { text: "Weighted portfolio summary" }),
      portfolioRates,
      el("h3", { text: "Campaign exposure snapshots" }),
      points,
      el("p", {
        class: "field-help",
        text: "This snapshot includes retained engagement evidence and current transport state at one cutoff. It does not establish causal training efficacy.",
      }),
    ].filter(Boolean));
  }

  async function loadTrend() {
    results.replaceChildren(el("p", { class: "empty", text: "Loading aggregate trend…" }));
    const query = trendQuery();
    const report = await api(`/analytics/campaigns/trend?${query.toString()}`);
    statusLine.textContent = `UTC selection: ${formatUtcInstant(report.selection_start_inclusive)} through ${formatUtcInstant(report.selection_end_exclusive)} (exclusive).`;
    results.replaceChildren(trendTable(report));
  }

  async function downloadTrendCsv() {
    const query = trendQuery();
    await downloadApiCsv(
      `/analytics/campaigns/trend.csv?${query.toString()}`,
      "campaign-trend-analytics.csv",
    );
  }

  const refreshButton = el("button", { class: "btn primary", type: "button", text: "Refresh trend", onclick: async (event) => {
    event.target.disabled = true;
    try { await loadTrend(); } catch (e) {
      results.replaceChildren(el("div", { role: "alert", class: "modal-error", text: e.message }));
    } finally { event.target.disabled = false; }
  } });
  const exportButton = el("button", {
    class: "btn", type: "button", text: "Download aggregate CSV",
    disabled: canExportTrend ? null : "disabled",
    title: canExportTrend ? null : "Bulk export capability is required.",
    onclick: async (event) => {
    event.target.disabled = true;
    try { await downloadTrendCsv(); } catch (e) { toast(e.message, "error"); }
    finally { event.target.disabled = false; }
    },
  });
  root.appendChild(el("fieldset", {}, [
    el("legend", { text: "UTC schedule-start window" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [el("label", { for: "trend-start", text: "Start UTC (inclusive)" }), startInput]),
      el("div", {}, [el("label", { for: "trend-end", text: "End UTC (exclusive)" }), endInput]),
    ]),
    statusLine,
    el("div", { class: "btn-row" }, [refreshButton, exportButton]),
  ]));
  root.appendChild(results);
  try { await loadTrend(); } catch (e) {
    results.replaceChildren(el("div", { role: "alert", class: "modal-error", text: e.message }));
  }

  /* ---------- five-year pseudonymous awareness ledger ---------- */
  root.appendChild(el("h2", { text: "Five-year awareness ledger trend" }));
  root.appendChild(el("p", {
    class: "sub",
    text: "Monthly click/no-click projections from the pseudonymous awareness ledger, retained 1,826 days after each terminal campaign date. Months with no projected exposures are omitted.",
  }));
  const ledgerNow = new Date();
  const fiveYearsAgo = new Date(ledgerNow.getTime() - (1826 * 24 * 60 * 60 * 1000));
  const ledgerStart = el("input", {
    id: "ledger-trend-start", type: "date", value: fiveYearsAgo.toISOString().slice(0, 10),
  });
  const ledgerEnd = el("input", {
    id: "ledger-trend-end", type: "date", value: ledgerNow.toISOString().slice(0, 10),
  });
  const ledgerStatus = el("p", { class: "field-help", role: "status", "aria-live": "polite" });
  const ledgerResults = el("div", { "aria-live": "polite" });

  function ledgerWindow() {
    const start = new Date(`${ledgerStart.value}T00:00:00Z`);
    const end = new Date(`${ledgerEnd.value}T00:00:00Z`);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
      throw new Error("Enter valid ledger trend start and end dates.");
    }
    if (start >= end) throw new Error("Ledger trend end must be after start.");
    if (end.getTime() - start.getTime() > 1826 * 24 * 60 * 60 * 1000) {
      throw new Error("Ledger trend window cannot exceed 1,826 days.");
    }
    return new URLSearchParams({
      window_start: ledgerStart.value,
      window_end: ledgerEnd.value,
    });
  }

  function ledgerTable(report) {
    const rows = report.buckets.map((bucket) => {
      const rates = new Map(bucket.rates.map((rate) => [rate.name, rate]));
      const clicked = rates.get("clicked");
      const noClick = rates.get("no_click");
      const confirmed = rates.get("confirmed_interaction");
      const trained = rates.get("training_completed");
      const counts = new Map(bucket.counts.map((metric) => [metric.name, metric.value]));
      return el("tr", {}, [
        el("td", { class: "mono", text: bucket.month }),
        el("td", { class: "num", text: String(counts.get("targeted")) }),
        el("td", { class: "num", text: String(counts.get("delivered")) }),
        el("td", { text: rateSummary(clicked) }),
        el("td", { text: rateSummary(noClick) }),
        el("td", { text: rateSummary(confirmed) }),
        el("td", { text: rateSummary(trained) }),
      ]);
    });
    return el("div", {}, [
      el("p", { text: `Generated ${formatUtcInstant(report.generated_at)} · ${report.buckets.length} month(s) with projected exposures` }),
      el("table", { class: "report-table", "aria-label": "Five-year pseudonymous awareness ledger trend" }, [
        el("thead", {}, [el("tr", {}, [
          el("th", { text: "Month" }), el("th", { text: "Targeted exposures" }),
          el("th", { text: "Delivered exposures" }), el("th", { text: "Clicked" }),
          el("th", { text: "No click" }), el("th", { text: "Confirmed interaction" }),
          el("th", { text: "Training completed" }),
        ])]),
        el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", {
          class: "empty", colspan: 7, text: "No projected exposures fall in this date window.",
        })])]),
      ]),
      el("p", {
        class: "field-help",
        text: "Ledger counts are pseudonymous assignment-exposure projections, not unique people, and are not raw inbox or reading evidence. A delivered exposure without a recorded click is an explicit no-click bucket; scanner or bot corrections are never silently subtracted.",
      }),
    ]);
  }

  async function loadLedgerTrend() {
    ledgerResults.replaceChildren(el("p", { class: "empty", text: "Loading ledger trend…" }));
    const query = ledgerWindow();
    const report = await api(`/analytics/ledger/trend?${query.toString()}`);
    ledgerStatus.textContent = `Ledger window: ${report.window_start_inclusive} through ${report.window_end_exclusive} (exclusive).`;
    ledgerResults.replaceChildren(ledgerTable(report));
  }

  async function downloadLedgerTrendCsv() {
    const query = ledgerWindow();
    await downloadApiCsv(
      `/analytics/ledger/trend.csv?${query.toString()}`,
      "awareness-ledger-trend.csv",
    );
  }

  const ledgerRefresh = el("button", { class: "btn primary", type: "button", text: "Refresh ledger trend", onclick: async (event) => {
    event.target.disabled = true;
    try { await loadLedgerTrend(); } catch (e) {
      ledgerResults.replaceChildren(el("div", { role: "alert", class: "modal-error", text: e.message }));
    } finally { event.target.disabled = false; }
  } });
  const ledgerExport = el("button", {
    class: "btn", type: "button", text: "Download ledger CSV",
    disabled: canExportTrend ? null : "disabled",
    title: canExportTrend ? null : "Bulk export capability is required.",
    onclick: async (event) => {
      event.target.disabled = true;
      try { await downloadLedgerTrendCsv(); } catch (e) { toast(e.message, "error"); }
      finally { event.target.disabled = false; }
    },
  });
  root.appendChild(el("fieldset", {}, [
    el("legend", { text: "Ledger campaign-date window (UTC)" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [el("label", { for: "ledger-trend-start", text: "Start date (inclusive)" }), ledgerStart]),
      el("div", {}, [el("label", { for: "ledger-trend-end", text: "End date (exclusive)" }), ledgerEnd]),
    ]),
    ledgerStatus,
    el("div", { class: "btn-row" }, [ledgerRefresh, ledgerExport]),
  ]));
  root.appendChild(ledgerResults);
  try { await loadLedgerTrend(); } catch (e) {
    ledgerResults.replaceChildren(el("div", { role: "alert", class: "modal-error", text: e.message }));
  }

  /* ---------- repeat exposure history ---------- */
  root.appendChild(el("h2", { text: "Repeat exposure history" }));
  root.appendChild(el("p", {
    class: "sub",
    text: "Distinct pseudonymous participants by number of exposures (and by exposures with retained human activity) in the selected campaign-date window. The final bucket means at least that many exposures.",
  }));
  const repeatsStart = el("input", {
    id: "ledger-repeats-start", type: "date", value: fiveYearsAgo.toISOString().slice(0, 10),
  });
  const repeatsEnd = el("input", {
    id: "ledger-repeats-end", type: "date", value: ledgerNow.toISOString().slice(0, 10),
  });
  const repeatsStatus = el("p", { class: "field-help", role: "status", "aria-live": "polite" });
  const repeatsResults = el("div", { "aria-live": "polite" });

  function repeatsWindow() {
    const start = new Date(`${repeatsStart.value}T00:00:00Z`);
    const end = new Date(`${repeatsEnd.value}T00:00:00Z`);
    if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
      throw new Error("Enter valid repeat history start and end dates.");
    }
    if (start >= end) throw new Error("Repeat history end must be after start.");
    if (end.getTime() - start.getTime() > 1826 * 24 * 60 * 60 * 1000) {
      throw new Error("Repeat history window cannot exceed 1,826 days.");
    }
    return new URLSearchParams({
      window_start: repeatsStart.value,
      window_end: repeatsEnd.value,
    });
  }

  function repeatsTable(report) {
    const summary = new Map(report.summary.map((metric) => [metric.name, metric.value]));
    const rates = new Map(report.rates.map((rate) => [rate.name, rate]));
    const rows = report.exposure_buckets.map((bucket) => {
      const label = bucket.exposures === 5 ? "5 or more" : String(bucket.exposures);
      const engaged = report.engaged_buckets.find((candidate) => candidate.exposures === bucket.exposures);
      return el("tr", {}, [
        el("td", { text: label }),
        el("td", { class: "num", text: String(bucket.participants) }),
        el("td", { class: "num", text: String(engaged ? engaged.participants : 0) }),
      ]);
    });
    return el("div", {}, [
      el("p", {
        text: `Generated ${formatUtcInstant(report.generated_at)} · ${summary.get("unique_exposed")} distinct exposed participants, ${summary.get("exposures_total")} total exposures.`,
      }),
      el("table", { class: "report-table", "aria-label": "Repeat exposure history" }, [
        el("thead", {}, [el("tr", {}, [
          el("th", { text: "Exposures" }), el("th", { text: "Participants" }),
          el("th", { text: "With activity" }),
        ])]),
        el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", {
          class: "empty", colspan: 3, text: "No projected exposures fall in this date window.",
        })])]),
      ]),
      el("p", {
        class: "field-help",
        text: `Repeat exposure: ${rateSummary(rates.get("repeat_exposure"))} of distinct exposed participants. Pseudonymous ledger participants are never resolved to identities.`,
      }),
    ]);
  }

  async function loadLedgerRepeats() {
    repeatsResults.replaceChildren(el("p", { class: "empty", text: "Loading repeat history…" }));
    const query = repeatsWindow();
    const report = await api(`/analytics/ledger/repeats?${query.toString()}`);
    repeatsStatus.textContent = `Repeat window: ${report.window_start_inclusive} through ${report.window_end_exclusive} (exclusive).`;
    repeatsResults.replaceChildren(repeatsTable(report));
  }

  async function downloadLedgerRepeatsCsv() {
    const query = repeatsWindow();
    await downloadApiCsv(
      `/analytics/ledger/repeats.csv?${query.toString()}`,
      "awareness-ledger-repeats.csv",
    );
  }

  const repeatsRefresh = el("button", { class: "btn primary", type: "button", text: "Refresh repeat history", onclick: async (event) => {
    event.target.disabled = true;
    try { await loadLedgerRepeats(); } catch (e) {
      repeatsResults.replaceChildren(el("div", { role: "alert", class: "modal-error", text: e.message }));
    } finally { event.target.disabled = false; }
  } });
  const repeatsExport = el("button", {
    class: "btn", type: "button", text: "Download repeat CSV",
    disabled: canExportTrend ? null : "disabled",
    title: canExportTrend ? null : "Bulk export capability is required.",
    onclick: async (event) => {
      event.target.disabled = true;
      try { await downloadLedgerRepeatsCsv(); } catch (e) { toast(e.message, "error"); }
      finally { event.target.disabled = false; }
    },
  });
  root.appendChild(el("fieldset", {}, [
    el("legend", { text: "Repeat campaign-date window (UTC)" }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [el("label", { for: "ledger-repeats-start", text: "Start date (inclusive)" }), repeatsStart]),
      el("div", {}, [el("label", { for: "ledger-repeats-end", text: "End date (exclusive)" }), repeatsEnd]),
    ]),
    repeatsStatus,
    el("div", { class: "btn-row" }, [repeatsRefresh, repeatsExport]),
  ]));
  root.appendChild(repeatsResults);
  try { await loadLedgerRepeats(); } catch (e) {
    repeatsResults.replaceChildren(el("div", { role: "alert", class: "modal-error", text: e.message }));
  }
};

/* ---------- template review ----------
   The human gate on AI-generated content. Until a draft is approved here it
   cannot be scheduled, so this screen is what stops an unreviewed model output
   reaching a recipient. */
async function showTemplatePreview(draft, trigger) {
  trigger.disabled = true;
  let rendered;
  try {
    rendered = await api("/templates/preview", {
      method: "POST",
      body: JSON.stringify({
        subject: draft.subject || "",
        plain_text: draft.plain_text || "",
        safe_html: draft.safe_html || "",
      }),
    });
  } catch (err) {
    toast(err.message, "error");
    trigger.disabled = false;
    return;
  }
  trigger.disabled = false;

  showRenderedTemplatePreview(rendered);
}

function showRenderedTemplatePreview(rendered) {
  const { dlg, form } = dialogShell(
    `Preview: ${rendered.subject || "(no subject)"}`,
    "Rendered with the server's non-delivery sample recipient. Previewing does not approve, schedule, or send this message.",
  );
  dlg.classList.add("modal-wide");
  const status = el("p", { class: "modal-help", role: "status", "aria-live": "polite" });
  const stage = el("div", { "aria-label": "Rendered message preview" });
  const controls = el("div", { class: "btn-row", role: "group", "aria-label": "Preview format" });
  const buttons = new Map();

  const draw = (mode) => {
    for (const [name, button] of buttons) button.setAttribute("aria-pressed", String(name === mode));
    if (mode === "plain") {
      status.textContent = "Plain-text alternative as delivered to clients that do not render HTML.";
      stage.replaceChildren(el("pre", {
        class: "template-body tall", tabindex: "0", text: rendered.plain_text || "(empty plain-text body)",
      }));
      return;
    }
    const mobile = mode === "mobile";
    status.textContent = mobile
      ? "Narrow mobile reading frame using the approved plain-text fallback."
      : "Desktop reading frame using the approved plain-text fallback.";
    const message = el("article", {
      tabindex: "0",
      class: `preview-frame ${mobile ? "mobile" : "desktop"}`,
      "aria-label": `${mobile ? "Mobile" : "Desktop"} message preview`,
    }, [
      el("dl", { class: "modal-detail" }, [
        el("dt", { text: "From" }), el("dd", { text: "IT Security <sender@example.com>" }),
        el("dt", { text: "To" }), el("dd", { text: "Sample Employee <sample@example.com>" }),
        el("dt", { text: "Subject" }), el("dd", { text: rendered.subject || "(no subject)" }),
      ]),
      el("pre", {
        class: "template-body medium", text: rendered.plain_text || "(empty plain-text body)",
      }),
    ]);
    stage.replaceChildren(message);
  };

  for (const [mode, label] of [["desktop", "Desktop"], ["mobile", "Mobile"], ["plain", "Plain text"]]) {
    const button = el("button", {
      class: "btn small", type: "button", text: label, "aria-pressed": "false", onclick: () => draw(mode),
    });
    buttons.set(mode, button);
    controls.appendChild(button);
  }
  form.appendChild(controls);
  form.appendChild(status);
  if (rendered.safe_html || rendered.safe_html_present) {
    form.appendChild(el("p", {
      class: "modal-help",
      text: "A sanitized HTML alternative exists but is deliberately not executed in the operator console. Use the plain-text fallback below for safe review.",
    }));
  } else {
    form.appendChild(el("p", {
      class: "modal-help",
      text: "This pending-draft contract exposes only the plain-text body, so desktop and mobile frames do not claim to be an HTML-client rendering.",
    }));
  }
  form.appendChild(stage);
  form.appendChild(el("div", { class: "modal-actions" }, [
    el("button", { class: "btn primary", type: "button", text: "Close preview", onclick: () => dlg.close() }),
  ]));
  draw("desktop");
  openDialog(dlg);
}

async function showLibraryTemplatePreview(template, trigger) {
  trigger.disabled = true;
  try {
    const rendered = await api(`/templates/${template.template_version_id}/preview`);
    showRenderedTemplatePreview(rendered);
  } catch (err) {
    toast(err.message, "error");
  } finally {
    trigger.disabled = false;
  }
}

views.templates = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_TEMPLATE)) return;
  const canCreateCampaign = hasCapability(CAPABILITY.CREATE_CAMPAIGN);
  const canApproveTemplate = hasCapability(CAPABILITY.APPROVE_TEMPLATE);
  const canPreviewTemplate = canCreateCampaign || canApproveTemplate;
  root.appendChild(el("h2", { text: "Template library & review" }));
  root.appendChild(el("p", { class: "sub", text: "Find approved reusable content, clone it into a new draft, and review generated drafts." }));

  const banner = el("div", { class: "policy-banner" });
  banner.appendChild(el("strong", { text: "Nothing here has been sent. " }));
  banner.appendChild(document.createTextNode(
    "Drafts are produced from approved threat patterns by the configured AI gateway, re-checked by the safety validator, and can only be used in a campaign once approved below. Managed deployment validation requires that gateway. You cannot approve a draft whose generation you requested.",
  ));
  root.appendChild(banner);

  if (canCreateCampaign) {
  const library = el("div", { class: "card", "aria-live": "polite" });
  const search = el("input", { type: "search", maxlength: "100", "aria-label": "Search template library", placeholder: "Search subject, body, or model" });
  const stateFilter = el("select", { "aria-label": "Filter templates by review state" }, [
    el("option", { value: "", text: "All review states" }),
    ...["approved", "draft", "pending", "rejected", "superseded"].map((value) => el("option", { value, text: value })),
  ]);
  const libraryResults = el("div");
  const loadLibrary = async () => {
    libraryResults.replaceChildren(el("p", { class: "empty", text: "Loading template library…" }));
    const params = new URLSearchParams({ limit: "100" });
    if (search.value.trim()) params.set("q", search.value.trim());
    if (stateFilter.value) params.set("approval_state", stateFilter.value);
    let templates;
    try { templates = await boundedCollection(`/templates?${params}`); } catch (err) {
      libraryResults.replaceChildren(collectionLoadError(
        `Could not load template library: ${err.message}`,
        () => loadLibrary(),
      ));
      return;
    }
    if (!templates.length) {
      libraryResults.replaceChildren(el("p", { class: "empty", text: "No templates match these filters." }));
      return;
    }
    const rows = templates.map((template) => {
      const state = template.reusable ? "Approved reusable" : `${template.approval_state} — human review required`;
      return el("tr", {}, [
        el("td", { text: template.subject || "(no subject)" }),
        el("td", { text: template.model_id || "unknown" }),
        el("td", {}, [el("span", { class: `pill ${template.reusable ? "ok" : "down"}`, text: state })]),
        el("td", { text: template.campaign_bound ? "Campaign-bound" : "Library item" }),
        el("td", {}, [el("div", { class: "btn-row" }, [
          el("button", {
            class: "btn small", type: "button", text: "Safe preview",
            "aria-label": `Safely preview ${template.subject || "untitled template"}`,
            onclick: (event) => showLibraryTemplatePreview(template, event.currentTarget),
          }),
          el("button", {
            class: "btn small", type: "button", text: "Clone as draft",
            "aria-label": `Clone ${template.subject || "untitled template"} as a new draft`,
            onclick: async (event) => {
              const button = event.currentTarget;
              const values = await promptDialog({
                title: "Clone template as a new draft",
                description: "The copy will have no campaign binding or approval. A different authorized reviewer must approve it before use.",
                fields: [{ name: "reason", label: "Audit reason", type: "textarea", required: true, maxLength: 500,
                  help: "Required for the audit trail. Do not include recipient data or secrets." }],
                submitLabel: "Clone as draft",
              });
              if (!values) return;
              button.disabled = true;
              try {
                const result = await api(`/templates/${template.template_version_id}/clone`, {
                  method: "POST", body: JSON.stringify({ reason: values.reason }),
                });
                toast(result.requires_human_review
                  ? "New DRAFT created. Human approval is required before use."
                  : "Template cloned.", "success");
                await loadLibrary();
              } catch (err) { toast(err.message, "error"); }
              finally { button.disabled = false; }
            },
          }),
        ])]),
      ]);
    });
    libraryResults.replaceChildren(el("table", {}, [
      el("thead", {}, [el("tr", {}, ["Subject", "Model", "Review state", "Binding", "Actions"].map((label) => el("th", { text: label })))]),
      el("tbody", {}, rows),
    ]));
  };
  const searchButton = el("button", { class: "btn", type: "button", text: "Search library", onclick: loadLibrary });
  search.addEventListener("keydown", (event) => { if (event.key === "Enter") loadLibrary(); });
  library.appendChild(el("div", { class: "card-head" }, [el("h3", { text: "Reusable template library" })]));
  library.appendChild(el("p", { class: "field-help", text: "Only items marked Approved reusable can be selected for campaigns. Cloning always creates an unapproved DRAFT and never copies a campaign binding." }));
  library.appendChild(el("div", { class: "btn-row", role: "search" }, [search, stateFilter, searchButton]));
  library.appendChild(libraryResults);
  root.appendChild(library);
  await loadLibrary();
  } else {
    root.appendChild(el("div", { class: "card", role: "status" }, [
      el("h3", { text: "Reusable template library" }),
      el("p", { text: "Browsing, safely previewing, and cloning reusable templates requires campaign-author capability." }),
    ]));
  }

  if (!canApproveTemplate) {
    root.appendChild(el("div", { class: "card", role: "status" }, [
      el("h3", { text: "Generated-template review" }),
      el("p", { text: "The pending review queue requires template-approval capability." }),
    ]));
    return;
  }

  let pending;
  try { pending = await boundedCollection("/templates/pending"); } catch (e) {
    root.appendChild(collectionLoadError(`Failed to load pending templates: ${e.message}`, () => render())); return;
  }
  const principalId = sessionInfo()?.principalId;

  if (!pending.length) {
    root.appendChild(el("div", { class: "card" }, [
      el("h3", { text: "Nothing awaiting review" }),
      el("p", { class: "modal-help", text: "Approving a threat pattern queues a draft for generation; it will appear here once the generation worker has produced it." }),
    ]));
  } else for (const draft of pending) {
    const canReviewDraft = !draft.requested_by
      || (typeof principalId === "string" && principalId.length > 0 && draft.requested_by !== principalId);
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
      ...(canPreviewTemplate ? [el("button", {
        class: "btn small", type: "button", text: "Preview desktop, mobile & plain",
        "aria-label": `Preview ${draft.subject || "untitled template"}`,
        onclick: (event) => showTemplatePreview(draft, event.currentTarget),
      })] : []),
      ...(canReviewDraft ? [
        el("button", { class: "btn small primary", type: "button", text: "Approve", onclick: decide(draft, "approved") }),
        el("button", { class: "btn small danger", type: "button", text: "Reject", onclick: decide(draft, "rejected") }),
      ] : [el("span", {
        class: "modal-help", role: "status",
        text: "You requested this generation. A different authorized reviewer must record its decision.",
      })]),
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

/* ---------- training resource library ---------- */
function trainingResourceWithServerActions(resource) {
  if (!resource || typeof resource !== "object"
    || typeof resource.can_submit !== "boolean"
    || typeof resource.can_review !== "boolean") {
    const error = new Error("Training action authority is unavailable. Refresh before taking any action.");
    error.invalidTrainingActionAuthority = true;
    throw error;
  }
  return resource;
}

async function showTrainingResourcePreview(resource, trigger) {
  trigger.disabled = true;
  try {
    const preview = trainingResourceWithServerActions(
      await api(`/training-resources/${encodeURIComponent(resource.training_resource_id)}/preview`),
    );
    const { dlg, form } = dialogShell(
      `Training preview: ${preview.title || "Untitled lesson"}`,
      "This is the exact text-only lesson. Previewing never approves, retires, assigns, or sends it.",
    );
    form.appendChild(el("dl", { class: "modal-detail" }, [
      el("dt", { text: "Review state" }), el("dd", { text: preview.approval_state || "unknown" }),
      el("dt", { text: "Version" }), el("dd", { text: String(preview.version || 1) }),
      el("dt", { text: "Source reference" }), el("dd", { text: preview.source_ref || "Not provided" }),
      el("dt", { text: "Format" }), el("dd", { text: "Plain text" }),
    ]));
    form.appendChild(el("pre", {
      class: "template-body tall",
      tabindex: "0",
      text: preview.content || "(empty lesson)",
    }));
    form.appendChild(el("p", {
      class: "modal-help",
      text: "Lesson text is rendered as text only. Markup-like characters are never executed by this console.",
    }));
    if (preview.knowledge_check && typeof preview.knowledge_check === "object") {
      const check = preview.knowledge_check;
      form.appendChild(el("h4", { class: "modal-section", text: "Campaign-bound knowledge check" }));
      form.appendChild(el("p", { text: String(check.question || "") }));
      const list = el("ol", {});
      (Array.isArray(check.options) ? check.options : []).forEach((option, index) => {
        const correct = Number.isInteger(check.answer_index) && index === check.answer_index;
        list.appendChild(el("li", {
          class: correct ? "knowledge-option-correct" : "",
          text: `${option}${correct ? " — correct answer" : ""}`,
        }));
      });
      form.appendChild(list);
      form.appendChild(el("p", {
        class: "modal-help",
        text: "The correct answer is shown only to operators. Recipients see the question and options without any marker; the tracking service compares the submitted option server-side.",
      }));
    }
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn primary", type: "button", text: "Close preview", onclick: () => dlg.close() }),
    ]));
    openDialog(dlg);
  } catch (err) {
    toast(`Could not preview training lesson: ${err.message}`, "error");
  } finally {
    trigger.disabled = false;
  }
}

views.training = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_TEMPLATE)) return;
  const canAuthorTraining = hasCapability(CAPABILITY.CREATE_CAMPAIGN);

  root.appendChild(el("h2", { text: "Training lesson library" }));
  root.appendChild(el("p", {
    class: "sub",
    text: "Create concise text-only awareness lessons and govern which approved lesson may be assigned to a campaign.",
  }));
  root.appendChild(el("div", { class: "policy-banner" }, [
    el("strong", { text: "Author and reviewer duties stay separate. " }),
    document.createTextNode(
      "Authors create and submit drafts. Template approvers independently approve or reject pending lessons and may retire approved lessons from future campaign assignments.",
    ),
  ]));

  const stateFilter = el("select", { "aria-label": "Filter training lessons by review state" }, [
    el("option", { value: "", text: "All review states" }),
    ...["draft", "pending", "approved", "rejected", "superseded"]
      .map((value) => el("option", { value, text: value })),
  ]);
  const results = el("div", { "aria-live": "polite" });

  const loadResources = async () => {
    results.replaceChildren(el("p", { class: "empty", text: "Loading training lessons…" }));
    const params = new URLSearchParams({ limit: "100" });
    if (stateFilter.value) params.set("approval_state", stateFilter.value);
    let resources;
    try {
      const payload = await boundedCollection(`/training-resources?${params.toString()}`);
      if (!Array.isArray(payload)) throw new Error("Training lesson list is invalid.");
      resources = payload.map(trainingResourceWithServerActions);
    } catch (err) {
      results.replaceChildren(collectionLoadError(
        `Could not load training lessons: ${err.message}`,
        () => loadResources(),
      ));
      return;
    }
    if (!resources.length) {
      results.replaceChildren(el("p", { class: "empty", text: "No training lessons match this review state." }));
      return;
    }

    const submitResource = async (resource, button) => {
      const confirmed = await confirmDialog({
        title: "Submit lesson for independent review",
        message: "Submission locks this draft into the review workflow. The API permits only its original author to submit it.",
        detail: { Lesson: resource.title, Version: resource.version },
        confirmLabel: "Submit for review",
      });
      if (!confirmed) return;
      button.disabled = true;
      try {
        trainingResourceWithServerActions(
          await api(`/training-resources/${encodeURIComponent(resource.training_resource_id)}/submit`, {
            method: "POST",
          }),
        );
        toast("Training lesson submitted for independent review.", "success");
        await loadResources();
      } catch (err) {
        if (err.invalidTrainingActionAuthority) {
          toast(err.message, "error");
          await loadResources();
        } else {
          toast(`Could not submit training lesson: ${err.message}`, "error");
        }
      } finally {
        if (button.isConnected) button.disabled = false;
      }
    };

    const decideResource = async (resource, decision, button) => {
      const label = decision === "approved" ? "Approve" : decision === "rejected" ? "Reject" : "Supersede";
      const values = await promptDialog({
        title: `${label} training lesson`,
        description: decision === "superseded"
          ? "Retirement prevents new campaigns from selecting this lesson. Campaigns already bound to it keep their immutable assignment."
          : "Record the independent review decision and rationale.",
        fields: [{
          name: "rationale", label: "Review rationale", type: "textarea", required: true, maxLength: 1000,
          help: "Required by the API and recorded in the audit trail. Do not include recipient data or secrets.",
        }],
        submitLabel: `Review ${label.toLowerCase()}`,
      });
      if (!values) return;
      const confirmed = await confirmDialog({
        title: `Confirm ${label.toLowerCase()} decision`,
        message: "This decision is recorded against your authenticated identity. A resource author cannot review their own lesson.",
        detail: { Lesson: resource.title, Decision: decision, Rationale: values.rationale },
        confirmLabel: `${label} lesson`,
        danger: decision !== "approved",
      });
      if (!confirmed) return;
      button.disabled = true;
      try {
        trainingResourceWithServerActions(
          await api(`/training-resources/${encodeURIComponent(resource.training_resource_id)}/decision`, {
            method: "POST",
            body: JSON.stringify({ decision, rationale: values.rationale }),
          }),
        );
        toast(`Training lesson ${decision}.`, "success");
        await loadResources();
      } catch (err) {
        if (err.invalidTrainingActionAuthority) {
          toast(err.message, "error");
          await loadResources();
        } else {
          toast(`Could not record training review: ${err.message}`, "error");
        }
      } finally {
        if (button.isConnected) button.disabled = false;
      }
    };

    const rows = resources.map((resource) => {
      const actions = [el("button", {
        class: "btn small", type: "button", text: "Safe text preview",
        onclick: (event) => showTrainingResourcePreview(resource, event.currentTarget),
      })];
      if (resource.can_submit === true && resource.approval_state === "draft") {
        actions.push(el("button", {
          class: "btn small", type: "button", text: "Submit for review",
          onclick: (event) => submitResource(resource, event.currentTarget),
        }));
      }
      if (resource.can_review === true && resource.approval_state === "pending") {
        actions.push(el("button", {
          class: "btn small primary", type: "button", text: "Approve",
          onclick: (event) => decideResource(resource, "approved", event.currentTarget),
        }));
        actions.push(el("button", {
          class: "btn small danger", type: "button", text: "Reject",
          onclick: (event) => decideResource(resource, "rejected", event.currentTarget),
        }));
      }
      if (resource.can_review === true && resource.approval_state === "approved") {
        actions.push(el("button", {
          class: "btn small danger", type: "button", text: "Supersede for future campaigns",
          onclick: (event) => decideResource(resource, "superseded", event.currentTarget),
        }));
      }
      return el("tr", {}, [
        el("td", { text: resource.title || "Untitled lesson" }),
        el("td", { text: String(resource.version || 1) }),
        el("td", { text: resource.source_ref || "Not provided" }),
        el("td", {}, [el("span", { class: `pill ${resource.approval_state === "approved" ? "ok" : "down"}`, text: resource.approval_state || "unknown" })]),
        el("td", { text: resource.requires_completion ? "Required" : "Optional" }),
        el("td", {}, [el("div", { class: "btn-row" }, actions)]),
      ]);
    });
    results.replaceChildren(el("table", {}, [
      el("thead", {}, [el("tr", {}, ["Lesson", "Version", "Source reference", "Review state", "Completion", "Actions"]
        .map((label) => el("th", { text: label })))]),
      el("tbody", {}, rows),
    ]));
  };

  const controls = [stateFilter, el("button", {
    class: "btn", type: "button", text: "Refresh lessons", onclick: loadResources,
  })];
  if (canAuthorTraining) controls.unshift(el("button", {
    class: "btn primary", type: "button", text: "Create training lesson", onclick: async (event) => {
      const values = await promptDialog({
        title: "Create text-only training lesson",
        description: "Create a concise draft. It cannot be assigned until an independent reviewer approves it.",
        fields: [
          { name: "title", label: "Lesson title", required: true, maxLength: 160 },
          { name: "content", label: "Lesson text", type: "textarea", required: true, maxLength: 20000,
            help: "Plain text only. Markup-like text is displayed literally and never executed." },
          { name: "source_ref", label: "Non-secret source reference (optional)", maxLength: 500,
            help: "Use a short policy or evidence reference; never enter credentials or recipient data." },
          { name: "knowledge_question", label: "Knowledge-check question (optional)", maxLength: 500,
            help: "Leave empty to keep the generic quiz. Provide it with 2–5 options and mark the correct one." },
          { name: "knowledge_options", label: "Knowledge-check options (comma-separated, 2–5)", maxLength: 1000,
            help: "Each option is bounded to 200 characters and must be distinct." },
          { name: "knowledge_answer_index", label: "Correct option number (1-based, matching the list order)",
            help: "Recipients never see which option is correct; the tracking service compares it server-side." },
        ],
        submitLabel: "Create draft",
      });
      if (!values) return;
      const button = event.currentTarget;
      button.disabled = true;
      try {
        const knowledgeQuestion = values.knowledge_question ? values.knowledge_question.trim() : null;
        const knowledgeOptions = values.knowledge_options
          ? values.knowledge_options.split(",").map((option) => option.trim()).filter(Boolean)
          : null;
        const knowledgeAnswerIndex = knowledgeQuestion && knowledgeOptions && values.knowledge_answer_index
          ? Number(values.knowledge_answer_index) - 1
          : null;
        trainingResourceWithServerActions(
          await api("/training-resources", {
            method: "POST",
            body: JSON.stringify({
              title: values.title,
              content: values.content,
              source_ref: values.source_ref || null,
              knowledge_question: knowledgeQuestion,
              knowledge_options: knowledgeOptions,
              knowledge_answer_index: knowledgeAnswerIndex,
            }),
          }),
        );
        toast("Training lesson draft created.", "success");
        await loadResources();
      } catch (err) {
        if (err.invalidTrainingActionAuthority) {
          toast(err.message, "error");
          await loadResources();
        } else {
          toast(`Could not create training lesson: ${err.message}`, "error");
        }
      } finally {
        button.disabled = false;
      }
    },
  }));

  const card = el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [el("h3", { text: "Awareness lessons" })]),
    el("p", { class: "field-help", text: "At most 100 bounded metadata records are loaded. Lesson content is fetched only for explicit safe preview." }),
    el("div", { class: "btn-row" }, controls),
    results,
  ]);
  root.appendChild(card);
  stateFilter.addEventListener("change", loadResources);
  await loadResources();
};

/* ---------- recipients ---------- */
async function changeTestAccountDesignation(recipient) {
  const adding = !recipient.is_test_account;
  const reference = String(recipient.recipient_id || "").slice(0, 8);
  const typedConfirmation = `DESIGNATE ${reference}`;
  const fields = [{
    name: "reason",
    label: "Audit reason",
    type: "textarea",
    required: true,
    maxLength: 500,
    placeholder: adding ? "Approved internal canary mailbox" : "No longer used for canary delivery",
    help: "Required and recorded in the audit trail. Do not include a mailbox address or other personal data.",
  }];
  if (adding) {
    fields.push({
      name: "confirmation",
      label: `Type ${typedConfirmation} to continue`,
      required: true,
      maxLength: 64,
      help: "Adding this designation makes the selected server record eligible for campaign test sends.",
    });
  }
  const values = await promptDialog({
    title: adding ? "Designate test account" : "Remove test-account designation",
    description: adding
      ? "This grants canary/test-send eligibility. It never changes the frozen audience, but a future test send may include this exact server-designated recipient."
      : "This removes canary/test-send eligibility from this exact server-designated recipient.",
    fields,
    submitLabel: adding ? "Review designation" : "Review removal",
  });
  if (!values) return;
  if (adding && values.confirmation !== typedConfirmation) {
    toast(`Confirmation did not match. Type ${typedConfirmation} exactly.`, "error");
    return;
  }
  if (!values.reason || values.reason.length > 500) {
    toast("Enter an audit reason between 1 and 500 characters.", "error");
    return;
  }
  const confirmed = await confirmDialog({
    title: adding ? "Confirm test-send eligibility" : "Confirm eligibility removal",
    message: adding
      ? "Confirm that this recipient record is an authorized internal canary account. Never designate a normal employee mailbox."
      : "Confirm removal. Test sends will no longer select this recipient record.",
    detail: {
      "Recipient reference": reference,
      "New designation": adding ? "Test account" : "Standard recipient",
    },
    confirmLabel: adding ? "Designate test account" : "Remove designation",
    danger: adding,
  });
  if (!confirmed) return;
  try {
    const result = await api(`/recipients/${encodeURIComponent(recipient.recipient_id)}/test-account`, {
      method: "PUT",
      body: JSON.stringify({
        is_test_account: adding,
        confirm: true,
        reason: values.reason,
      }),
    });
    toast(
      result.changed
        ? (result.is_test_account ? "Test-account designation added." : "Test-account designation removed.")
        : `Designation was already ${result.is_test_account ? "test account" : "standard recipient"}; no change was made.`,
      "success",
    );
    await render();
  } catch (err) {
    if (err.status === 409) {
      toast(
        "Designation is locked because this recipient belongs to a frozen audience or assignment for a nonterminal campaign. Complete or stop that campaign before changing canary eligibility.",
        "error",
      );
      return;
    }
    toast(err.message, "error");
  }
}

const EXCLUSION_TYPE_LABELS = Object.freeze({
  global: "Global exclusion",
  accommodation: "Accommodation",
  executive: "Executive",
  legal_hold: "Legal hold",
  campaign_specific: "Selected campaign only",
  test_account: "Test-account policy",
});

async function manageRecipientExclusions(recipient, campaigns, campaignsLoaded) {
  if (!hasCapability(CAPABILITY.MANAGE_EXCLUSIONS)) return;
  const reference = String(recipient.recipient_id || "").slice(0, 8);
  const { dlg, form } = dialogShell(
    `Exclusions for recipient ${reference}`,
    "This view uses the opaque recipient reference only. Active exclusions prevent future audience preparation in their configured scope.",
  );
  const content = el("div", { role: "status" }, [
    el("p", { class: "empty", text: "Loading active and recent exclusion history…" }),
  ]);
  form.appendChild(content);
  form.appendChild(el("div", { class: "modal-actions" }, [
    el("button", { class: "btn", type: "button", text: "Close", onclick: () => dlg.close() }),
  ]));
  openDialog(dlg);

  let history;
  try {
    history = await api(
      `/recipients/${encodeURIComponent(recipient.recipient_id)}/exclusions?include_inactive=true&limit=50`,
    );
    if (!Array.isArray(history)) throw new Error("The server returned an invalid history response");
    history = history.slice(0, 50);
  } catch (err) {
    content.replaceChildren(el("div", {
      class: "modal-error", role: "alert",
      text: `Exclusion history is unavailable. No exclusion controls are enabled. ${err.message}`,
    }));
    return;
  }

  async function revokeExclusion(exclusion) {
    const values = await promptDialog({
      title: "Document exclusion revocation",
      description: "Revocation keeps the exclusion and its audit history. It only restores eligibility for future campaign preparation.",
      fields: [{
        name: "rationale", label: "Revocation rationale", type: "textarea", required: true,
        maxLength: 500, placeholder: "Why this exclusion is no longer required",
        help: "Required and stored encrypted. Do not include a mailbox address, employee key, or credentials.",
      }],
      submitLabel: "Review revocation",
    });
    if (!values) return;
    const rationale = values.rationale.trim();
    if (!rationale || rationale.length > 500) {
      toast("Enter a revocation rationale between 1 and 500 characters.", "error");
      return;
    }
    const confirmed = await confirmDialog({
      title: "Revoke this active exclusion?",
      message: "The historical record remains. Future campaigns may include this recipient unless another active exclusion applies.",
      detail: {
        "Recipient reference": reference,
        "Exclusion type": EXCLUSION_TYPE_LABELS[exclusion.exclusion_type] || exclusion.exclusion_type,
        Scope: exclusion.campaign_id ? `Campaign ${String(exclusion.campaign_id).slice(0, 8)}` : "Global",
      },
      confirmLabel: "Revoke exclusion",
      danger: true,
    });
    if (!confirmed) return;
    try {
      const result = await api(
        `/recipients/${encodeURIComponent(recipient.recipient_id)}/exclusions/${encodeURIComponent(exclusion.recipient_exclusion_id)}/revoke`,
        { method: "POST", body: JSON.stringify({ confirm: true, rationale }) },
      );
      dlg.close();
      toast(
        result.changed
          ? "Exclusion revoked; the historical record was retained."
          : "Exclusion was already revoked; no change was made.",
        "success",
      );
      await render();
    } catch (err) { toast(err.message, "error"); }
  }

  const rows = history.map((exclusion) => el("tr", {}, [
    el("td", { text: EXCLUSION_TYPE_LABELS[exclusion.exclusion_type] || exclusion.exclusion_type }),
    el("td", { text: exclusion.campaign_id ? `Campaign ${String(exclusion.campaign_id).slice(0, 8)}` : "Global" }),
    el("td", { text: exclusion.active ? "Active" : (exclusion.revoked_at ? "Revoked" : "Expired") }),
    el("td", { text: exclusion.expires_at ? formatInstant(exclusion.expires_at) : "No expiry" }),
    el("td", { text: exclusion.reason || "Reason recorded" }),
    el("td", {}, exclusion.active ? [el("button", {
      class: "btn small danger", type: "button", text: "Revoke",
      "aria-label": `Revoke ${exclusion.exclusion_type} exclusion for recipient ${reference}`,
      onclick: async (event) => {
        event.currentTarget.disabled = true;
        try { await revokeExclusion(exclusion); }
        finally { if (event.currentTarget.isConnected) event.currentTarget.disabled = false; }
      },
    })] : []),
  ]));
  const historyTable = el("table", { class: "report-table", "aria-label": "Bounded recipient exclusion history" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Type" }), el("th", { text: "Scope" }), el("th", { text: "State" }),
      el("th", { text: "Expiry" }), el("th", { text: "Reason" }), el("th", { text: "Action" }),
    ])]),
    el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", {
      class: "empty", colspan: 6, text: "No active or recent exclusions are recorded for this recipient.",
    })])]),
  ]);

  const eligibleCampaigns = campaigns.slice(0, 100);
  const createButton = el("button", {
    class: "btn primary", type: "button", text: "Add exclusion",
    disabled: recipient.status === "active" ? null : "disabled",
    title: recipient.status === "active" ? null : "New exclusions require an active recipient record.",
  });
  createButton.addEventListener("click", async () => {
    const typeOptions = Object.entries(EXCLUSION_TYPE_LABELS)
      .filter(([value]) => value !== "campaign_specific" || campaignsLoaded)
      .map(([value, label]) => ({ value, label }));
    const campaignOptions = [
      { value: "", label: "No campaign (global scope)" },
      ...eligibleCampaigns.map((campaign) => ({
        value: campaign.campaign_id,
        label: `${campaign.title} · ${String(campaign.campaign_id).slice(0, 8)}`,
      })),
    ];
    const values = await promptDialog({
      title: `Add exclusion for recipient ${reference}`,
      description: "Choose an explicit exclusion type. Only Selected campaign requires a campaign; every other type is global.",
      fields: [
        { name: "exclusion_type", label: "Exclusion type", type: "select", value: "global", options: typeOptions },
        { name: "campaign_id", label: "Campaign scope", type: "select", value: "", options: campaignOptions,
          help: campaignsLoaded
            ? "Select a campaign only when the exclusion type is Selected campaign only."
            : "Campaign metadata is unavailable; selected-campaign exclusions are disabled." },
        { name: "reason", label: "Required rationale", type: "textarea", required: true, maxLength: 500,
          placeholder: "Document the policy or accommodation basis",
          help: "Stored encrypted. Do not include a mailbox address, employee key, or credentials." },
        { name: "expires_at", label: "Optional expiry (browser local time)", type: "datetime-local",
          help: "Leave blank for no expiry. An entered expiry must be in the future and is sent with an explicit timezone." },
      ],
      submitLabel: "Create exclusion",
    });
    if (!values) return;
    const campaignSpecific = values.exclusion_type === "campaign_specific";
    if (campaignSpecific !== Boolean(values.campaign_id)) {
      toast("Selected campaign exclusions require one campaign; all other exclusion types must use global scope.", "error");
      return;
    }
    const reason = values.reason.trim();
    if (!reason || reason.length > 500) {
      toast("Enter an exclusion rationale between 1 and 500 characters.", "error");
      return;
    }
    let expiresAt = null;
    if (values.expires_at) {
      try { expiresAt = localDateTimeToIso(values.expires_at, "Expiry"); }
      catch (err) { toast(err.message, "error"); return; }
      if (Date.parse(expiresAt) <= Date.now()) {
        toast("Expiry must be in the future.", "error");
        return;
      }
    }
    createButton.disabled = true;
    try {
      const result = await api(`/recipients/${encodeURIComponent(recipient.recipient_id)}/exclusions`, {
        method: "POST",
        body: JSON.stringify({
          exclusion_type: values.exclusion_type,
          campaign_id: values.campaign_id || null,
          reason,
          expires_at: expiresAt,
        }),
      });
      dlg.close();
      toast(
        result.created
          ? "Recipient exclusion created."
          : "An identical active exclusion already exists; no change was made.",
        "success",
      );
      await render();
    } catch (err) {
      toast(err.message, "error");
      if (createButton.isConnected) createButton.disabled = recipient.status !== "active";
    }
  });

  content.replaceChildren(...[
    el("p", { class: "modal-help", text: `Showing at most 50 active and recent records. ${history.length} loaded.` }),
    historyTable,
    campaignsLoaded ? null : el("p", {
      class: "modal-warn", role: "alert",
      text: "Campaign metadata is unavailable. Global exclusion controls remain available; selected-campaign creation is disabled.",
    }),
    recipient.status === "active" ? null : el("p", {
      class: "modal-warn", role: "status", text: "This recipient is not active. History and revoke remain available, but a new exclusion cannot be created.",
    }),
    el("div", { class: "btn-row" }, [createButton]),
  ].filter(Boolean));
}

const RECIPIENT_PAGE_LIMIT = 100;
let recipientPageOffset = 0;

views.recipients = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VIEW_NAMED_RESULTS, CAPABILITY.MANAGE_RECIPIENTS)) return;
  const canManageRecipients = hasCapability(CAPABILITY.MANAGE_RECIPIENTS);
  const canManageExclusions = hasCapability(CAPABILITY.MANAGE_EXCLUSIONS);
  root.appendChild(el("h2", { text: "Recipients" }));
  root.appendChild(el("p", { class: "sub", text: "Import recipients, manage explicit canary and exclusion controls, or review and apply a bounded Microsoft 365 directory preview." }));
  let recipientPage;
  try {
    recipientPage = boundedRecipientPage(
      await api(`/recipients?limit=${RECIPIENT_PAGE_LIMIT}&offset=${recipientPageOffset}`),
      RECIPIENT_PAGE_LIMIT,
    );
  } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  const recipients = recipientPage.items;
  const [integrationResult, campaignResult] = await Promise.allSettled([
    canManageRecipients ? api("/integrations/microsoft365/status") : Promise.resolve(null),
    canManageExclusions ? boundedCollection("/campaigns") : Promise.resolve([]),
  ]);
  const integration = integrationResult.status === "fulfilled" ? integrationResult.value : null;
  const integrationLoaded = !canManageRecipients || Boolean(
    integration && typeof integration === "object"
      && integration.directory && typeof integration.directory === "object"
      && integration.reported_mailbox && typeof integration.reported_mailbox === "object",
  );
  const campaignsLoaded = campaignResult.status === "fulfilled" && Array.isArray(campaignResult.value);
  const campaigns = campaignsLoaded ? campaignResult.value : [];
  const dependencyFailures = [];
  if (canManageRecipients && integrationResult.status === "rejected") {
    dependencyFailures.push(`Microsoft 365 integration: ${integrationResult.reason.message}`);
  } else if (canManageRecipients && !integrationLoaded) {
    dependencyFailures.push("Microsoft 365 integration: the server returned an invalid status response");
  }
  if (canManageExclusions && campaignResult.status === "rejected") {
    dependencyFailures.push(`campaign scopes: ${campaignResult.reason.message}`);
  }
  if (dependencyFailures.length) {
    root.appendChild(el("div", {
      class: "modal-warn", role: "alert",
      text: `Some recipient controls are unavailable and remain disabled. ${dependencyFailures.join(" ")}`,
    }));
  }
  const directory = integrationLoaded ? (integration?.directory || {}) : {};
  const mailbox = integrationLoaded ? (integration?.reported_mailbox || {}) : {};
  const healthLine = (state) => {
    if (!state || typeof state !== "object" || typeof state.status !== "string") {
      return "Unavailable · status could not be verified";
    }
    const counts = Object.entries(state.counts || {}).map(([name, value]) => `${name}: ${value}`).join(" · ");
    const age = state.cursor_age_seconds == null ? "no successful run" : `last success ${Math.floor(state.cursor_age_seconds / 60)}m ago`;
    const lastError = state.last_error ? String(state.last_error).slice(0, 240) : "";
    return `${state.provider || "not observed"} · ${state.status} · ${age}${counts ? ` · ${counts}` : ""}${lastError ? ` · ${lastError}` : ""}`;
  };
  const previewReference = typeof directory.preview_id === "string" && directory.preview_id.length <= 128
    ? directory.preview_id : null;
  const directoryUnavailable = !integrationLoaded
    ? "Microsoft 365 integration status is unavailable."
    : integration?.directory_preview_unavailable_reason || directory.action_unavailable_reason
      || (integration.directory_preview_available === true ? null : "Directory preview is not currently available.");
  const mailboxUnavailable = !integrationLoaded
    ? "Microsoft 365 integration status is unavailable."
    : integration?.mailbox_poll_unavailable_reason || mailbox.action_unavailable_reason
      || (integration.mailbox_poll_available === true ? null : "Reported-mail polling is not currently available.");
  const previewDisabled = !integrationLoaded || integration?.directory_preview_available !== true;
  const applyDisabled = !integrationLoaded || directory.apply_available !== true || !previewReference;
  const discardDisabled = !integrationLoaded || directory.discard_available !== true || !previewReference;
  const mailboxDisabled = !integrationLoaded || integration?.mailbox_poll_available !== true;
  const integrationControls = canManageRecipients ? [
    el("button", { class: "btn primary", type: "button", text: "Preview directory changes", disabled: previewDisabled, title: previewDisabled ? directoryUnavailable : null, onclick: async (event) => {
      event.target.disabled = true;
      try {
        await api("/recipients/directory/preview", { method: "POST" });
        toast("Directory preview queued. Refresh after the worker finishes; no recipients change until Apply.", "success");
        await render();
      } catch (e) { toast(e.message, "error"); }
      finally { if (event.target.isConnected) event.target.disabled = previewDisabled; }
    } }),
    el("button", { class: "btn danger", type: "button", text: "Apply reviewed directory preview", disabled: applyDisabled, title: applyDisabled ? (directoryUnavailable || "Create and review a current directory preview first.") : null, onclick: async (event) => {
      const confirmed = await confirmDialog({
        title: `Apply directory preview ${previewReference}?`,
        message: "Only the reviewed preview is applied. Disabled, removed, guest, service, and out-of-domain users remain excluded.",
        detail: { "Preview reference": previewReference },
        confirmLabel: "Apply reviewed preview",
        danger: true,
      });
      if (!confirmed) return;
      event.target.disabled = true;
      try {
        await api("/recipients/directory/apply", { method: "POST", body: JSON.stringify({ preview_id: previewReference }) });
        toast("Directory apply queued. Frozen campaign audiences affected by group changes will be invalidated.", "success");
        await render();
      } catch (e) { toast(e.message, "error"); }
      finally { if (event.target.isConnected) event.target.disabled = applyDisabled; }
    } }),
    el("button", { class: "btn", type: "button", text: "Discard directory preview", disabled: discardDisabled, title: discardDisabled ? (directoryUnavailable || "There is no directory preview to discard.") : null, onclick: async (event) => {
      event.target.disabled = true;
      try {
        await api("/recipients/directory/discard", { method: "POST", body: JSON.stringify({ preview_id: previewReference }) });
        toast("Directory preview discard queued. No recipient records will be changed.", "success");
        await render();
      } catch (e) { toast(e.message, "error"); }
      finally { if (event.target.isConnected) event.target.disabled = discardDisabled; }
    } }),
  ] : [];
  if (canManageRecipients) integrationControls.push(el("button", { class: "btn", type: "button", text: "Poll reported mailbox now", disabled: mailboxDisabled, title: mailboxDisabled ? mailboxUnavailable : null, onclick: async (event) => {
    event.target.disabled = true;
    try {
      await api("/integrations/reported-mail/poll", { method: "POST" });
      toast("A bounded mailbox poll was queued.", "success");
      await render();
    } catch (e) { toast(e.message, "error"); }
    finally { if (event.target.isConnected) event.target.disabled = mailboxDisabled; }
  } }));
  if (canManageRecipients) root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Microsoft 365 integration" }),
    el("p", { text: `Directory: ${healthLine(directory)}` }),
    el("p", { text: `Reported-mail canary mailbox: ${healthLine(mailbox)}` }),
    directoryUnavailable ? el("p", { class: "modal-help", text: `Directory actions unavailable: ${directoryUnavailable}` }) : null,
    mailboxUnavailable ? el("p", { class: "modal-help", text: `Reported-mail action unavailable: ${mailboxUnavailable}` }) : null,
    !directoryUnavailable && !previewReference ? el("p", { class: "modal-help", text: "Apply and Discard become available after the directory worker produces a complete preview." }) : null,
    el("p", { class: "modal-help", text: "Preview is non-mutating. Apply uses the exact encrypted preview and advances its cursor atomically. Incomplete or failed directory results never deactivate recipients." }),
    el("div", { class: "btn-row" }, integrationControls),
  ].filter(Boolean)));
  if (canManageRecipients) {
    const csvArea = el("textarea", {
      id: "r-csv", rows: "10", maxlength: String(MAX_RECIPIENT_CSV_BYTES),
      placeholder: "Email,Name,Department\nuser@example.com,Jane Doe,Engineering",
    });
    const filePicker = el("input", { id: "r-file", type: "file", accept: ".csv,text/csv,text/plain" });
    const defaultDepartment = el("input", { id: "r-dept", maxlength: "255", value: "" });
    const headerMode = el("select", { id: "r-header-mode" }, [
      el("option", { value: "auto", text: "Auto-detect conventional headers" }),
      el("option", { value: "first_row", text: "Use the first populated row as headers" }),
      el("option", { value: "none", text: "Treat every populated row as recipient data" }),
    ]);
    const mergeExisting = el("select", { id: "r-merge" }, [
      el("option", { value: "skip", text: "Skip existing recipients" }),
      el("option", { value: "update", text: "Update existing non-directory recipients" }),
    ]);
    const deactivateMissing = el("input", { id: "r-deactivate", type: "checkbox" });
    const mappingControls = {
      mailbox: el("select", { id: "r-map-mailbox" }),
      display_name: el("select", { id: "r-map-name" }),
      department: el("select", { id: "r-map-department" }),
    };
    const previewStatus = el("div", {
      class: "modal-help", role: "status", text: "Preview is required before Apply.",
    });
    let currentPreview = null;
    let explicitHeaderColumnsReviewed = false;

    function populateMappingSelect(select, columns, { optional = false, resolved = undefined } = {}) {
      const previous = select.value;
      select.replaceChildren(el("option", { value: "auto", text: "Auto-detect" }));
      if (optional) select.appendChild(el("option", { value: "none", text: "Do not import" }));
      for (const column of columns || []) {
        select.appendChild(el("option", { value: String(column.index), text: column.label }));
      }
      const next = resolved === null ? "none" : resolved === undefined ? previous : String(resolved);
      select.value = Array.from(select.options).some((option) => option.value === next) ? next : "auto";
    }

    populateMappingSelect(mappingControls.mailbox, []);
    populateMappingSelect(mappingControls.display_name, [], { optional: true });
    populateMappingSelect(mappingControls.department, [], { optional: true });

    function importRequestBody() {
      const csvText = validateRecipientCsvText(csvArea.value);
      const mapping = {};
      for (const [field, select] of Object.entries(mappingControls)) {
        if (select.value === "none") mapping[field] = null;
        else if (select.value !== "auto") mapping[field] = Number(select.value);
      }
      return {
        csv_text: csvText,
        department: defaultDepartment.value.trim(),
        header_mode: headerMode.value,
        mapping,
        merge_existing: mergeExisting.value,
        deactivate_missing: deactivateMissing.checked,
      };
    }

    function invalidateImportPreview() {
      currentPreview = null;
      applyButton.disabled = true;
      previewStatus.replaceChildren(document.createTextNode("Inputs changed. Preview again before Apply."));
    }

    function showRecipientImportPreview(preview) {
      const counts = preview.counts || {};
      const table = el("table", { class: "report-table", "aria-label": "Recipient CSV preview counts" }, [
        el("tbody", {}, [
          ["Will create", "created"], ["Can update", "updateable"], ["Already exists", "existing"],
          ["Blocked by domain policy", "blocked"], ["Invalid", "invalid"], ["Duplicate", "duplicate"],
          ["CSV-managed recipients to deactivate", "deactivateable"],
        ].map(([label, key]) => el("tr", {}, [
          el("td", { text: label }), el("td", { class: "num", text: String(counts[key] || 0) }),
        ]))),
      ]);
      const content = [
        el("p", {
          text: `${preview.header_mode === "first_row" ? "First populated row explicitly used as headers" : preview.header_detected ? "Conventional header detected" : "No header row used"}. ${preview.input_rows} data row${preview.input_rows === 1 ? "" : "s"}. Preview ${preview.preview_digest.slice(0, 12)}….`,
        }),
        table,
      ];
      if (preview.deactivation_requires_clean_preview) {
        content.push(el("p", { class: "modal-warn", role: "alert", text: "Deactivate missing is blocked until every invalid, blocked, and duplicate row is fixed." }));
      }
      if ((preview.errors || []).length) {
        const list = el("ul", { class: "modal-errors", "aria-label": "Bounded non-PII CSV row errors" });
        for (const issue of preview.errors) list.appendChild(el("li", { text: `Row ${issue.row}: ${issue.code}` }));
        content.push(list);
        if (preview.errors_truncated) content.push(el("p", { class: "modal-help", text: "Only the first 20 row errors are shown." }));
      }
      previewStatus.replaceChildren(...content);
    }

    const applyButton = el("button", {
      class: "btn primary", type: "button", text: "Apply exact preview", disabled: "disabled",
      onclick: async (event) => {
        if (!currentPreview) return;
        let body;
        try { body = importRequestBody(); }
        catch (err) { toast(err.message, "error"); return; }
        const deactivating = body.deactivate_missing;
        const confirmed = await confirmDialog({
          title: deactivating
            ? "Deactivate CSV recipients missing from this file?"
            : "Apply this exact recipient CSV preview?",
          message: deactivating
            ? "This second confirmation changes only CSV-managed, non-directory recipients to Departed. It never deletes recipients or changes frozen campaign audiences."
            : "The server will recompute the exact digest and current recipient state before applying this preview.",
          detail: {
            "Preview digest": currentPreview.preview_digest,
            "Create": currentPreview.counts.created || 0,
            "Update": currentPreview.counts.updateable || 0,
            "Deactivate": currentPreview.counts.deactivateable || 0,
          },
          confirmLabel: deactivating ? "Deactivate missing and apply" : "Apply exact preview",
          danger: deactivating,
        });
        if (!confirmed) return;
        event.currentTarget.disabled = true;
        try {
          const result = await api("/recipients/import/apply", {
            method: "POST",
            body: JSON.stringify({
              ...body,
              preview_digest: currentPreview.preview_digest,
              deactivate_missing_confirm: deactivating,
            }),
          });
          currentPreview = null;
          showImportResult(result);
        } catch (err) {
          toast(err.message, "error");
          invalidateImportPreview();
        } finally {
          if (event.currentTarget.isConnected) event.currentTarget.disabled = currentPreview === null;
        }
      },
    });

    const previewButton = el("button", {
      class: "btn primary", type: "button", text: "Preview CSV changes", onclick: async (event) => {
        event.currentTarget.disabled = true;
        try {
          const requiresHeaderMappingReview = headerMode.value === "first_row" && !explicitHeaderColumnsReviewed;
          const preview = await api("/recipients/import/preview", {
            method: "POST", body: JSON.stringify(importRequestBody()),
          });
          if (!preview || typeof preview.preview_digest !== "string" || !preview.counts) {
            throw new Error("The server returned an invalid recipient import preview");
          }
          populateMappingSelect(mappingControls.mailbox, preview.columns, { resolved: preview.mapping.mailbox });
          populateMappingSelect(mappingControls.display_name, preview.columns, { optional: true, resolved: preview.mapping.display_name });
          populateMappingSelect(mappingControls.department, preview.columns, { optional: true, resolved: preview.mapping.department });
          showRecipientImportPreview(preview);
          if (requiresHeaderMappingReview) {
            explicitHeaderColumnsReviewed = true;
            currentPreview = null;
            applyButton.disabled = true;
            previewStatus.appendChild(el("p", {
              class: "modal-warn", role: "status",
              text: "Header names are loaded as bounded text. Review every column mapping, choose Do not import for unused optional columns, then Preview again to bind the exact mapping before Apply.",
            }));
          } else {
            currentPreview = preview;
            applyButton.disabled = preview.can_apply !== true;
          }
        } catch (err) {
          invalidateImportPreview();
          toast(err.message, "error");
        } finally {
          if (event.currentTarget.isConnected) event.currentTarget.disabled = false;
        }
      },
    });

    filePicker.addEventListener("change", async () => {
      const file = filePicker.files && filePicker.files[0];
      if (!file) return;
      if (file.size > MAX_RECIPIENT_CSV_BYTES) {
        toast("Recipient CSV exceeds the 512 KiB browser limit", "error");
        filePicker.value = "";
        return;
      }
      try {
        const text = await file.text();
        validateRecipientCsvText(text);
        csvArea.value = text;
        explicitHeaderColumnsReviewed = false;
        invalidateImportPreview();
        toast(`Loaded ${file.name}`, "success");
      } catch (err) { toast(`Could not read ${file.name}: ${err.message}`, "error"); }
    });
    csvArea.addEventListener("input", () => { explicitHeaderColumnsReviewed = false; invalidateImportPreview(); });
    headerMode.addEventListener("change", () => { explicitHeaderColumnsReviewed = false; invalidateImportPreview(); });
    for (const control of [defaultDepartment, mergeExisting, deactivateMissing, ...Object.values(mappingControls)]) {
      control.addEventListener("input", invalidateImportPreview);
      control.addEventListener("change", invalidateImportPreview);
    }

    root.appendChild(el("div", { class: "card" }, [
      el("h3", { text: "Import CSV" }),
      el("p", { text: "Preview is non-mutating and shows only counts plus bounded row-number error codes. Apply is bound to the exact CSV, mapping, options, domain policy, and current recipient state." }),
      el("label", { for: "r-file", text: "Choose a CSV file" }),
      filePicker,
      el("p", { class: "modal-help", text: "The browser refuses files over 512 KiB or 5,000 lines. File contents stay in this page until Preview." }),
      el("label", { for: "r-csv", text: "CSV text" }),
      csvArea,
      el("label", { for: "r-header-mode", text: "Header row handling" }), headerMode,
      el("p", { class: "modal-help", text: "For nonstandard header names, choose first-row headers and Preview once to load safe, bounded labels. Review the mappings, then Preview again before Apply." }),
      el("label", { for: "r-map-mailbox", text: "Mailbox column" }), mappingControls.mailbox,
      el("label", { for: "r-map-name", text: "Name column" }), mappingControls.display_name,
      el("label", { for: "r-map-department", text: "Department column" }), mappingControls.department,
      el("label", { for: "r-dept", text: "Default department when the mapped value is blank" }),
      defaultDepartment,
      el("label", { for: "r-merge", text: "Existing recipient merge choice" }), mergeExisting,
      el("p", { class: "modal-help", text: "Update changes mapped name and department fields for non-directory recipients and marks those records as CSV-managed. It does not override explicit exclusions." }),
      el("label", { for: "r-deactivate" }, [
        deactivateMissing,
        document.createTextNode(" Deactivate CSV-managed recipients missing from this file"),
      ]),
      el("p", { class: "modal-help", text: "Deactivate missing never hard-deletes, never changes directory-owned recipients, and requires a clean preview plus a second confirmation." }),
      el("div", { class: "btn-row" }, [previewButton, applyButton]),
      previewStatus,
    ]));
  }
  const table = el("table", { "aria-label": "Authorized recipient records and test-account designations" }, [
    el("thead", {}, [el("tr", {}, [
      el("th", { text: "Recipient reference" }),
      el("th", { text: "Department" }),
      el("th", { text: "Status" }),
      el("th", { text: "Test-send eligibility" }),
      el("th", { text: "Action" }),
    ])]),
    el("tbody", {}, recipients.length ? recipients.map((r) => el("tr", {}, [
      el("td", { class: "mono", text: String(r.recipient_id || "").slice(0, 8) }),
      el("td", { text: r.department || "No department" }),
      el("td", { text: r.status }),
      el("td", { text: r.is_test_account ? "Server-designated test account" : "Standard recipient" }),
      el("td", {}, [
        ...(canManageRecipients ? [el("button", {
        class: r.is_test_account ? "btn" : "btn danger",
        type: "button",
        text: r.is_test_account ? "Remove designation" : "Designate test account",
        "aria-label": `${r.is_test_account ? "Remove test-account designation from" : "Designate as test account"} recipient ${String(r.recipient_id || "").slice(0, 8)}`,
        onclick: async (event) => {
          event.currentTarget.disabled = true;
          try { await changeTestAccountDesignation(r); }
          finally { event.currentTarget.disabled = false; }
        },
        })] : []),
        ...(canManageExclusions ? [el("button", {
          class: "btn", type: "button", text: "Manage exclusions",
          "aria-label": `Manage exclusions for recipient ${String(r.recipient_id || "").slice(0, 8)}`,
          onclick: async (event) => {
            event.currentTarget.disabled = true;
            try { await manageRecipientExclusions(r, campaigns, campaignsLoaded); }
            finally { if (event.currentTarget.isConnected) event.currentTarget.disabled = false; }
          },
        })] : []),
      ]),
    ])) : [el("tr", {}, [el("td", { class: "empty", colspan: 5, text: "No recipients." })])]),
  ]);
  const pageStart = recipientPage.total === 0 ? 0 : recipientPage.offset + 1;
  const pageEnd = recipientPage.offset + recipients.length;
  const previousPage = el("button", {
    class: "btn small", type: "button", text: "Previous recipients",
    disabled: recipientPage.offset === 0 ? "disabled" : null,
    onclick: async (event) => {
      event.currentTarget.disabled = true;
      recipientPageOffset = Math.max(0, recipientPage.offset - recipientPage.limit);
      await render();
    },
  });
  const nextPage = el("button", {
    class: "btn small", type: "button", text: "Next recipients",
    disabled: recipientPage.truncated ? null : "disabled",
    onclick: async (event) => {
      event.currentTarget.disabled = true;
      recipientPageOffset = recipientPage.offset + recipientPage.limit;
      await render();
    },
  });
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Recipients" }),
    el("p", { class: "modal-help", text: "Test accounts are explicitly designated server records. The console never infers eligibility from mailbox text, names, or departments. Frozen or assigned nonterminal campaigns lock designation changes." }),
    table,
    el("div", { class: "btn-row", "aria-label": "Recipient page controls" }, [
      previousPage,
      el("span", { role: "status", text: `Showing ${pageStart}–${pageEnd} of ${recipientPage.total} recipients.` }),
      nextPage,
    ]),
  ]));
};

/* ---------- privacy ---------- */
const PRIVACY_TYPES = ["search", "access_export", "correction", "deletion", "exception"];

views.privacy = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.HANDLE_PRIVACY)) return;
  const canDeleteData = hasCapability(CAPABILITY.DELETE_DATA);
  root.appendChild(el("h2", { text: "Privacy" }));
  root.appendChild(el("p", { class: "sub", text: "Privacy notice and data-subject requests (CCPA)." }));
  let notice = null;
  let requests;
  try {
    requests = await boundedCollection("/privacy/requests");
  } catch (e) {
    root.appendChild(collectionLoadError(`Failed to load privacy requests: ${e.message}`, () => render())); return;
  }
  try {
    notice = await api("/privacy/notice");
  } catch (e) {
    root.appendChild(el("div", {
      class: "banner warning",
      text: `Privacy requests remain available, but the current notice could not be loaded: ${e.message}`,
    }));
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
        el("label", { for: "pr-type", text: "Request type" }),
        el("select", { id: "pr-type" }, PRIVACY_TYPES.map((t) => el("option", { value: t, text: t }))),
      ]),
      el("div", {}, [
        el("label", { for: "pr-mailbox", text: "Requester mailbox" }), el("input", { id: "pr-mailbox", type: "email", required: "required" }),
        el("label", { for: "pr-campaign", text: "Campaign ID (optional)" }), el("input", { id: "pr-campaign" }),
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

  async function fulfillRequest(request, button) {
    const requestReference = String(request.privacy_request_id || "").slice(0, 8);
    let body = {};
    let danger = false;
    let confirmLabel = "Complete request";
    if (request.request_type === "deletion") {
      const typedConfirmation = `DELETE ${requestReference}`;
      const values = await promptDialog({
        title: "Document deletion fulfillment",
        description: "Matched recipient data is irreversibly erased. The privacy request and aggregate audit evidence remain.",
        fields: [
          { name: "note", label: "Completion note", type: "textarea", required: true, maxLength: 2000,
            help: "Record the approved case or retention decision; do not copy unnecessary personal data." },
          { name: "confirmation", label: `Type ${typedConfirmation} to continue`, required: true, maxLength: 64 },
        ],
        submitLabel: "Review deletion",
      });
      if (!values) return;
      if (values.confirmation !== typedConfirmation) {
        toast(`Confirmation did not match. Type ${typedConfirmation} exactly.`, "error");
        return;
      }
      body = { note: values.note };
      danger = true;
      confirmLabel = "Erase matched recipient data";
    } else if (request.request_type === "correction") {
      const values = await promptDialog({
        title: "Apply verified data correction",
        description: "Leave a value blank to keep it unchanged. For display name or department, type CLEAR to erase that optional value.",
        fields: [
          { name: "employee_key", label: "Employee key", maxLength: 256 },
          { name: "mailbox", label: "Mailbox", type: "email", maxLength: 320 },
          { name: "display_name", label: "Display name", maxLength: 256 },
          { name: "department", label: "Department", maxLength: 256 },
          { name: "note", label: "Completion note", type: "textarea", required: true, maxLength: 2000 },
        ],
        submitLabel: "Review correction",
      });
      if (!values) return;
      const corrections = {};
      for (const field of ["employee_key", "mailbox", "display_name", "department"]) {
        if (!values[field]) continue;
        corrections[field] = ["display_name", "department"].includes(field) && values[field] === "CLEAR"
          ? null : values[field];
      }
      if (!Object.keys(corrections).length) {
        toast("Enter at least one supported correction.", "error");
        return;
      }
      body = { note: values.note, corrections };
      confirmLabel = "Apply correction and complete";
    } else {
      const values = await promptDialog({
        title: request.request_type === "access_export" ? "Complete access-export request" : "Complete verified search request",
        description: request.request_type === "access_export"
          ? "Download the export first. The server will refuse completion until an export has been generated."
          : "Record the outcome of the verified search before completing this request.",
        fields: [{ name: "note", label: "Completion note", type: "textarea", required: true, maxLength: 2000 }],
        submitLabel: "Review completion",
      });
      if (!values) return;
      body = { note: values.note };
    }
    const confirmed = await confirmDialog({
      title: `${confirmLabel}?`,
      message: "This closes the verified privacy request and records the outcome in the audit chain.",
      detail: { "Request reference": requestReference, Type: request.request_type },
      confirmLabel,
      danger,
    });
    if (!confirmed) return;
    button.disabled = true;
    try {
      const result = await api(`/privacy/requests/${request.privacy_request_id}/fulfill`, {
        method: "POST", body: JSON.stringify(body),
      });
      toast(`Request completed. Matched ${result.matched}; deleted ${result.deleted}; corrected ${result.corrected}.`, "success");
      location.reload();
    } catch (err) { toast(err.message, "error"); }
    finally { if (button.isConnected) button.disabled = false; }
  }

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
        finally { if (e.target.isConnected) e.target.disabled = false; }
      } }));
    }
    if (["verified", "in_progress"].includes(r.status) && r.request_type === "access_export") {
      actions.appendChild(el("button", { class: "btn small", text: "Export", onclick: async (e) => {
        e.target.disabled = true;
        try {
          const res = await api(`/privacy/requests/${r.privacy_request_id}/export`, { method: "POST" });
          const blob = new Blob([JSON.stringify(res, null, 2)], { type: "application/json" });
          const link = document.createElement("a");
          const url = URL.createObjectURL(blob);
          try {
            link.href = url;
            link.download = `privacy-request-${r.privacy_request_id}.json`;
            document.body.appendChild(link);
            link.click();
            link.remove();
          } finally { URL.revokeObjectURL(url); }
          toast(`Downloaded ${(res.records || []).length} recipient record(s)`, "success");
        } catch (err) { toast(err.message, "error"); }
        finally { e.target.disabled = false; }
      } }));
    }
    if (canDeleteData && ["verified", "in_progress"].includes(r.status)
      && ["search", "access_export", "correction", "deletion"].includes(r.request_type)) {
      const label = r.request_type === "deletion" ? "Fulfill deletion"
        : r.request_type === "correction" ? "Apply correction" : "Complete request";
      actions.appendChild(el("button", {
        class: r.request_type === "deletion" ? "btn small danger" : "btn small primary",
        type: "button", text: label,
        onclick: (event) => fulfillRequest(r, event.currentTarget),
      }));
    } else if (["verified", "in_progress"].includes(r.status) && r.request_type === "exception") {
      actions.appendChild(el("span", {
        class: "modal-help",
        text: "Exception completion requires documented legal review; this API has no legal-review completion workflow.",
      }));
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
const THREAT_PAGE_LIMIT = 25;
const THREAT_MAX_OFFSET = 10000;
let threatPageOffset = 0;
const threatFilterState = {
  review_state: "",
  confidence: "",
  freshness: "",
  source_id: "",
};

views.sources = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.MANAGE_SOURCES)) return;
  const canManageSources = hasCapability(CAPABILITY.MANAGE_SOURCES);
  const canSubmitSource = hasCapability(CAPABILITY.SUBMIT_SOURCE);
  const refreshSourceView = async () => {
    root.replaceChildren();
    await views.sources(root);
  };
  const typeLabel = (sourceType) => ({
    rss: "RSS feed",
    stix: "STIX feed",
    bulk_download: "Bulk download",
  }[sourceType] || "Unsupported type");
  const timeLabel = (value) => value ? formatInstant(value) : "Never";
  const boundedMetadata = (value, limit) => {
    const text = String(value || "Not recorded");
    return text.length <= limit ? text : `${text.slice(0, limit - 1)}…`;
  };
  const lifecycleError = (err) => {
    if (err.status === 409) {
      toast("Source action blocked. Confirm current source terms and enabled state; no job was queued.", "error");
      return;
    }
    if (err.status === 403) {
      toast("Your current session does not have source-management capability. No change was made.", "error");
      return;
    }
    toast("Source action could not be completed. Refresh and retry.", "error");
  };
  const termsError = (err) => {
    if (err.status === 422) {
      toast("Terms acknowledgement was not accepted. Check every field and retry.", "error");
      return;
    }
    if (err.status === 403) {
      toast("Your current session does not have source-management capability. No change was made.", "error");
      return;
    }
    toast("Source terms could not be changed. Refresh and retry.", "error");
  };
  root.appendChild(el("h2", { text: "Threat Campaigns" }));
  root.appendChild(el("p", {
    class: "sub",
    text: "Curate current threat evidence, then register and govern the supported RSS, STIX, and bulk-download source adapters.",
  }));
  root.appendChild(el("div", { class: "policy-banner" }, [
    el("strong", { text: "Current terms are required. " }),
    document.createTextNode(
      "Enable and Ingest remain unavailable until all four permissions are explicitly confirmed. Revocation disables the source. Disable is not cancellation: it prevents new and not-yet-started ingestion but does not cancel a fetch already in progress.",
    ),
  ]));
  let sources;
  try { sources = await boundedCollection("/sources"); } catch (e) {
    root.appendChild(collectionLoadError("Sources could not be loaded. Refresh and retry.", () => render())); return;
  }

  const reviewFilter = el("select", { "aria-label": "Filter threat campaigns by review state" }, [
    el("option", { value: "", text: "All review states" }),
    ...["active", "quarantined", "rejected", "duplicate"].map((value) => (
      el("option", { value, text: value, selected: threatFilterState.review_state === value })
    )),
  ]);
  const confidenceFilter = el("select", { "aria-label": "Filter threat campaigns by confidence" }, [
    el("option", { value: "", text: "All confidence levels" }),
    ...["high", "medium", "low"].map((value) => (
      el("option", { value, text: value, selected: threatFilterState.confidence === value })
    )),
  ]);
  const freshnessFilter = el("select", { "aria-label": "Filter threat campaigns by freshness" }, [
    el("option", { value: "", text: "All freshness levels" }),
    ...["fresh", "aging", "stale"].map((value) => (
      el("option", { value, text: value, selected: threatFilterState.freshness === value })
    )),
  ]);
  const sourceFilter = el("select", { "aria-label": "Filter threat campaigns by source" }, [
    el("option", { value: "", text: "All configured sources" }),
    ...sources.map((source) => el("option", {
      value: source.source_id,
      text: boundedMetadata(source.name, 255),
      selected: threatFilterState.source_id === source.source_id,
    })),
  ]);
  const threatContent = el("div", { "aria-live": "polite", "aria-busy": "false" });

  const validThreatPage = (payload) => Boolean(
    payload && typeof payload === "object"
    && Array.isArray(payload.items) && payload.items.length <= THREAT_PAGE_LIMIT
    && Number.isInteger(payload.total) && payload.total >= 0
    && payload.limit === THREAT_PAGE_LIMIT
    && payload.offset === threatPageOffset
    && typeof payload.truncated === "boolean"
    && typeof payload.as_of === "string"
    && payload.items.every((item) => (
      item && typeof item === "object"
      && typeof item.source_item_id === "string"
      && typeof item.source_id === "string"
      && typeof item.title === "string" && item.title.length <= 255
      && typeof item.publisher === "string" && item.publisher.length <= 255
      && typeof item.citation === "string" && item.citation.length <= 2048
      && typeof item.excerpt === "string" && item.excerpt.length <= 500
      && item.excerpt_is_untrusted === true
      && typeof item.published_at === "string"
      && typeof item.retrieved_at === "string"
      && item.freshness && ["fresh", "aging", "stale"].includes(item.freshness.bucket)
      && Number.isInteger(item.freshness.published_age_days)
      && Number.isInteger(item.freshness.retrieved_age_days)
      && (item.claimed_actor === null || typeof item.claimed_actor === "string")
      && (item.claimed_target_sector === null || typeof item.claimed_target_sector === "string")
      && ["high", "medium", "low"].includes(item.confidence)
      && ["active", "quarantined", "rejected", "duplicate"].includes(item.review_state)
      && Array.isArray(item.ttp_indicator_summary) && item.ttp_indicator_summary.length <= 20
      && item.ttp_indicator_summary.every((indicator) => (
        indicator && typeof indicator.name === "string" && indicator.name.length <= 64
        && typeof indicator.value === "string" && indicator.value.length <= 256
      ))
      && item.source_health && typeof item.source_health === "object"
      && typeof item.source_health.source_id === "string"
      && typeof item.source_health.name === "string" && item.source_health.name.length <= 255
      && typeof item.source_health.enabled === "boolean"
      && typeof item.source_health.governance_ready === "boolean"
      && ["disabled", "governance_blocked", "awaiting_first_success", "degraded", "healthy"].includes(item.source_health.state)
      && Number.isInteger(item.source_health.consecutive_failures)
      && (item.source_health.last_success_at === null || typeof item.source_health.last_success_at === "string")
      && (item.source_health.last_attempt_at === null || typeof item.source_health.last_attempt_at === "string")
    )),
  );

  const threatActionError = (error) => {
    if (error.status === 403) {
      toast("Source-management capability is required. No threat curation change was made.", "error");
    } else if (error.status === 409) {
      toast("The threat item changed or the duplicate relationship is not valid. Refresh and review it again.", "error");
    } else if (error.status === 422) {
      toast("The threat action was not accepted. Use bounded non-identifying rationale and valid references.", "error");
    } else {
      toast("Threat curation could not be completed. Refresh and retry.", "error");
    }
  };

  const loadThreats = async () => {
    threatContent.setAttribute("aria-busy", "true");
    threatContent.replaceChildren(el("p", { role: "status", text: "Loading bounded threat campaign page…" }));
    const params = new URLSearchParams({
      limit: String(THREAT_PAGE_LIMIT), offset: String(threatPageOffset),
    });
    for (const [name, value] of Object.entries(threatFilterState)) {
      if (value) params.set(name, value);
    }
    let page;
    try {
      page = await api(`/threats?${params.toString()}`);
      if (!validThreatPage(page)) throw new Error("invalid threat page");
    } catch {
      threatContent.setAttribute("aria-busy", "false");
      threatContent.replaceChildren(collectionLoadError(
        "Threat campaigns could not be loaded or validated. Actions remain unavailable.",
        loadThreats,
      ));
      return;
    }

    const rows = page.items.map((item) => {
      const indicators = item.ttp_indicator_summary.length
        ? item.ttp_indicator_summary.map((indicator) => (
          el("li", { text: `${boundedMetadata(indicator.name, 64)}: ${boundedMetadata(indicator.value, 256)}` })
        ))
        : [el("li", { text: "No bounded TTP or indicator summary" })];
      const health = item.source_health;
      const pageCandidates = page.items.filter((candidate) => candidate.source_item_id !== item.source_item_id);
      const actions = [];

      actions.push(el("button", {
        class: "btn small primary", type: "button", text: "Activate",
        "aria-label": `Activate threat campaign ${boundedMetadata(item.title, 120)}`,
        disabled: !canManageSources || item.review_state === "active" ? "disabled" : null,
        title: item.review_state === "active" ? "This threat item is already active" : null,
        onclick: async (event) => {
          const confirmed = await confirmDialog({
            title: "Activate this threat evidence?",
            message: "Activation creates or retains one deterministic draft pattern-basis candidate for explicit downstream review. It never approves a pattern, selects recipients, or launches a campaign.",
            detail: { "Source item": item.source_item_id, "Current review state": item.review_state },
            confirmLabel: "Activate evidence",
          });
          if (!confirmed) return;
          event.currentTarget.disabled = true;
          try {
            await api(`/threats/${encodeURIComponent(item.source_item_id)}/activate`, { method: "POST" });
            toast("Threat evidence activated. Pattern review remains a separate operator step.", "success");
            await loadThreats();
          } catch (error) { threatActionError(error); event.currentTarget.disabled = false; }
        },
      }));

      actions.push(el("button", {
        class: "btn small danger", type: "button", text: "Reject",
        "aria-label": `Reject threat campaign ${boundedMetadata(item.title, 120)}`,
        disabled: !canManageSources ? "disabled" : null,
        onclick: async (event) => {
          const values = await promptDialog({
            title: "Reject this threat evidence",
            description: "Record a short program-relevance rationale. The server rejects contact details, URLs, IP addresses, identifiers, and other identifying data.",
            fields: [{
              name: "rationale", label: "Non-identifying rationale", type: "textarea", required: true,
              maxLength: 256, help: "1–256 characters. Do not include people, contact data, URLs, IP addresses, or secrets.",
            }],
            submitLabel: "Reject evidence",
          });
          if (!values) return;
          event.currentTarget.disabled = true;
          try {
            await api(`/threats/${encodeURIComponent(item.source_item_id)}/reject`, {
              method: "POST", body: JSON.stringify({ rationale: values.rationale }),
            });
            toast("Threat evidence rejected. No downstream campaign state changed.", "success");
            await loadThreats();
          } catch (error) { threatActionError(error); event.currentTarget.disabled = false; }
        },
      }));

      actions.push(el("button", {
        class: "btn small", type: "button", text: "Merge duplicate",
        "aria-label": `Merge duplicate threat campaign ${boundedMetadata(item.title, 120)}`,
        disabled: !canManageSources || !pageCandidates.length ? "disabled" : null,
        title: pageCandidates.length ? null : "No canonical target is available on this bounded page",
        onclick: async (event) => {
          const values = await promptDialog({
            title: "Merge this item as a duplicate",
            description: "Choose the canonical item from this bounded page. The server prevents self-links, missing targets, and duplicate cycles.",
            fields: [{
              name: "duplicate_of", label: "Canonical threat evidence", type: "select", required: true,
              options: pageCandidates.map((candidate) => ({
                value: candidate.source_item_id,
                label: `${boundedMetadata(candidate.title, 100)} · ${candidate.source_item_id.slice(0, 8)}`,
              })),
            }],
            submitLabel: "Merge as duplicate",
          });
          if (!values) return;
          event.currentTarget.disabled = true;
          try {
            await api(`/threats/${encodeURIComponent(item.source_item_id)}/merge-duplicate`, {
              method: "POST", body: JSON.stringify({ duplicate_of: values.duplicate_of }),
            });
            toast("Duplicate relationship recorded. No pattern, audience, approval, or launch was changed.", "success");
            await loadThreats();
          } catch (error) { threatActionError(error); event.currentTarget.disabled = false; }
        },
      }));

      return el("tr", {}, [
        el("td", {}, [
          el("strong", { text: boundedMetadata(item.title, 255) }),
          el("p", { text: `Publisher: ${boundedMetadata(item.publisher, 255)}` }),
          el("p", { text: `Citation text: ${boundedMetadata(item.citation, 2048)}` }),
          el("p", { class: "mono", text: `Source item: ${item.source_item_id}` }),
        ]),
        el("td", {}, [
          el("p", { text: `Actor: ${boundedMetadata(item.claimed_actor, 255)}` }),
          el("p", { text: `Sector: ${boundedMetadata(item.claimed_target_sector, 255)}` }),
          el("p", { text: `Confidence: ${item.confidence}` }),
          el("ul", { "aria-label": "Bounded TTP and indicator summary" }, indicators),
        ]),
        el("td", {}, [
          el("details", {}, [
            el("summary", { text: "View minimized untrusted excerpt" }),
            el("p", { class: "modal-warn", text: "Untrusted source text follows. It is rendered only as text; remote HTML is never executed." }),
            el("p", { text: boundedMetadata(item.excerpt, 500) }),
          ]),
        ]),
        el("td", {}, [
          el("p", { text: `Published: ${timeLabel(item.published_at)} (${item.freshness.published_age_days}d old)` }),
          el("p", { text: `Retrieved: ${timeLabel(item.retrieved_at)} (${item.freshness.retrieved_age_days}d old)` }),
          el("span", { class: `pill ${item.freshness.bucket === "fresh" ? "ok" : "down"}`, text: item.freshness.bucket }),
        ]),
        el("td", {}, [
          el("span", { class: `pill ${health.state === "healthy" ? "ok" : "down"}`, text: health.state }),
          el("p", { text: `Source: ${boundedMetadata(health.name, 255)}` }),
          el("p", { text: `Daily ingestion last attempt: ${timeLabel(health.last_attempt_at)}` }),
          el("p", { text: `Last success: ${timeLabel(health.last_success_at)}` }),
          el("p", { text: `Failures: ${health.consecutive_failures}; enabled: ${health.enabled ? "yes" : "no"}; governance: ${health.governance_ready ? "current" : "blocked"}` }),
        ]),
        el("td", {}, [
          el("span", { class: `pill ${item.review_state === "active" ? "ok" : "down"}`, text: item.review_state }),
          item.review_rationale ? el("p", { text: `Rationale: ${boundedMetadata(item.review_rationale, 256)}` }) : null,
          item.duplicate_of ? el("p", { class: "mono", text: `Duplicate of: ${item.duplicate_of}` }) : null,
        ].filter(Boolean)),
        el("td", {}, [el("div", { class: "btn-row", role: "group", "aria-label": `Curation actions for ${boundedMetadata(item.title, 120)}` }, actions)]),
      ]);
    });

    const previous = el("button", {
      class: "btn small", type: "button", text: "Previous threat page",
      disabled: page.offset === 0 ? "disabled" : null,
      onclick: async () => { threatPageOffset = Math.max(0, page.offset - THREAT_PAGE_LIMIT); await loadThreats(); },
    });
    const next = el("button", {
      class: "btn small", type: "button", text: "Next threat page",
      disabled: !page.truncated || page.offset + THREAT_PAGE_LIMIT > THREAT_MAX_OFFSET ? "disabled" : null,
      onclick: async () => {
        threatPageOffset = Math.min(THREAT_MAX_OFFSET, page.offset + THREAT_PAGE_LIMIT);
        await loadThreats();
      },
    });
    threatContent.setAttribute("aria-busy", "false");
    threatContent.replaceChildren(
      el("p", { class: "field-help", text: `Server snapshot ${timeLabel(page.as_of)} · showing ${page.offset + (page.items.length ? 1 : 0)}–${page.offset + page.items.length} of ${page.total}.` }),
      el("table", { "aria-label": "Bounded threat campaign curation queue" }, [
        el("thead", {}, [el("tr", {}, [
          "Threat and citation", "Actor, sector and indicators", "Minimized evidence", "Freshness",
          "Daily source health", "Review state", "Actions",
        ].map((label) => el("th", { text: label })))]),
        el("tbody", {}, rows.length ? rows : [el("tr", {}, [
          el("td", { class: "empty", role: "status", colspan: 7, text: "No threat campaigns match these filters." }),
        ])]),
      ]),
      el("div", { class: "btn-row", "aria-label": "Threat campaign pagination" }, [previous, next]),
    );
  };

  const filterThreats = async () => {
    threatFilterState.review_state = reviewFilter.value;
    threatFilterState.confidence = confidenceFilter.value;
    threatFilterState.freshness = freshnessFilter.value;
    threatFilterState.source_id = sourceFilter.value;
    threatPageOffset = 0;
    await loadThreats();
  };
  const nextStep = canNavigateTo("patterns")
    ? el("button", {
      class: "btn", type: "button", text: "Open pattern review",
      onclick: () => navigateTo("patterns"),
    })
    : el("p", { class: "field-help", text: "An operator with campaign-pattern access must complete the separate pattern review step." });
  root.appendChild(el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [el("h3", { text: "Threat Campaigns workbench" }), nextStep]),
    el("div", { class: "policy-banner" }, [
      el("strong", { text: "Curation is evidence review only. " }),
      document.createTextNode("Activation creates or retains one deterministic draft pattern-basis candidate; rejecting and merging curate evidence only. These actions never approve a pattern, select recipients, or launch a campaign. Pattern review is the explicit next step."),
    ]),
    el("div", { class: "btn-row", role: "search", "aria-label": "Threat campaign filters" }, [
      reviewFilter, confidenceFilter, freshnessFilter, sourceFilter,
      el("button", { class: "btn primary", type: "button", text: "Apply threat filters", onclick: filterThreats }),
      el("button", { class: "btn", type: "button", text: "Refresh threat page", onclick: loadThreats }),
    ]),
    threatContent,
  ]));
  await loadThreats();

  const governanceEntries = await Promise.all(sources.map(async (source) => {
    try {
      const state = await api(`/sources/${encodeURIComponent(source.source_id)}/terms/current`);
      return [source.source_id, { ...state, unavailable: false }];
    } catch {
      return [source.source_id, { governance_ready: false, acknowledgement: null, unavailable: true }];
    }
  }));
  const governanceBySource = new Map(governanceEntries);
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "New source" }),
    el("p", { class: "field-help", text: "New sources start disabled. Record a current terms acknowledgement before enabling ingestion." }),
    el("div", { class: "form-grid" }, [
      el("div", {}, [
        el("label", { for: "s-name", text: "Name" }), el("input", { id: "s-name" }),
        el("label", { for: "s-domain", text: "Base domain" }), el("input", { id: "s-domain", value: "example.com" }),
      ]),
      el("div", {}, [
        el("label", { for: "s-type", text: "Source type" }),
        el("select", { id: "s-type" }, ["rss", "stix", "bulk_download"].map((value) => (
          el("option", { value, text: typeLabel(value) })
        ))),
        el("label", { for: "s-path", text: "Feed path" }), el("input", { id: "s-path", value: "/" }),
      ]),
    ]),
    el("div", { class: "btn-row" }, [
      el("button", {
        class: "btn primary", type: "button", text: "Create source",
        disabled: canSubmitSource ? null : "disabled",
        title: canSubmitSource ? null : "Source-submission capability is required.",
        onclick: async (e) => {
        if (!canSubmitSource) return;
        const btn = e.target; btn.disabled = true;
        try {
          await api("/sources", { method: "POST", body: JSON.stringify({
            name: document.getElementById("s-name").value,
            source_type: document.getElementById("s-type").value,
            base_domain: document.getElementById("s-domain").value,
            fetch_path: document.getElementById("s-path").value,
          }) });
          toast("Source created. Record its terms acknowledgement before enabling ingestion.", "success");
          await refreshSourceView();
        } catch (err) { lifecycleError(err); }
        finally { btn.disabled = false; }
        },
      }),
    ]),
  ]));

  const rows = sources.map((source) => {
    const failures = Number.isInteger(source.consecutive_failures) ? source.consecutive_failures : 0;
    const governance = governanceBySource.get(source.source_id) || {
      governance_ready: false, acknowledgement: null, unavailable: true,
    };
    const acknowledgement = governance.acknowledgement;
    const acknowledgementEnabled = acknowledgement?.enabled === true;
    const governanceReady = governance.governance_ready === true && !governance.unavailable;
    const nextReviewTime = acknowledgement?.next_review_at
      ? new Date(acknowledgement.next_review_at).getTime()
      : Number.NaN;
    const governanceLabel = governance.unavailable
      ? "Unavailable"
      : !acknowledgement
        ? "Missing"
        : !acknowledgementEnabled
          ? "Revoked"
          : Number.isFinite(nextReviewTime) && nextReviewTime <= Date.now()
            ? "Expired"
            : governanceReady ? "Current" : "Incomplete";
    const actionButtons = [];
    let busy = false;
    const setBusy = (value) => {
      busy = value;
      for (const button of actionButtons) {
        const needsCurrentTerms = button.dataset.requiresCurrentTerms === "true";
        const needsEnabledTerms = button.dataset.requiresEnabledTerms === "true";
        button.disabled = value || !canManageSources
          || (needsCurrentTerms && !governanceReady)
          || (needsEnabledTerms && !acknowledgementEnabled);
        button.setAttribute("aria-disabled", String(button.disabled));
      }
    };
    const runAction = async (action) => {
      const needsCurrentTerms = action === "enable" || action === "ingest";
      if (busy || !canManageSources || (needsCurrentTerms && !governanceReady)) return;
      if (action === "disable") {
        const confirmed = await confirmDialog({
          title: `Disable ${source.name}?`,
          message: "This prevents new and not-yet-started ingestion. A fetch already in progress is not cancelled.",
          confirmLabel: "Disable source",
          danger: true,
        });
        if (!confirmed) return;
      }
      setBusy(true);
      try {
        const result = await api(`/sources/${encodeURIComponent(source.source_id)}/${action}`, { method: "POST" });
        if (action === "enable") {
          toast(result.changed
            ? `Source enabled and ingestion queued. Request reference: ${result.job_id}. This reference is not a status link.`
            : "Source was already enabled; no new ingestion was queued.", "success");
        } else if (action === "disable") {
          toast(result.changed
            ? "Source disabled. New and not-yet-started ingestion is blocked; an in-progress fetch is not cancelled."
            : "Source was already disabled; no change was made.", "success");
        } else {
          toast(`Ingestion queued. Request reference: ${result.job_id}. This reference is not a status link.`, "success");
        }
        await refreshSourceView();
      } catch (err) {
        lifecycleError(err);
        setBusy(false);
      }
    };
    const makeAction = (action, label, primary = false) => {
      const needsCurrentTerms = action === "enable" || action === "ingest";
      const button = el("button", {
        class: `btn small${primary ? " primary" : ""}`,
        type: "button",
        text: label,
        disabled: canManageSources && (!needsCurrentTerms || governanceReady) ? null : "disabled",
        "aria-disabled": String(!canManageSources || (needsCurrentTerms && !governanceReady)),
        "aria-label": `${label} for source ${source.name}`,
        title: needsCurrentTerms && !governanceReady ? "Record a current terms acknowledgement first" : null,
        onclick: () => runAction(action),
      });
      button.dataset.requiresCurrentTerms = String(needsCurrentTerms);
      actionButtons.push(button);
      return button;
    };
    const acknowledgeTerms = () => {
      if (busy || !canManageSources) return;
      const { dlg, form } = dialogShell(
        `Acknowledge source terms for ${source.name}`,
        "Confirm the reviewed terms explicitly. These confirmations are never inferred or selected for you.",
      );
      const reference = el("input", {
        id: `terms-reference-${source.source_id}`, type: "text", maxlength: "2048", required: "required",
        autocomplete: "off", spellcheck: "false",
      });
      const hash = el("input", {
        id: `terms-hash-${source.source_id}`, type: "text", maxlength: "64", required: "required",
        pattern: "[0-9A-Fa-f]{64}", autocomplete: "off", spellcheck: "false", autocapitalize: "none",
      });
      const termsFile = el("input", {
        id: `terms-file-${source.source_id}`, type: "file",
        "aria-describedby": `terms-file-help-${source.source_id}`,
      });
      const hashStatus = el("p", {
        id: `terms-file-help-${source.source_id}`, class: "modal-help", role: "status",
        text: "Optional: choose the exact reviewed terms file to calculate its SHA-256 in this browser. The file is never uploaded.",
      });
      termsFile.addEventListener("change", async () => {
        const file = termsFile.files?.[0];
        if (!file) return;
        if (file.size > 5 * 1024 * 1024) {
          hashStatus.textContent = "The selected file exceeds the 5 MB browser hashing limit.";
          termsFile.value = "";
          return;
        }
        if (!globalThis.crypto?.subtle) {
          hashStatus.textContent = "Browser SHA-256 is unavailable in this context; enter the reviewed hash manually.";
          return;
        }
        termsFile.disabled = true;
        try {
          const digest = await globalThis.crypto.subtle.digest("SHA-256", await file.arrayBuffer());
          hash.value = [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
          hashStatus.textContent = `SHA-256 calculated locally for ${file.name}. Review it before recording the acknowledgement.`;
        } catch {
          hashStatus.textContent = "The browser could not hash this file; enter the reviewed SHA-256 manually.";
        } finally {
          termsFile.disabled = false;
        }
      });
      const nextReview = el("input", {
        id: `terms-review-${source.source_id}`, type: "datetime-local", required: "required", step: "60",
      });
      form.appendChild(el("label", { for: reference.id, text: "Terms reference" }));
      form.appendChild(reference);
      form.appendChild(el("p", {
        class: "modal-help", text: "Use a non-secret URL or policy reference (1–2048 characters).",
      }));
      form.appendChild(el("label", { for: hash.id, text: "Terms SHA-256" }));
      form.appendChild(hash);
      form.appendChild(el("p", {
        class: "modal-help", text: "Enter the exact 64-character hexadecimal SHA-256 of the reviewed terms.",
      }));
      form.appendChild(el("label", { for: termsFile.id, text: "Calculate from reviewed terms file (optional)" }));
      form.appendChild(termsFile);
      form.appendChild(hashStatus);
      form.appendChild(el("label", { for: nextReview.id, text: "Review again after (your local time)" }));
      form.appendChild(nextReview);

      const confirmations = [
        ["commercial_use_ok", "The terms permit commercial use for this program."],
        ["automation_ok", "The terms permit automated retrieval."],
        ["redistribution_ok", "The terms permit the required redistribution or derived use."],
        ["retention_ok", "The terms permit the configured retention of source material."],
      ].map(([name, label]) => {
        const input = el("input", { id: `terms-${name}-${source.source_id}`, type: "checkbox", name });
        form.appendChild(el("label", { for: input.id, class: "check-row" }, [input, document.createTextNode(label)]));
        return [name, input];
      });
      const errorLine = el("div", { class: "modal-error", role: "alert", "aria-live": "assertive" });
      form.appendChild(errorLine);
      const cancel = el("button", { class: "btn", type: "button", text: "Cancel", onclick: () => dlg.close() });
      const submit = el("button", { class: "btn primary", type: "submit", text: "Record acknowledgement" });
      form.appendChild(el("div", { class: "modal-actions" }, [cancel, submit]));
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        errorLine.textContent = "";
        const normalizedReference = reference.value.trim();
        const normalizedHash = hash.value.trim().toLowerCase();
        const reviewDate = new Date(nextReview.value);
        if (!normalizedReference || normalizedReference.length > 2048 || /[\u0000-\u001f]/.test(normalizedReference)) {
          errorLine.textContent = "Enter a single-line terms reference between 1 and 2048 characters.";
          return;
        }
        if (!/^[0-9a-f]{64}$/.test(normalizedHash)) {
          errorLine.textContent = "Enter an exact 64-character hexadecimal SHA-256.";
          return;
        }
        if (!nextReview.value || Number.isNaN(reviewDate.getTime()) || reviewDate.getTime() <= Date.now()) {
          errorLine.textContent = "Choose a future review date and time.";
          return;
        }
        if (confirmations.some(([, input]) => !input.checked)) {
          errorLine.textContent = "Explicitly confirm all four source-use permissions.";
          return;
        }
        submit.disabled = true;
        cancel.disabled = true;
        try {
          await api(`/sources/${encodeURIComponent(source.source_id)}/terms`, {
            method: "POST",
            body: JSON.stringify({
              terms_reference: normalizedReference,
              terms_hash: normalizedHash,
              commercial_use_ok: confirmations[0][1].checked,
              automation_ok: confirmations[1][1].checked,
              redistribution_ok: confirmations[2][1].checked,
              retention_ok: confirmations[3][1].checked,
              next_review_at: reviewDate.toISOString(),
            }),
          });
          toast("Source terms acknowledgement recorded. Enable and Ingest now use the current review.", "success");
          dlg.close();
          await refreshSourceView();
        } catch (err) {
          termsError(err);
          submit.disabled = false;
          cancel.disabled = false;
        }
      });
      openDialog(dlg);
    };
    const revokeTerms = async () => {
      if (busy || !canManageSources || !acknowledgementEnabled) return;
      const confirmed = await confirmDialog({
        title: `Revoke terms for ${source.name}?`,
        message: "Revocation disables this acknowledgement and the source. Queued workers recheck terms before using fetched material.",
        detail: { Source: source.name, "Current terms state": governanceLabel },
        confirmLabel: "Revoke terms and disable source",
        danger: true,
      });
      if (!confirmed) return;
      setBusy(true);
      try {
        await api(`/sources/${encodeURIComponent(source.source_id)}/terms/revoke`, { method: "POST" });
        toast("Source terms revoked and source disabled.", "success");
        await refreshSourceView();
      } catch (err) {
        termsError(err);
        setBusy(false);
      }
    };
    const actions = source.enabled
      ? [makeAction("ingest", "Ingest now", true), makeAction("disable", "Disable")]
      : [makeAction("enable", "Enable", true)];
    const acknowledgeButton = el("button", {
      class: "btn small", type: "button", text: acknowledgement ? "Replace terms" : "Acknowledge terms",
      disabled: canManageSources ? null : "disabled",
      "aria-disabled": String(!canManageSources),
      "aria-label": `Acknowledge terms for source ${source.name}`,
      onclick: acknowledgeTerms,
    });
    const revokeButton = el("button", {
      class: "btn small danger", type: "button", text: "Revoke terms",
      disabled: canManageSources && acknowledgementEnabled ? null : "disabled",
      "aria-disabled": String(!canManageSources || !acknowledgementEnabled),
      "aria-label": `Revoke terms for source ${source.name}`,
      onclick: revokeTerms,
    });
    revokeButton.dataset.requiresEnabledTerms = "true";
    const refreshButton = el("button", {
      class: "btn small", type: "button", text: "Refresh terms",
      disabled: canManageSources ? null : "disabled",
      "aria-disabled": String(!canManageSources),
      "aria-label": `Refresh terms for source ${source.name}`,
      onclick: refreshSourceView,
    });
    actionButtons.push(acknowledgeButton, revokeButton, refreshButton);
    actions.push(acknowledgeButton, revokeButton, refreshButton);
    const breakerState = source.enabled
      ? "Not disabled"
      : failures > 0
        ? "Disabled with unresolved failures; the disabling cause is not recorded"
        : "No failure trip recorded";
    return el("tr", {}, [
      el("td", { text: source.name }),
      el("td", { text: typeLabel(source.source_type) }),
      el("td", { text: `${source.base_domain}${source.fetch_path || "/"}` }),
      el("td", { text: source.enabled ? "Enabled" : "Disabled" }),
      el("td", { text: timeLabel(source.last_attempt_at) }),
      el("td", { text: timeLabel(source.last_success_at) }),
      el("td", { class: "num", text: String(failures) }),
      el("td", { text: breakerState }),
      el("td", {}, [
        el("span", {
          class: `pill ${governanceReady ? "ok" : "down"}`,
          text: governanceLabel,
        }),
        governance.unavailable
          ? el("p", { class: "field-help", text: "Terms state unavailable. Enable and Ingest remain disabled." })
          : acknowledgement
            ? el("dl", { class: "modal-detail" }, [
              el("dt", { text: "Reference" }),
              el("dd", { text: boundedMetadata(acknowledgement.terms_reference, 2048) }),
              el("dt", { text: "SHA-256" }),
              el("dd", { class: "mono", text: boundedMetadata(acknowledgement.terms_hash, 64) }),
              el("dt", { text: "Reviewed" }),
              el("dd", { text: timeLabel(acknowledgement.reviewed_at) }),
              el("dt", { text: "Next review" }),
              el("dd", { text: timeLabel(acknowledgement.next_review_at) }),
            ])
            : el("p", { class: "field-help", text: "No terms acknowledgement recorded." }),
      ]),
      el("td", {}, [el("div", { class: "btn-row" }, actions)]),
    ]);
  });
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: "Configured sources" }),
    el("table", { "aria-label": "Configured source ingestion lifecycle" }, [
      el("thead", {}, [el("tr", {}, [
        "Name", "Type", "Domain and path", "Status", "Last attempt", "Last success",
        "Consecutive failures", "Failure breaker", "Terms governance", "Actions",
      ].map((name) => el("th", { text: name })))]),
      el("tbody", {}, rows.length ? rows : [el("tr", {}, [
        el("td", { class: "empty", role: "status", colspan: 10, text: "No configured sources." }),
      ])]),
    ]),
  ]));
};

/* ---------- patterns ---------- */
views.patterns = async (root) => {
  if (!requireAnyCapability(
    root, CAPABILITY.CREATE_CAMPAIGN, CAPABILITY.APPROVE_PATTERN,
  )) return;
  root.appendChild(el("h2", { text: "Campaign-pattern library" }));
  root.appendChild(el("p", { class: "sub", text: "Search reusable patterns, safely inspect their educational cues, or clone one for human review." }));
  root.appendChild(el("div", { class: "policy-banner" }, [
    el("strong", { text: "Clones are never pre-approved. " }),
    document.createTextNode("Every copy starts as a DRAFT, carries no source evidence or review decision, and must pass independent human approval before use."),
  ]));

  const search = el("input", { type: "search", maxlength: "100", "aria-label": "Search campaign patterns", placeholder: "Search role, action, actor, or sector" });
  const stateFilter = el("select", { "aria-label": "Filter patterns by review state" }, [
    el("option", { value: "", text: "All review states" }),
    ...["approved", "draft", "pending", "rejected"].map((value) => el("option", { value, text: value })),
  ]);
  const categoryFilter = el("select", { "aria-label": "Filter patterns by lure category" }, [
    el("option", { value: "", text: "All lure categories" }),
    ...["invoice", "password_reset", "shared_document", "executive_request", "vendor_impersonation", "oauth_consent", "qr_phishing", "payroll_hr", "conference", "calendar_invite", "urgent_response", "credential_reference", "malware_reference", "invoice_reference", "other"]
      .map((value) => el("option", { value, text: value })),
  ]);
  const difficultyFilter = el("select", { "aria-label": "Filter patterns by difficulty" }, [
    el("option", { value: "", text: "All difficulty levels" }),
    ...[1, 2, 3, 4, 5].map((value) => el("option", { value: String(value), text: `Difficulty ${value}` })),
  ]);
  const results = el("div", { "aria-live": "polite" });

  const preview = async (pattern, button) => {
    button.disabled = true;
    let detail;
    try { detail = await api(`/patterns/${pattern.campaign_pattern_id}/preview`); }
    catch (err) { toast(err.message, "error"); button.disabled = false; return; }
    button.disabled = false;
    const previewActionAuthorityValid = hasBooleanActionFlags(detail, PATTERN_ACTION_FLAGS);
    const { dlg, form } = dialogShell(
      `Pattern preview: ${detail.lure_category}`,
      "A non-executing, privacy-minimized view of the reusable pattern. Supporting source evidence is deliberately excluded.",
    );
    const facts = el("dl", { class: "modal-detail" });
    for (const [label, value] of [
      ["Review state", detail.approval_state], ["Target role", detail.target_role_category || "Not specified"],
      ["Impersonation", detail.impersonation_category || "Not specified"], ["Requested action", detail.requested_action || "Not specified"],
      ["Delivery method", detail.delivery_method || "Not specified"], ["Actor type", detail.actor_type || "Not specified"],
      ["Sector", detail.sector_targeting || "Not specified"], ["Difficulty", detail.difficulty?.score ?? "Not specified"],
    ]) {
      facts.appendChild(el("dt", { text: label })); facts.appendChild(el("dd", { text: String(value) }));
    }
    form.appendChild(facts);
    if (!previewActionAuthorityValid) {
      form.appendChild(actionAuthorityUnavailable("Pattern preview", async (event) => {
        event.currentTarget.disabled = true;
        dlg.close();
        await load();
      }));
    }
    for (const [heading, items] of [["Warning cues", detail.warning_cues], ["Emotional triggers", detail.emotional_triggers], ["Attack techniques", detail.attack_techniques]]) {
      form.appendChild(el("h4", { class: "modal-section", text: heading }));
      form.appendChild(el("ul", {}, (items || []).map((item) => el("li", { text: typeof item === "string" ? item : JSON.stringify(item) }))));
    }
    form.appendChild(el("div", { class: "modal-actions" }, [
      el("button", { class: "btn primary", type: "button", text: "Close preview", onclick: () => dlg.close() }),
    ]));
    openDialog(dlg);
  };

  const load = async () => {
    results.replaceChildren(el("p", { class: "empty", text: "Loading campaign patterns…" }));
    const params = new URLSearchParams({ limit: "100" });
    if (search.value.trim()) params.set("q", search.value.trim());
    if (stateFilter.value) params.set("approval_state", stateFilter.value);
    if (categoryFilter.value) params.set("lure_category", categoryFilter.value);
    if (difficultyFilter.value) params.set("difficulty_score", difficultyFilter.value);
    let patterns;
    try {
      patterns = await boundedCollection(`/patterns?${params}`);
      if (!Array.isArray(patterns)) throw new Error("The server returned an invalid pattern list");
    } catch (err) {
      results.replaceChildren(collectionLoadError(
        `Could not load pattern library: ${err.message}`,
        () => load(),
      ));
      return;
    }
    const rows = patterns.map((pattern) => {
      const reviewLabel = pattern.reusable ? "Approved reusable" : `${pattern.approval_state} — human review required`;
      const actionAuthorityValid = hasBooleanActionFlags(pattern, PATTERN_ACTION_FLAGS);
      const actions = [
        el("button", { class: "btn small", type: "button", text: "Safe preview", "aria-label": `Safely preview ${pattern.lure_category} pattern`,
          onclick: (event) => preview(pattern, event.currentTarget) }),
      ];
      if (!actionAuthorityValid) {
        actions.push(actionAuthorityUnavailable("Pattern", async (event) => {
          event.currentTarget.disabled = true;
          await load();
        }));
      } else {
        if (pattern.can_clone === true) actions.push(el("button", { class: "btn small", type: "button", text: "Clone as draft", "aria-label": `Clone ${pattern.lure_category} pattern as a new draft`, onclick: async (event) => {
          const button = event.currentTarget;
          const values = await promptDialog({
            title: "Clone campaign pattern as a new draft",
            description: "The copy will contain reusable educational attributes only. Approval and source evidence are reset.",
            fields: [{ name: "reason", label: "Audit reason", type: "textarea", required: true, maxLength: 500,
              help: "Required for the audit trail. Do not include recipient data or secrets." }],
            submitLabel: "Clone as draft",
          });
          if (!values) return;
          button.disabled = true;
          try {
            await api(`/patterns/${pattern.campaign_pattern_id}/clone`, { method: "POST", body: JSON.stringify({ reason: values.reason }) });
            toast("New DRAFT created. Independent human approval is required before use.", "success");
            await load();
          } catch (err) {
            if (!await refreshAfterStaleActionFailure(err, load)) toast(err.message, "error");
          }
          finally { if (button.isConnected) button.disabled = false; }
        } }));
        if (pattern.can_approve === true) actions.push(el("button", { class: "btn small primary", type: "button", text: "Approve", onclick: async (event) => {
          const button = event.currentTarget; button.disabled = true;
          try {
            const approval = await api(`/patterns/${pattern.campaign_pattern_id}/approve`, { method: "POST" });
            if (approval?.generation_request_recorded !== true || Object.hasOwn(approval, "generation_queued")) {
              throw new Error("The server did not confirm a durable template-generation request");
            }
            toast("Pattern approved; template generation requested", "success");
            await load();
          }
          catch (err) {
            if (!await refreshAfterStaleActionFailure(err, load)) toast(err.message, "error");
          }
          finally { if (button.isConnected) button.disabled = false; }
        } }));
      }
      return el("tr", {}, [
        el("td", { text: pattern.lure_category }),
        el("td", { text: pattern.difficulty_score == null ? "Not specified" : String(pattern.difficulty_score) }),
        el("td", {}, [el("span", { class: `pill ${pattern.reusable ? "ok" : "down"}`, text: reviewLabel })]),
        el("td", {}, [el("div", { class: "btn-row" }, actions)]),
      ]);
    });
    results.replaceChildren(el("table", {}, [
      el("thead", {}, [el("tr", {}, ["Lure category", "Difficulty", "Review state", "Actions"].map((label) => el("th", { text: label })))]),
      el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", { class: "empty", colspan: 4, text: "No patterns match these filters." })])]),
    ]));
  };
  const searchButton = el("button", { class: "btn", type: "button", text: "Search library", onclick: load });
  search.addEventListener("keydown", (event) => { if (event.key === "Enter") load(); });
  root.appendChild(el("div", { class: "card" }, [
    el("div", { class: "card-head" }, [el("h3", { text: "Reusable campaign patterns" })]),
    el("div", { class: "btn-row", role: "search" }, [search, stateFilter, categoryFilter, difficultyFilter, searchButton]),
    results,
  ]));
  await load();
};

/* ---------- failed jobs / dead-letter queue ---------- */
views.queues = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.MANAGE_QUEUE)) return;
  root.replaceChildren();
  root.appendChild(el("h2", { text: "Failed jobs" }));
  root.appendChild(el("p", { class: "sub", text: "Inspect quarantined worker jobs and replay one after resolving its underlying cause. List views contain metadata only; personal and secret payload values remain redacted." }));

  const toolbar = el("div", { class: "btn-row" });
  const topic = el("select", { "aria-label": "Queue topic" }, [
    el("option", { value: "", text: "All worker topics" }),
    ...["ingest", "generate", "deliver", "retention", "mailbox", "remind", "alert", "directory"]
      .map((name) => el("option", { value: name, text: name })),
  ]);
  toolbar.appendChild(topic);
  toolbar.appendChild(el("button", { class: "btn", type: "button", text: "Refresh", onclick: () => load() }));
  root.appendChild(toolbar);
  const content = el("div", { class: "card", "aria-live": "polite" });
  root.appendChild(content);

  const inspect = async (item) => {
    let detail;
    try { detail = await api(`/queues/dead-letters/${encodeURIComponent(item.topic)}/${encodeURIComponent(item.reference)}`); }
    catch (err) { toast(err.message, "error"); return; }
    const { dlg, form } = dialogShell("Failed job details", "Payload values are redacted by the server. Resolve the cause before replaying the job.");
    const facts = el("dl", { class: "modal-detail" });
    for (const [label, value] of [
      ["Topic", detail.topic], ["Reference", detail.reference], ["Retries", detail.retry ?? "unknown"],
      ["Dead-lettered", detail.dead_lettered_at ? new Date(detail.dead_lettered_at * 1000).toLocaleString() : "unknown"],
      ["Prior replays", detail.replay_count || 0], ["Replayable", detail.replayable ? "yes" : "no"],
    ]) {
      facts.appendChild(el("dt", { text: label })); facts.appendChild(el("dd", { text: String(value) }));
    }
    form.appendChild(facts);
    form.appendChild(el("h4", { class: "modal-section", text: "Redacted payload" }));
    form.appendChild(el("pre", { class: "mono", text: JSON.stringify(detail.payload, null, 2) }));
    form.appendChild(el("div", { class: "modal-actions" }, [el("button", { class: "btn primary", type: "button", text: "Close", onclick: () => dlg.close() })]));
    openDialog(dlg);
  };

  const replay = async (item, button) => {
    const ok = await confirmDialog({
      title: "Replay this failed job?",
      message: "Only replay after correcting the failure. The worker's idempotency key is retained to prevent duplicate effects.",
      detail: { Topic: item.topic, Reference: item.reference, Retries: item.retry ?? "unknown" },
      confirmLabel: "Replay job",
      danger: true,
    });
    if (!ok) return;
    button.disabled = true;
    try {
      await api(`/queues/dead-letters/${encodeURIComponent(item.topic)}/${encodeURIComponent(item.reference)}/replay`, {
        method: "POST", body: JSON.stringify({ confirm: true }),
      });
      toast("Job returned to its worker queue", "success");
      await load();
    } catch (err) { toast(err.message, "error"); button.disabled = false; }
  };

  const load = async () => {
    content.replaceChildren(el("p", { class: "empty", text: "Loading failed jobs…" }));
    const query = topic.value ? `?topic=${encodeURIComponent(topic.value)}&limit=500` : "?limit=500";
    let result;
    try { result = await api(`/queues/dead-letters${query}`); }
    catch (err) { content.replaceChildren(el("p", { class: "down", text: `Failed to load: ${err.message}` })); return; }
    const rows = result.items.map((item) => {
      const replayButton = el("button", { class: "btn small danger", type: "button", text: "Replay", disabled: item.replayable ? null : "disabled" });
      replayButton.addEventListener("click", () => replay(item, replayButton));
      return el("tr", {}, [
        el("td", { text: item.topic }),
        el("td", { class: "mono", text: item.reference }),
        el("td", { class: "num", text: item.retry === null ? "—" : String(item.retry) }),
        el("td", { text: item.dead_lettered_at ? new Date(item.dead_lettered_at * 1000).toLocaleString() : "Unknown" }),
        el("td", { class: "num", text: item.malformed ? "Malformed envelope" : String(item.payload_field_count || 0) }),
        el("td", {}, [
          el("button", { class: "btn small", type: "button", text: "Inspect", onclick: () => inspect(item) }),
          replayButton,
        ]),
      ]);
    });
    const table = el("table", {}, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "Topic" }), el("th", { text: "Job reference" }), el("th", { text: "Retries" }),
        el("th", { text: "Failed" }), el("th", { text: "Payload field count" }), el("th", { text: "Actions" }),
      ])]),
      el("tbody", {}, rows.length ? rows : [el("tr", {}, [el("td", { class: "empty", colspan: 6, text: "No failed jobs. Worker queues are clear." })])]),
    ]);
    const summary = el("p", { class: "modal-help", text: `${result.total} failed job${result.total === 1 ? "" : "s"} across selected topics.${result.total > result.items.length ? ` Showing the first ${result.items.length}. Choose a topic to narrow the list.` : ""}` });
    content.replaceChildren(summary, table);
  };
  topic.addEventListener("change", load);
  await load();
};

/* ---------- audit ---------- */
views.audit = async (root) => {
  if (!requireAnyCapability(root, CAPABILITY.VIEW_AUDIT)) return;
  const canUseKillSwitch = hasCapability(CAPABILITY.USE_KILL_SWITCH);
  root.appendChild(el("h2", { text: "Audit" }));
  root.appendChild(el("p", { class: "sub", text: "Hash-chained append-only event log." }));
  let events, kill;
  try {
    [events, kill] = await Promise.all([
      api("/audit"),
      canUseKillSwitch ? api("/kill-switch") : Promise.resolve(null),
    ]);
  }
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
    canUseKillSwitch ? el("button", { class: `btn ${engaged ? "primary" : "danger"}`, text: engaged ? "Reset global stop" : "Engage global stop",
      onclick: async (e) => {
      const values = await promptDialog({
        title: engaged ? "Why is the global stop safe to reset?" : "Why is the global stop required?",
        description: engaged
          ? "Resetting reopens future scheduling and delivery. Cancelled assignments and revoked links stay cancelled."
          : "The reason is retained with the persistent safety-state audit trail.",
        fields: [{ name: "reason", label: "Operator reason", type: "textarea", required: true }],
        submitLabel: "Continue",
      });
      if (!values) return;
      const ok = await confirmDialog({
        title: engaged ? "Reset the GLOBAL emergency stop?" : "Engage the GLOBAL emergency stop?",
        message: engaged
          ? "Future campaigns may schedule and deliver again. Previously cancelled work is not restored."
          : "This persistently blocks scheduling and delivery across every replica and restart, cancels queued delivery, and revokes active tracking links.",
        detail: { Reason: values.reason },
        confirmLabel: engaged ? "Reset global stop" : "Engage global stop", danger: true,
      });
      if (!ok) return;
      e.target.disabled = true;
      try {
        const path = engaged ? "/kill-switch/reset" : "/kill-switch";
        const res = await api(path, { method: "POST", body: JSON.stringify({ confirm: true, reason: values.reason }) });
        toast(engaged
          ? "Global emergency stop reset; future delivery is enabled"
          : `Global stop engaged: ${res.cancelled} cancelled, ${res.tokens_revoked} tokens revoked`, "success");
        location.reload();
      } catch (err) { toast(err.message, "error"); }
      finally { e.target.disabled = false; }
    } }) : null,
  ].filter(Boolean)));
  if (!canUseKillSwitch) {
    root.appendChild(el("p", { class: "field-help", text: "Emergency-stop state and controls require the kill-switch capability." }));
  } else if (engaged) {
    root.appendChild(el("p", { class: "down", text: `Global emergency stop engaged by ${kill.engaged_by || "?"}${kill.engaged_at ? ` at ${String(kill.engaged_at).slice(0, 19)}` : ""} (generation ${kill.generation ?? "?"}). Reason: ${kill.engage_reason || "not recorded"}. Last run cancelled ${kill.last_cancelled ?? 0}, revoked ${kill.last_tokens_revoked ?? 0}.` }));
  } else {
    root.appendChild(el("p", { class: "ok", text: `Global emergency stop is disengaged (generation ${kill?.generation ?? 0}).${kill?.disengaged_by ? ` Last reset by ${kill.disengaged_by}${kill.disengaged_at ? ` at ${String(kill.disengaged_at).slice(0, 19)}` : ""}: ${kill.disengage_reason || "reason not recorded"}.` : ""}` }));
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
  if (!requireAnyCapability(root, CAPABILITY.MANAGE_ROLES)) return;
  root.appendChild(el("h2", { text: "Settings" }));

  let cfg;
  try { cfg = await api("/console/config"); } catch (e) {
    root.appendChild(el("div", { class: "card", text: `Failed to load: ${e.message}` })); return;
  }
  let status = null;
  try { status = await api("/console/status"); } catch { /* Keep configuration mutability separate from lifecycle controls. */ }
  const capabilities = status ? runtimeCapabilities(status, cfg) : {
    managed: cfg.mutable === false,
    configMutation: cfg.mutable !== false,
    processRestart: false,
  };
  const configMutable = cfg.mutable !== false && capabilities.configMutation;

  root.appendChild(el("p", {
    class: "sub",
    text: configMutable
      ? "GUI configuration for the local stack. Secrets are masked."
      : "Runtime configuration is managed externally by Azure and is read-only in this console.",
  }));
  if (!configMutable) {
    root.appendChild(el("div", { class: "notice", role: "status" }, [
      el("strong", { text: "Azure-managed configuration" }),
      el("p", { text: status?.status_message || "This console cannot change configuration or control processes for the managed runtime." }),
      el("p", { text: "Use the Azure deployment workflow to review and apply changes." }),
    ]));
  }
  if (!status) {
    root.appendChild(el("div", { class: "notice", role: "alert" }, [
      el("strong", { text: "Runtime status unavailable" }),
      el("p", { text: "Restart controls are hidden until the server confirms which runtime owns that action." }),
    ]));
  }

  const inputs = {};
  const container = el("div", { class: "form-grid" });
  for (const [key, value] of Object.entries(cfg.values)) {
    const inputId = `cfg-${key}`;
    const wrap = el("div", {}, [el("label", { for: inputId, text: key })]);
    const input = el("input", { id: inputId, value, disabled: configMutable ? null : "" });
    if (cfg.masked[key]) {
      input.type = "password";
      input.placeholder = "leave blank to keep current";
    }
    inputs[key] = input;
    wrap.appendChild(input);
    container.appendChild(wrap);
  }
  if (configMutable) guardUnsavedForm(container, "Configuration changes");
  const controls = [];
  if (configMutable) {
    controls.push(el("button", { class: "btn primary", type: "button", text: "Save changes", onclick: async (e) => {
      const btn = e.target; btn.disabled = true;
      const values = {};
      for (const [key, input] of Object.entries(inputs)) {
        if (cfg.masked[key] && !input.value) continue; // blank secret = keep current
        values[key] = input.value;
      }
      try {
        const res = await api("/console/config", { method: "PUT", body: JSON.stringify({ values }) });
        markFormSaved(container);
        toast(`Saved. Changed: ${res.changed.length ? res.changed.join(", ") : "none"}`, "success");
      } catch (err) { toast(err.message, "error"); }
      finally { btn.disabled = false; }
    } }));
  }
  controls.push(el("button", {
    class: "btn",
    type: "button",
    text: configMutable ? "Reload from disk" : "Refresh managed status",
    onclick: () => { location.reload(); },
  }));
  if (capabilities.processRestart) {
    controls.push(el("button", { class: "btn", type: "button", text: "Restart services", onclick: async (e) => {
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
    } }));
  }
  root.appendChild(el("div", { class: "card" }, [
    el("h3", { text: configMutable ? "Configuration (.env)" : "Managed configuration" }),
    container,
    el("p", {
      class: "field-help",
      text: "Full-stack shutdown is intentionally not offered here because it would also remove the browser control needed to recover. Use the audited global emergency stop in Audit to halt scheduling and delivery without stranding the console.",
    }),
    el("div", { class: "btn-row" }, controls),
  ].filter(Boolean)));

  if (status) {
    root.appendChild(el("div", { class: "card" }, [
      el("h3", { text: "Service status" }),
      statusPills(status),
      el("p", {
        text: capabilities.managed
          ? status.status_message
          : "Note: configuration changes apply after services are restarted by the launcher supervisor.",
      }),
    ]));
  }
};

/* ---------- boot ---------- */
let oidcSessionChecked = false;
async function render() {
  if ((token() || sessionInfo()) && !hasValidSessionAuthority()) {
    // Sessions created before capability-aware responses cannot safely drive
    // controls. OIDC can refresh from its HttpOnly cookie; dev users sign in
    // again instead of receiving an optimistic administrator UI.
    clearToken();
    oidcSessionChecked = false;
  }
  if (!token() && !oidcSessionChecked) {
    oidcSessionChecked = true;
    try {
      const resp = await fetch(`${API}/console/session`, { credentials: "same-origin", cache: "no-store" });
      if (resp.ok) {
        const data = await resp.json();
        setSessionInfo({
          authMode: data.auth_mode,
          principalId: data.principal_id,
          approvalLimited: false,
          approvalPolicy: data.approval_policy || "single-admin",
          roles: data.roles,
          capabilities: data.capabilities,
        });
        onboardingChecked = false;
      }
    } catch { /* Render login below. */ }
  }
  if (!token() && !sessionInfo()) { views.login(document.getElementById("app")); return; }
  if (!onboardingChecked) {
    onboardingChecked = true;
    if (hasCapability(CAPABILITY.MANAGE_ROLES)) {
      try {
        const onboarding = await api("/console/onboarding");
        if (!onboarding.complete) location.hash = "onboarding";
      } catch (e) { toast(`Unable to check setup status: ${e.message}`, "error"); }
    }
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
const LIVE_VIEWS = new Set(["dashboard", "campaigns", "queues"]);
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
    if (currentUnsavedForm()) {
      const status = document.getElementById("last-updated");
      if (status) status.textContent = "Unsaved changes — automatic refresh paused";
      return;
    }
    if (!token() && !sessionInfo()) return;
    render();
  }, REFRESH_MS);
}

window.addEventListener("hashchange", render);
window.addEventListener("beforeunload", (event) => {
  if (!currentUnsavedForm()) return;
  event.preventDefault();
  event.returnValue = "";
});
document.addEventListener("visibilitychange", () => { if (!document.hidden && LIVE_VIEWS.has(currentView())) render(); });
scheduleRefresh();
render();

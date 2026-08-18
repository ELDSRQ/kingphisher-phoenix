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
      onboardingChecked = false;
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
  ["onboarding", "Setup wizard"],
  ["azure-deployment", "Azure deployment"],
  ["help", "Help"],
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
        feedback.textContent = result.message || (result.ok ? "Connected successfully. You can save and continue." : "We couldn’t connect. Check the address and credentials, then try again.");
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
  root.appendChild(el("h2", { text: "Campaigns" }));
  root.appendChild(el("p", { class: "sub", text: "Create, schedule and manage campaigns from one administrator account." }));

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
        if (c.state === "draft") actions.push(el("button", { class: "btn small primary", text: "Schedule", onclick: scheduleAct(c) }));
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
          const channel = prompt("Alert channel: webhook or ntfy", "webhook");
          if (!channel) return;
          const destination = prompt(channel.trim().toLowerCase() === "ntfy" ? "ntfy HTTPS topic URL (for example, https://ntfy.sh/my-private-topic):" : "HTTPS webhook destination URL:");
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

window.addEventListener("hashchange", render);
render();

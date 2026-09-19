// DEP-010 client-side Azure discovery.
//
// Reads the operator's own Azure control-plane, IN THE BROWSER, to pre-fill the
// deployment wizard (subscription / tenant / region / DNS zone / resource
// group). The server never sees the token and never calls ARM — the whole flow
// is browser -> login.microsoftonline.com (auth) -> management.azure.com (reads).
//
// Auth is OAuth2 authorization-code + PKCE (S256) in a popup — NO dependency and
// NO client secret. The token is delegated (the signed-in operator's own
// permissions) and lives only in this module's closure for the duration of one
// discovery run; it is never persisted, never sent to our server.
//
// CSP contract: this needs `connect-src` to include
// https://login.microsoftonline.com and https://management.azure.com. The
// authorize step is a popup navigation (not an iframe), so no `frame-src` is
// required. Keep it that way.
//
// Fail-closed: every entry point throws on any error; the caller falls back to
// manual entry. Discovery is a convenience, never a requirement.

const AUTHORITY = "https://login.microsoftonline.com";
const ARM = "https://management.azure.com";
// Delegated ARM access as the signed-in user; offline_access is intentionally
// omitted — discovery is a single short-lived read, we never store a refresh
// token.
const SCOPE = "https://management.azure.com/user_impersonation openid profile";
const ARM_API = "2021-04-01"; // resource groups / subscriptions
const DNS_API = "2018-05-01"; // Microsoft.Network dnszones
const ACS_API = "2023-04-01"; // Microsoft.Communication communicationServices
const GRAPH = "https://graph.microsoft.com";
// Entra app-list discovery (A2b) uses delegated Application.Read.All, which an
// admin must consent to for this console's app registration. It is requested
// only by the Entra discovery step, never for the plain ARM reads.
const GRAPH_SCOPE = "https://graph.microsoft.com/Application.Read.All openid profile";

function _base64url(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i += 1) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function _randomString(byteLength) {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return _base64url(buf.buffer);
}

async function _s256(verifier) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return _base64url(digest);
}

function _authorizeUrl({ clientId, tenant, redirectUri, state, codeChallenge, scope }) {
  const q = new URLSearchParams({
    client_id: clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    response_mode: "query",
    scope,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
    prompt: "select_account",
  });
  return `${AUTHORITY}/${encodeURIComponent(tenant || "organizations")}/oauth2/v2.0/authorize?${q.toString()}`;
}

// Open the authorize URL in a popup and resolve with the returned code once the
// same-origin redirect page (azure-redirect.html) posts it back. Rejects on
// error, state mismatch, timeout, or a closed popup.
function _popupForCode({ url, state, redirectOrigin }) {
  return new Promise((resolve, reject) => {
    const popup = window.open(url, "kp-azure-discovery", "width=520,height=640,menubar=no,toolbar=no");
    if (!popup) {
      reject(new Error("Popup blocked. Allow popups for this console, then retry discovery."));
      return;
    }
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("message", onMessage);
      clearInterval(closedTimer);
      clearTimeout(timeout);
      try {
        popup.close();
      } catch (_e) {
        /* ignore */
      }
      fn(arg);
    };
    const onMessage = (event) => {
      if (event.origin !== redirectOrigin) return;
      const data = event.data || {};
      if (data.kind !== "kp-azure-discovery") return;
      if (data.error) {
        finish(reject, new Error(String(data.error)));
      } else if (data.state !== state) {
        finish(reject, new Error("Discovery state mismatch — aborting for safety."));
      } else if (data.code) {
        finish(resolve, String(data.code));
      }
    };
    window.addEventListener("message", onMessage);
    const closedTimer = setInterval(() => {
      if (popup.closed) finish(reject, new Error("Sign-in window closed before completing discovery."));
    }, 500);
    const timeout = setTimeout(() => finish(reject, new Error("Discovery sign-in timed out.")), 300000);
  });
}

async function _exchangeCode({ clientId, tenant, redirectUri, code, verifier, scope }) {
  const body = new URLSearchParams({
    client_id: clientId,
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    scope,
  });
  const resp = await fetch(`${AUTHORITY}/${encodeURIComponent(tenant || "organizations")}/oauth2/v2.0/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || `Token exchange failed (${resp.status}).`);
  }
  return data.access_token;
}

async function _armGet(token, path) {
  const resp = await fetch(`${ARM}${path}`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => "");
    throw new Error(`Azure read failed (${resp.status}) for ${path}. ${detail.slice(0, 200)}`);
  }
  const data = await resp.json().catch(() => ({}));
  return Array.isArray(data.value) ? data.value : [];
}

// Acquire a delegated access token via PKCE popup for a given resource scope.
// `scope` selects the resource: ARM reads use SCOPE, Entra app-list uses
// GRAPH_SCOPE. `tenant` may be "organizations" when the operator does not yet
// know it.
async function _acquireToken({ clientId, tenant, redirectUri, scope }) {
  if (!clientId) throw new Error("Azure discovery is not configured (no Entra client ID).");
  const verifier = _randomString(48);
  const state = _randomString(24);
  const codeChallenge = await _s256(verifier);
  const url = _authorizeUrl({ clientId, tenant, redirectUri, state, codeChallenge, scope });
  const code = await _popupForCode({ url, state, redirectOrigin: new URL(redirectUri).origin });
  return _exchangeCode({ clientId, tenant, redirectUri, code, verifier, scope });
}

export async function acquireArmToken({ clientId, tenant, redirectUri }) {
  return _acquireToken({ clientId, tenant, redirectUri, scope: SCOPE });
}

async function acquireGraphToken({ clientId, tenant, redirectUri }) {
  return _acquireToken({ clientId, tenant, redirectUri, scope: GRAPH_SCOPE });
}

// Read-only ARM enumeration. Each is a thin GET; callers handle failures.
export async function listSubscriptions(token) {
  const subs = await _armGet(token, `/subscriptions?api-version=${ARM_API}`);
  return subs
    .filter((s) => (s.state || "").toLowerCase() === "enabled" || !s.state)
    .map((s) => ({ id: s.subscriptionId, name: s.displayName, tenantId: s.tenantId }));
}

export async function listLocations(token, subscriptionId) {
  const locs = await _armGet(token, `/subscriptions/${subscriptionId}/locations?api-version=${ARM_API}`);
  return locs.map((l) => ({ name: l.name, display: l.displayName }));
}

export async function listResourceGroups(token, subscriptionId) {
  const groups = await _armGet(token, `/subscriptions/${subscriptionId}/resourcegroups?api-version=${ARM_API}`);
  return groups.map((g) => ({ name: g.name, location: g.location }));
}

export async function listDnsZones(token, subscriptionId) {
  const zones = await _armGet(
    token,
    `/subscriptions/${subscriptionId}/providers/Microsoft.Network/dnszones?api-version=${DNS_API}`,
  );
  return zones.map((z) => ({ id: z.id, name: z.name }));
}

export async function listCommunicationServices(token, subscriptionId) {
  const svcs = await _armGet(
    token,
    `/subscriptions/${subscriptionId}/providers/Microsoft.Communication/communicationServices?api-version=${ACS_API}`,
  );
  return svcs.map((c) => ({ id: c.id, name: c.name }));
}

// Entra app registrations by friendly name (A2b). Requires the console's app
// registration to hold delegated Application.Read.All (admin consent) — the
// token is requested only when the operator runs this step, never for ARM reads.
export async function listEntraApplications({ clientId, tenant, redirectUri }) {
  const token = await acquireGraphToken({ clientId, tenant, redirectUri });
  const resp = await fetch(`${GRAPH}/v1.0/applications?$select=id,appId,displayName`, {
    headers: { Authorization: `Bearer ${token}`, Accept: "application/json" },
  });
  if (!resp.ok) {
    const detail = await resp.text().catch(() => "");
    throw new Error(`Entra app list failed (${resp.status}). ${detail.slice(0, 200)}`);
  }
  const data = await resp.json().catch(() => ({}));
  const apps = Array.isArray(data.value) ? data.value : [];
  return apps
    .filter((a) => a.appId && a.displayName)
    .map((a) => ({ objectId: a.id, appId: a.appId, name: a.displayName }));
}

// Orchestrate a full discovery pass for one subscription. `subscriptionId`
// optional — when omitted, the first enabled subscription is used and returned
// so the caller can let the operator switch. Returns normalized, secret-free
// data suitable for pre-filling the wizard; the token never leaves this call.
export async function discoverAzure({ clientId, tenant, redirectUri, subscriptionId } = {}) {
  const token = await acquireArmToken({ clientId, tenant, redirectUri });
  const subscriptions = await listSubscriptions(token);
  if (!subscriptions.length) {
    return { subscriptions: [], selected: null, locations: [], resourceGroups: [], dnsZones: [], communicationServices: [] };
  }
  const selected = subscriptions.find((s) => s.id === subscriptionId) || subscriptions[0];
  const [locations, resourceGroups, dnsZones, communicationServices] = await Promise.all([
    listLocations(token, selected.id).catch(() => []),
    listResourceGroups(token, selected.id).catch(() => []),
    listDnsZones(token, selected.id).catch(() => []),
    listCommunicationServices(token, selected.id).catch(() => []),
  ]);
  return { subscriptions, selected, locations, resourceGroups, dnsZones, communicationServices };
}

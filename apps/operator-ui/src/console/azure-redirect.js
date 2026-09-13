// DEP-010 PKCE redirect capture. The discovery popup lands here after Azure
// sign-in; we hand the authorization code (or error) back to the opener console
// via postMessage, targeted at THIS SAME origin, then close. No token exchange
// happens here — only the one-time code crosses back, and only to the opener on
// the exact console origin. CSP: served under /console, script-src 'self', so
// this is an external file with no inline script.
(function () {
  "use strict";
  var params = new URLSearchParams(window.location.search);
  var message = { kind: "kp-azure-discovery" };
  var error = params.get("error");
  if (error) {
    message.error = params.get("error_description") || error;
  } else {
    message.code = params.get("code");
    message.state = params.get("state");
  }
  var status = document.getElementById("status");
  if (status) {
    status.textContent = message.error
      ? "Azure sign-in failed. You can close this window."
      : "Signed in. Returning to the console…";
  }
  try {
    if (window.opener) {
      // Opener is the console on this same origin; target it exactly, never "*".
      window.opener.postMessage(message, window.location.origin);
    }
  } catch (_e) {
    /* the opener may be gone; the console times out and falls back to manual entry */
  }
  setTimeout(function () {
    try {
      window.close();
    } catch (_e) {
      /* ignore */
    }
  }, 400);
})();

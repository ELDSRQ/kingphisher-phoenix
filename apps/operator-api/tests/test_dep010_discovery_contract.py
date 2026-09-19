"""DEP-010 client-side Azure discovery — source & CSP security contract.

Discovery signs the operator into Azure in a PKCE popup and reads their ARM
control-plane IN THE BROWSER to pre-fill the deployment wizard. The invariants
this guards:

- the delegated Azure token never touches our server and is never persisted;
- auth uses PKCE S256 with CSRF-state validation;
- the browser only reaches the two Azure control-plane origins;
- the redirect page hands the one-time code back only to the exact console
  origin (never a wildcard postMessage target);
- the CSP relaxation is exactly connect-src to those two origins — no frame-src
  (the flow is a popup, not an iframe) and the rest of the policy stays locked;
- discovery is fail-closed: any failure leaves manual entry untouched.

Source-text checks (this repo has no browser-JS unit runner; the console is
guarded by node --check + the drift gate + source contracts like this one).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from kp_operator_api.main import _CONSOLE_CSP

pytestmark = pytest.mark.console_ui

_REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_CONSOLE_DIR = _REPOSITORY_ROOT / "apps" / "operator-ui" / "src" / "console"
_CONSOLE_SRC_DIR = _REPOSITORY_ROOT / "apps" / "operator-ui" / "src" / "console-js"

DISCOVERY_JS = (_CONSOLE_SRC_DIR / "azure-discovery.js").read_text(encoding="utf-8")
APP_SRC_JS = (_CONSOLE_SRC_DIR / "app.js").read_text(encoding="utf-8")
REDIRECT_JS = (_CONSOLE_DIR / "azure-redirect.js").read_text(encoding="utf-8")
REDIRECT_HTML = (_CONSOLE_DIR / "azure-redirect.html").read_text(encoding="utf-8")


def test_discovery_uses_pkce_s256_with_state_validation() -> None:
    assert "code_challenge_method" in DISCOVERY_JS
    assert '"S256"' in DISCOVERY_JS
    assert 'crypto.subtle.digest("SHA-256"' in DISCOVERY_JS
    # The returned state must be checked against the one we sent.
    assert "state mismatch" in DISCOVERY_JS.lower()


def test_discovery_requests_only_delegated_arm_read_scope() -> None:
    assert "https://management.azure.com/user_impersonation" in DISCOVERY_JS
    # Delegated user flow — never a client secret in the browser.
    assert "client_secret" not in DISCOVERY_JS


def test_discovery_requests_entra_app_list_scope() -> None:
    # A2b: Entra app-list discovery uses delegated Application.Read.All, requested
    # only by the Entra step — never bundled into the ARM scope, no client secret.
    assert "https://graph.microsoft.com/Application.Read.All" in DISCOVERY_JS
    assert "client_secret" not in DISCOVERY_JS


def test_discovery_never_persists_the_azure_token() -> None:
    # The delegated token lives only in the module closure for one run.
    assert "localStorage" not in DISCOVERY_JS
    assert "sessionStorage" not in DISCOVERY_JS
    # ...and is never posted back to our own server/API.
    assert "/console/" not in DISCOVERY_JS
    assert "/api/v1" not in DISCOVERY_JS


def test_discovery_is_a_popup_not_an_iframe() -> None:
    assert "window.open(" in DISCOVERY_JS
    # No hidden-iframe token flow (MSAL silent-renew style); popup only.
    assert 'createElement("iframe")' not in DISCOVERY_JS
    assert "createElement('iframe')" not in DISCOVERY_JS


def test_discovery_only_reaches_the_three_azure_origins() -> None:
    assert "https://login.microsoftonline.com" in DISCOVERY_JS
    assert "https://management.azure.com" in DISCOVERY_JS
    assert "https://graph.microsoft.com" in DISCOVERY_JS


def test_redirect_page_returns_code_only_to_the_exact_console_origin() -> None:
    assert "postMessage(message, window.location.origin)" in REDIRECT_JS
    # Never a wildcard target origin for the one-time code.
    assert 'postMessage(message, "*")' not in REDIRECT_JS
    assert "kp-azure-discovery" in REDIRECT_JS
    # External script only (CSP script-src 'self'); no inline handler in the page.
    assert "/console/azure-redirect.js" in REDIRECT_HTML
    assert "onclick=" not in REDIRECT_HTML.lower()


def test_wizard_exposes_failclosed_discovery_control() -> None:
    assert "Discover from Azure" in APP_SRC_JS
    assert "Discover Entra apps" in APP_SRC_JS
    assert 'from "./azure-discovery.js"' in APP_SRC_JS
    # Fail-closed: a discovery failure surfaces a message and keeps manual entry.
    assert "Discovery unavailable" in APP_SRC_JS


def test_csp_relaxation_is_exactly_the_three_azure_origins_no_frame_src() -> None:
    assert (
        "connect-src 'self' https://login.microsoftonline.com https://management.azure.com https://graph.microsoft.com"
        in _CONSOLE_CSP
    )
    # The rest of the hardened policy is unchanged.
    assert "default-src 'none'" in _CONSOLE_CSP
    assert "script-src 'self'" in _CONSOLE_CSP
    assert "style-src 'self'" in _CONSOLE_CSP
    # Popup, not iframe: no frame-src is introduced.
    assert "frame-src" not in _CONSOLE_CSP
    assert "'unsafe-inline'" not in _CONSOLE_CSP
    assert "'unsafe-eval'" not in _CONSOLE_CSP

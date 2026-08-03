"""Safe Jinja2 message templating.

Ports the message-template-variable concept from the original King Phisher
(client/templates.py, client/mailer.py) into Phoenix's safe model.

Whitelist-only variables, rendered inside a SandboxedEnvironment with no
unsafe filters/globals. Every variable is scoped under a known namespace
(`recipient`, `campaign`, `tracking`, `sender`); unknown names and attribute
access outside the whitelist raise immediately (fail closed). Tracking token
hashes are injected per recipient so pixel opens and click redirects are
correlated without ever embedding the raw token in the message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from jinja2 import Environment, StrictUndefined, nodes
from jinja2.sandbox import SandboxedEnvironment

_ALLOWED_GLOBALS: set[str] = set()

_BASE_FILTERS = {"lower", "upper", "title", "trim", "strip"}

_RECIPIENT_FIELDS = frozenset({"first_name", "last_name", "department", "email"})
_CAMPAIGN_FIELDS = frozenset({"title", "sender_display", "training_domain"})
_TRACKING_FIELDS = frozenset({"open_url", "click_url", "training_url"})
_SENDER_FIELDS = frozenset({"email"})


@dataclass
class RecipientContext:
    first_name: str = ""
    last_name: str = ""
    department: str = ""
    email: str = ""


@dataclass
class CampaignContext:
    title: str = ""
    sender_display: str = ""
    training_domain: str = ""


@dataclass
class TrackingContext:
    open_url: str = ""
    click_url: str = ""
    training_url: str = ""


class TemplateVariableError(ValueError):
    """Raised when a template references an unauthorized variable."""


class _ScopedProxy:
    """Attribute-scoped proxy that only permits whitelisted field names."""

    __slots__ = ("_allowed", "_values")

    def __init__(self, allowed: frozenset[str], values: dict[str, Any]) -> None:
        self._allowed = allowed
        self._values = values

    def __getattr__(self, name: str) -> Any:
        if name in self._allowed and name in self._values:
            return self._values[name]
        raise TemplateVariableError(f"unauthorized template variable: {name}")


def _make_context(namespace: str, allowed: frozenset[str], values: dict[str, Any]) -> dict[str, Any]:
    return {namespace: _ScopedProxy(allowed, values)}


def make_environment() -> Environment:
    env = SandboxedEnvironment(
        autoescape=False,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    for name in sorted(_BASE_FILTERS):
        method = getattr(str, name) if name != "trim" else str.strip
        env.filters[name] = method
    return env


class MessageRenderer:
    """Renders a stored template against per-recipient context."""

    def __init__(self) -> None:
        self._env = make_environment()

    def _validate_names(self, source: str) -> None:
        ast = self._env.parse(source)
        allowed = {
            "recipient": _RECIPIENT_FIELDS,
            "campaign": _CAMPAIGN_FIELDS,
            "tracking": _TRACKING_FIELDS,
            "sender": _SENDER_FIELDS,
        }
        for node in ast.find_all(nodes.Getattr):
            chain: list[str] = []
            cursor: nodes.Expr = node
            while isinstance(cursor, nodes.Getattr):
                chain.append(cursor.attr)
                cursor = cursor.node
            if isinstance(cursor, nodes.Name):
                chain.append(cursor.name)
            chain.reverse()
            if len(chain) < 2:
                raise TemplateVariableError(f"unauthorized template variable: {'.'.join(chain)}")
            namespace, field = chain[0], chain[1]
            fields = allowed.get(namespace)
            if fields is None:
                raise TemplateVariableError(f"unknown template namespace: {'.'.join(chain)}")
            if field not in fields:
                raise TemplateVariableError(f"unauthorized template variable: {'.'.join(chain)}")

    def render(self, source: str, *, recipient: RecipientContext, campaign: CampaignContext,
               tracking: TrackingContext, sender_email: str) -> str:
        self._validate_names(source)
        context: dict[str, Any] = {}
        context.update(_make_context("recipient", _RECIPIENT_FIELDS, {
            "first_name": recipient.first_name,
            "last_name": recipient.last_name,
            "department": recipient.department,
            "email": recipient.email,
        }))
        context.update(_make_context("campaign", _CAMPAIGN_FIELDS, {
            "title": campaign.title,
            "sender_display": campaign.sender_display,
            "training_domain": campaign.training_domain,
        }))
        context.update(_make_context("tracking", _TRACKING_FIELDS, {
            "open_url": tracking.open_url,
            "click_url": tracking.click_url,
            "training_url": tracking.training_url,
        }))
        context.update(_make_context("sender", _SENDER_FIELDS, {"email": sender_email}))
        template = self._env.from_string(source)
        return template.render(**context)


def build_email_body(subject: str, plain_text: str, html: str | None, *, pixel_tag: str) -> tuple[str, str, str]:
    """Assemble subject + plain-text + HTML parts; `html` is already rendered,
    `pixel_tag` is the `<img>` tracking tag injected before </body>."""
    html = html or ""
    if html and "</body>" in html:
        html = html.replace("</body>", f"{pixel_tag}</body>", 1)
    elif html:
        html = f"{html}{pixel_tag}"
    return subject, plain_text, html

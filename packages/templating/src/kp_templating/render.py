"""Safe Jinja2 message templating.

Ports the message-template-variable concept from the original King Phisher
(client/templates.py, client/mailer.py) into Phoenix's safe model.

Whitelist-only variables, rendered inside a SandboxedEnvironment with no
unsafe filters/globals. Every variable is scoped under a known namespace
(`recipient`, `campaign`, `tracking`, `sender`); unknown names and attribute
access outside the whitelist raise immediately (fail closed). Raw tracking
bearer URLs are injected only into the recipient's message at render time;
database verifiers are never rendered.
"""

from __future__ import annotations

import math
import signal
import threading
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from jinja2 import Environment, StrictUndefined, nodes
from jinja2.sandbox import SandboxedEnvironment

# Whitelists actually enforced in make_environment(): everything not named here
# is stripped from the sandbox (no `range`, `cycler`, `dict`, `lipsum`,
# `namespace`, `joiner`, and no default Jinja filters such as `safe`, `attr`,
# `map`, `format`, `pprint`, ...).
_ALLOWED_GLOBALS: set[str] = set()

_BASE_FILTERS = {"lower", "upper", "title", "trim", "strip"}

# --- Resource limits (defence against template-author DoS) ------------------
# A malicious template author (or a compromised stored template) can request a
# huge allocation, e.g. ``{{ "x" * 10**9 }}`` (~1 GiB) or a giant big-int via
# ``{{ 10 ** 10000000 }}``. These caps make such expressions raise instead of
# allocating. They are deliberately far larger than any legitimate rendered
# message so normal templates are unaffected.
_MAX_OUTPUT_CHARS = 1_000_000  # total rendered message length (~1 MiB)
_MAX_SEQUENCE_LEN = 1_000_000  # cap on str/bytes/list produced by * and +
_MAX_POW_RESULT_BITS = 4096  # ceiling on the bit-length of an int produced by **
# Arithmetic operators routed through SandboxedEnvironment.call_binop. `~`
# (string concat / Concat node) is compiled separately by Jinja and never
# reaches call_binop, so it is bounded by the capped output join instead; it is
# listed for completeness and does no harm.
_INTERCEPTED_BINOPS = frozenset({"*", "**", "+", "-", "~"})


class TemplateRenderError(ValueError):
    """Raised when a template exceeds a rendering resource limit."""


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


def _is_int(value: Any) -> bool:
    # bool is a subclass of int but should not count as a numeric operand here.
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _sized_sequence(value: Any) -> bool:
    return isinstance(value, (str, bytes, bytearray, list, tuple))


def _check_binop(operator: str, left: Any, right: Any) -> None:
    """Reject arithmetic that would allocate an oversized result.

    Called BEFORE the operator runs, so the huge value is never materialised.
    """
    if operator == "*":
        # sequence repetition: len(seq) * count
        seq = count = None
        if _sized_sequence(left) and _is_int(right):
            seq, count = left, right
        elif _sized_sequence(right) and _is_int(left):
            seq, count = right, left
        if seq is not None and count > 0 and len(seq) * count > _MAX_SEQUENCE_LEN:
            raise TemplateRenderError(
                f"template multiplication would create a sequence of "
                f"{len(seq) * count} items (limit {_MAX_SEQUENCE_LEN})"
            )
    elif operator == "**":
        # int/float exponentiation: bound the bit-length of the result.
        if _is_number(left) and _is_number(right) and right > 0 and abs(left) > 1:
            approx_bits = right * math.log2(abs(left))
            if approx_bits > _MAX_POW_RESULT_BITS:
                raise TemplateRenderError(
                    f"template exponentiation would create a ~{int(approx_bits)}-bit "
                    f"number (limit {_MAX_POW_RESULT_BITS} bits)"
                )
    elif operator == "+":
        # sequence concatenation: len(left) + len(right)
        if _sized_sequence(left) and _sized_sequence(right) and len(left) + len(right) > _MAX_SEQUENCE_LEN:
            raise TemplateRenderError(
                f"template concatenation would create a sequence of "
                f"{len(left) + len(right)} items (limit {_MAX_SEQUENCE_LEN})"
            )
    # "-" (numeric subtraction) and "~" cannot cause an oversized allocation.


class _CappedSandbox(SandboxedEnvironment):
    """Sandbox whose arithmetic operators are size-checked before running."""

    intercepted_binops = _INTERCEPTED_BINOPS

    def call_binop(self, context: Any, operator: str, left: Any, right: Any) -> Any:
        _check_binop(operator, left, right)
        handler = self.binop_table.get(operator)
        if handler is None:  # e.g. "~" if it ever routed here; fall back to concat
            return str(left) + str(right)
        return handler(left, right)


def _capped_concat(parts: Iterable[str]) -> str:
    """Join the rendered stream, raising once total output exceeds the cap.

    Jinja pulls this over a lazy generator, so aborting here also stops any
    output-producing loop from running further (a step bound for preview).
    """
    collected: list[str] = []
    total = 0
    for part in parts:
        total += len(part)
        if total > _MAX_OUTPUT_CHARS:
            raise TemplateRenderError(f"rendered template exceeds the {_MAX_OUTPUT_CHARS}-character output limit")
        collected.append(part)
    return "".join(collected)


@contextmanager
def _time_limit(seconds: float | None):
    """Best-effort wall-clock guard for preview rendering.

    Uses SIGALRM, which is only available on the main thread on POSIX. In any
    other context (worker threads, Windows) it is a no-op — the binop and
    output caps remain the primary, always-on protections.
    """
    if (
        not seconds
        or seconds <= 0
        or not hasattr(signal, "SIGALRM")
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def _handler(signum: int, frame: Any) -> None:
        raise TemplateRenderError(f"template render exceeded {seconds:g}s time limit")

    previous = signal.signal(signal.SIGALRM, _handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def make_environment(*, autoescape: bool = False) -> Environment:
    env = _CappedSandbox(
        autoescape=autoescape,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    # Enforce the global whitelist: drop everything the sandbox installs by
    # default (range, cycler, dict, lipsum, namespace, joiner) and add back only
    # explicitly allowed names (currently none).
    env.globals.clear()
    for name in sorted(_ALLOWED_GLOBALS):
        env.globals[name] = _ALLOWED_GLOBAL_VALUES[name]
    # Enforce the filter whitelist: replace the full default filter set (safe,
    # attr, map, format, urlize, ...) with the small safe subset.
    env.filters.clear()
    for name in sorted(_BASE_FILTERS):
        method = getattr(str, name) if name != "trim" else str.strip
        env.filters[name] = method
    # Bound total output length (and, being lazily pulled, output-producing loops).
    env.concat = _capped_concat  # type: ignore[assignment]
    return env


# Values for any names listed in _ALLOWED_GLOBALS (empty today; kept so the
# whitelist can grow without touching make_environment).
_ALLOWED_GLOBAL_VALUES: dict[str, Any] = {}


class MessageRenderer:
    """Renders a stored template against per-recipient context."""

    def __init__(self) -> None:
        self._text_env = make_environment()
        self._html_env = make_environment(autoescape=True)

    def _validate_names(self, source: str) -> None:
        ast = self._text_env.parse(source)
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

    def render(
        self,
        source: str,
        *,
        recipient: RecipientContext,
        campaign: CampaignContext,
        tracking: TrackingContext,
        sender_email: str,
        html_context: bool = False,
        timeout_s: float | None = None,
    ) -> str:
        self._validate_names(source)
        context: dict[str, Any] = {}
        context.update(
            _make_context(
                "recipient",
                _RECIPIENT_FIELDS,
                {
                    "first_name": recipient.first_name,
                    "last_name": recipient.last_name,
                    "department": recipient.department,
                    "email": recipient.email,
                },
            )
        )
        context.update(
            _make_context(
                "campaign",
                _CAMPAIGN_FIELDS,
                {
                    "title": campaign.title,
                    "sender_display": campaign.sender_display,
                    "training_domain": campaign.training_domain,
                },
            )
        )
        context.update(
            _make_context(
                "tracking",
                _TRACKING_FIELDS,
                {
                    "open_url": tracking.open_url,
                    "click_url": tracking.click_url,
                    "training_url": tracking.training_url,
                },
            )
        )
        context.update(_make_context("sender", _SENDER_FIELDS, {"email": sender_email}))
        template = (self._html_env if html_context else self._text_env).from_string(source)
        with _time_limit(timeout_s):
            return template.render(**context)

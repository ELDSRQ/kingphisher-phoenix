import time

import pytest
from jinja2.exceptions import TemplateError, UndefinedError
from kp_templating.render import (
    CampaignContext,
    MessageRenderer,
    RecipientContext,
    TemplateRenderError,
    TemplateVariableError,
    TrackingContext,
)


def _render(renderer: MessageRenderer, source: str, **kwargs):
    return renderer.render(
        source,
        recipient=kwargs.get("recipient", RecipientContext(first_name="Ada")),
        campaign=kwargs.get("campaign", CampaignContext(title="Phish")),
        tracking=kwargs.get("tracking", TrackingContext()),
        sender_email=kwargs.get("sender_email", "ops@example.com"),
        html_context=kwargs.get("html_context", False),
    )


def test_render_whitelisted_variables() -> None:
    renderer = MessageRenderer()
    out = renderer.render(
        "Hi {{ recipient.first_name }}, {{ campaign.title }} open {{ tracking.open_url }} from {{ sender.email }}",
        recipient=RecipientContext(first_name="Ada"),
        campaign=CampaignContext(title="Phish"),
        tracking=TrackingContext(open_url="http://track/open/h"),
        sender_email="ops@example.com",
    )
    assert "Hi Ada, Phish" in out
    assert "http://track/open/h" in out
    assert "ops@example.com" in out


def test_training_placeholder_renders_only_the_supplied_recipient_bound_value() -> None:
    renderer = MessageRenderer()
    recipient_bound_url = "https://tracking.example/v1/track/click/recipient-bearer"
    out = renderer.render(
        "Complete training: {{ tracking.training_url }}",
        recipient=RecipientContext(),
        campaign=CampaignContext(),
        tracking=TrackingContext(training_url=recipient_bound_url),
        sender_email="ops@example.com",
    )

    assert out == f"Complete training: {recipient_bound_url}"


def test_render_rejects_unauthorized_variable() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateVariableError):
        renderer.render(
            "{{ recipient.ssn }}",
            recipient=RecipientContext(first_name="Ada"),
            campaign=CampaignContext(title="Phish"),
            tracking=TrackingContext(),
            sender_email="ops@example.com",
        )


def test_render_rejects_unknown_namespace() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateVariableError):
        renderer.render(
            "{{ secrets.token }}",
            recipient=RecipientContext(),
            campaign=CampaignContext(),
            tracking=TrackingContext(),
            sender_email="ops@example.com",
        )


def test_render_rejects_unknown_field() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateVariableError):
        renderer.render(
            "{{ recipient.missing }}",
            recipient=RecipientContext(),
            campaign=CampaignContext(),
            tracking=TrackingContext(),
            sender_email="ops@example.com",
        )


def test_html_render_escapes_untrusted_context_values() -> None:
    renderer = MessageRenderer()
    out = renderer.render(
        "<p>{{ recipient.first_name }} — {{ campaign.title }}</p>",
        recipient=RecipientContext(first_name='</p><img src="https://attacker.example/p">'),
        campaign=CampaignContext(title="<script>alert(1)</script>"),
        tracking=TrackingContext(),
        sender_email="ops@example.com",
        html_context=True,
    )
    assert "<img" not in out
    assert "<script>" not in out
    assert "&lt;img" in out


# --- Sandbox resource-limit enforcement (CNT-002) ---------------------------


def test_string_multiplication_bomb_is_rejected_without_allocating() -> None:
    """`{{ "x" * 10**9 }}` must be rejected fast, not allocate ~1 GiB."""
    renderer = MessageRenderer()
    start = time.perf_counter()
    with pytest.raises(TemplateRenderError):
        _render(renderer, '{{ "x" * 10**9 }}')
    # Rejection happens before the giant string is built, so it is effectively
    # instantaneous (allocating 1 GiB would take far longer than this bound).
    assert time.perf_counter() - start < 1.0


def test_list_multiplication_bomb_is_rejected() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateRenderError):
        _render(renderer, "{{ [0, 1] * 10**9 }}")


def test_exponentiation_bomb_is_rejected() -> None:
    """A huge big-int via ** must be refused before it is computed."""
    renderer = MessageRenderer()
    start = time.perf_counter()
    with pytest.raises(TemplateRenderError):
        _render(renderer, "{{ 10 ** 10000000 }}")
    assert time.perf_counter() - start < 1.0


def test_context_driven_multiplication_is_capped() -> None:
    renderer = MessageRenderer()
    with pytest.raises(TemplateRenderError):
        _render(
            renderer,
            "{{ recipient.first_name * 1000 }}",
            recipient=RecipientContext(first_name="y" * 5000),
        )


def test_disallowed_global_range_is_unavailable() -> None:
    renderer = MessageRenderer()
    with pytest.raises(UndefinedError):
        _render(renderer, "{{ range(3) }}")


def test_disallowed_global_cycler_is_unavailable() -> None:
    renderer = MessageRenderer()
    with pytest.raises(UndefinedError):
        _render(renderer, "{{ cycler('a', 'b') }}")


def test_disallowed_filter_safe_is_unavailable() -> None:
    """The `safe` filter (an XSS escape hatch) must not exist in the sandbox."""
    renderer = MessageRenderer()
    with pytest.raises(TemplateError):
        _render(renderer, "{{ campaign.title | safe }}", html_context=True)


def test_whitelisted_filters_still_work() -> None:
    renderer = MessageRenderer()
    out = _render(
        renderer,
        "{{ recipient.first_name | upper }}/{{ campaign.title | lower }}",
    )
    assert out == "ADA/phish"


def test_small_arithmetic_still_renders() -> None:
    """Legitimate small arithmetic must be unaffected by the caps."""
    renderer = MessageRenderer()
    out = _render(renderer, "{{ 3 * 4 }} {{ 2 ** 8 }} {{ 5 + 6 }}")
    assert out == "12 256 11"


def test_normal_template_and_training_placeholder_unchanged() -> None:
    """Regression guard: legitimate templates render exactly as before."""
    renderer = MessageRenderer()
    training_url = "https://tracking.example/v1/track/click/recipient-bearer"
    out = renderer.render(
        "Hi {{ recipient.first_name }}, complete training: {{ tracking.training_url }}",
        recipient=RecipientContext(first_name="Ada"),
        campaign=CampaignContext(title="Q3 Phish"),
        tracking=TrackingContext(training_url=training_url),
        sender_email="ops@example.com",
    )
    assert out == f"Hi Ada, complete training: {training_url}"

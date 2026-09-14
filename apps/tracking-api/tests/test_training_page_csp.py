"""Training-page CSP: inline styles are pinned by sha256 hash, not 'unsafe-inline'.

Audit 2026-09-14 finding #1 remediation. The awareness landing page and the
training page each carry one small STATIC inline ``<style>`` block (no scripts,
no user data in the CSS). They are allowed by exact sha256 hash, so no other
injected style can apply. This test recomputes those hashes from the rendered
pages — if the CSS changes without updating the CSP hash, this fails, and
``'unsafe-inline'`` can never silently return.
"""

from __future__ import annotations

import base64
import hashlib
import re
from types import SimpleNamespace

from kp_tracking_api import routers

CSP = routers._TRAINING_HEADERS["Content-Security-Policy"]


def _style_hashes(html_text: str) -> list[str]:
    return [
        "sha256-" + base64.b64encode(hashlib.sha256(block.encode("utf-8")).digest()).decode()
        for block in re.findall(r"<style>(.*?)</style>", html_text, re.S)
    ]


def _rendered_style_hashes() -> list[str]:
    hashes = _style_hashes(routers.training_awareness().body.decode("utf-8"))
    resource = SimpleNamespace(title="T", content="C", knowledge_question=None, knowledge_options=[])
    hashes += _style_hashes(routers._training_page(resource, "b" * 40).body.decode("utf-8"))
    return hashes


def test_training_csp_has_no_unsafe_inline_and_no_scripts() -> None:
    assert "'unsafe-inline'" not in CSP
    assert "'unsafe-eval'" not in CSP
    assert "default-src 'none'" in CSP
    assert "frame-ancestors 'none'" in CSP
    # No JavaScript is served on training pages, so there is no script-src at all.
    assert "script-src" not in CSP


def test_every_inline_style_block_is_pinned_by_hash() -> None:
    rendered = _rendered_style_hashes()
    assert rendered, "expected at least one inline <style> block to hash"
    for digest in rendered:
        assert f"'{digest}'" in CSP, f"CSP is missing the hash for a rendered <style> block: {digest}"


def test_completion_page_shares_the_hardened_csp() -> None:
    # The completion page has no inline style, but the same fail-closed CSP applies.
    assert routers._completion_page().headers["Content-Security-Policy"] == CSP

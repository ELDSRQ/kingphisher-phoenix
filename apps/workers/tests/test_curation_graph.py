"""Graph body-fetch for curation (list_raw_messages), with a mocked transport."""

from __future__ import annotations

from email.message import EmailMessage

import httpx
from kp_workers.providers.curation_mime import extract_forwarded_phish
from kp_workers.providers.microsoft365 import Microsoft365ReportedMailboxProvider


def _phish_bytes() -> bytes:
    m = EmailMessage()
    m["Subject"] = "Graph: verify your account"
    m["From"] = "attacker@evil.example"
    m["To"] = "report-phish@corp.example"
    m.set_content("verify now")
    m.add_alternative("<p>Verify <a href='https://evil.example/x'>now</a></p>", subtype="html")
    return m.as_bytes()


def _provider(handler: httpx.MockTransport) -> Microsoft365ReportedMailboxProvider:
    return Microsoft365ReportedMailboxProvider(
        "https://graph.test/v1.0",
        mailbox_id="reports@example.com",
        bearer_token="secret",
        transport=handler,
    )


def test_list_raw_messages_lists_then_fetches_each_value() -> None:
    phish = _phish_bytes()
    seen = {"list": 0, "value": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/$value"):
            seen["value"] += 1
            return httpx.Response(200, content=phish)
        seen["list"] += 1
        return httpx.Response(200, json={"value": [{"id": "AAA"}, {"id": "BBB"}]})

    raws = _provider(httpx.MockTransport(handler)).list_raw_messages(limit=10)
    assert raws == [phish, phish]
    assert seen["list"] == 1 and seen["value"] == 2
    # the fetched raw MIME is usable by the hardened curation extractor
    extracted = extract_forwarded_phish(raws[0])
    assert extracted is not None and extracted.html and "Verify" in extracted.html


def test_list_raw_messages_handles_empty_and_malformed() -> None:
    assert _provider(httpx.MockTransport(lambda _r: httpx.Response(200, json={"value": []}))).list_raw_messages() == []
    assert (
        _provider(httpx.MockTransport(lambda _r: httpx.Response(200, json={"value": "bad"}))).list_raw_messages() == []
    )

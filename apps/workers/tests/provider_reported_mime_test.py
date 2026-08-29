from __future__ import annotations

import gzip
from email.message import EmailMessage

import pytest
from kp_workers.providers.reported_mime import ReportedMimeError, ReportedMimeParser


def _original(candidate: str, *, folded: bool = False) -> bytes:
    if folded:
        return (
            b"x-kp-report-correlation: "
            + candidate[:16].encode()
            + b"\r\n\t"
            + candidate[16:].encode()
            + b"\r\nMessage-ID: <original@example.com>\r\n\r\nbody"
        )
    message = EmailMessage()
    message["X-KP-Report-Correlation"] = candidate
    message["Message-ID"] = "<original@example.com>"
    message.set_content("original content is never returned")
    return message.as_bytes()


def _wrapper(*originals: bytes, outer_candidate: str | None = None) -> bytes:
    wrapper = EmailMessage()
    if outer_candidate is not None:
        wrapper["X-KP-Report-Correlation"] = outer_candidate
    wrapper.set_content("Outlook report wrapper")
    for index, original in enumerate(originals):
        wrapper.add_attachment(
            original,
            maintype="application",
            subtype="octet-stream",
            filename=f"original-{index}.eml",
        )
    return wrapper.as_bytes()


def test_attached_original_handles_case_and_folded_correlation_header() -> None:
    candidate = "AbCdEfGhIjKlMnOpQrStUvWxYz-012345"

    result = ReportedMimeParser().parse(_wrapper(_original(candidate, folded=True)))

    assert result.disposition == "single"
    assert result.candidate == candidate
    assert len(result.evidence) == 1
    assert result.evidence[0].source == "attached_original"
    assert result.evidence[0].message_id == "<original@example.com>"
    assert result.attachments_seen == 1


def test_message_rfc822_attached_original_is_parsed_without_rendering() -> None:
    candidate = "message-rfc822-candidate-1234"
    original = _original(candidate)
    raw = (
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/mixed; boundary=report\r\n\r\n"
        b"--report\r\nContent-Type: text/plain\r\n\r\nreported\r\n"
        b"--report\r\nContent-Type: message/rfc822\r\n"
        b"Content-Disposition: attachment; filename=original.eml\r\n\r\n" + original + b"\r\n--report--\r\n"
    )

    result = ReportedMimeParser().parse(raw)

    assert result.candidate == candidate
    assert result.evidence[0].source == "attached_original"


def test_base64_encoded_message_rfc822_attachment_is_decoded_within_bounds() -> None:
    candidate = "base64-rfc822-candidate-0001"
    wrapper = EmailMessage()
    wrapper.set_content("report")
    wrapper.add_attachment(
        _original(candidate),
        maintype="message",
        subtype="rfc822",
        filename="original.eml",
    )

    result = ReportedMimeParser().parse(wrapper.as_bytes())

    assert result.disposition == "single"
    assert result.candidate == candidate
    assert result.evidence[0].source == "attached_original"


def test_ambiguous_candidates_are_returned_without_selecting_one() -> None:
    outer = "outer-candidate-00000001"
    attached = "attached-candidate-0001"

    result = ReportedMimeParser().parse(_wrapper(_original(attached), outer_candidate=outer))

    assert result.disposition == "ambiguous"
    assert result.candidate is None
    assert [item.candidate for item in result.evidence] == [outer, attached]
    assert [item.source for item in result.evidence] == ["wrapper", "attached_original"]


def test_repeated_identical_evidence_is_single_but_preserves_provenance() -> None:
    candidate = "same-candidate-0000000001"

    result = ReportedMimeParser().parse(_wrapper(_original(candidate), _original(candidate)))

    assert result.disposition == "single"
    assert result.candidate == candidate
    assert len(result.evidence) == 2
    assert result.evidence[0].part_path != result.evidence[1].part_path


def test_invalid_candidate_is_counted_without_returning_content() -> None:
    result = ReportedMimeParser().parse(_wrapper(_original("too-short")))

    assert result.disposition == "none"
    assert result.candidate is None
    assert result.evidence == ()
    assert result.invalid_candidate_count == 1


def test_compressed_attachment_is_never_decompressed_or_inspected() -> None:
    compressed = gzip.compress(_original("hidden-candidate-0000001"))
    wrapper = EmailMessage()
    wrapper.set_content("report")
    wrapper.add_attachment(compressed, maintype="application", subtype="gzip", filename="original.eml.gz")

    result = ReportedMimeParser().parse(wrapper.as_bytes())

    assert result.disposition == "none"
    assert result.compressed_parts_skipped == 1


def test_malformed_attached_eml_fails_closed() -> None:
    with pytest.raises(ReportedMimeError, match="attached message is malformed"):
        ReportedMimeParser().parse(_wrapper(b"not an RFC message"))


def test_total_and_decoded_byte_limits_fail_closed() -> None:
    raw = _wrapper(_original("bounded-candidate-000001"))
    with pytest.raises(ReportedMimeError, match="total byte limit"):
        ReportedMimeParser(max_total_bytes=len(raw) - 1).parse(raw)

    attachment = EmailMessage()
    attachment.set_content("report")
    attachment.add_attachment(b"x" * 1024, maintype="application", subtype="octet-stream", filename="blob.bin")
    with pytest.raises(ReportedMimeError, match="decoded byte limit"):
        ReportedMimeParser(max_decoded_bytes=128).parse(attachment.as_bytes())


def test_depth_part_and_attachment_limits_fail_closed() -> None:
    nested = _original("deep-candidate-000000001")
    for _ in range(3):
        nested = _wrapper(nested)
    with pytest.raises(ReportedMimeError, match="nesting depth"):
        ReportedMimeParser(max_depth=2).parse(nested)

    multipart = EmailMessage()
    multipart.set_content("body")
    multipart.add_attachment(b"one", maintype="application", subtype="octet-stream", filename="one.bin")
    multipart.add_attachment(b"two", maintype="application", subtype="octet-stream", filename="two.bin")
    with pytest.raises(ReportedMimeError, match="part limit"):
        ReportedMimeParser(max_parts=2).parse(multipart.as_bytes())
    with pytest.raises(ReportedMimeError, match="attachment limit"):
        ReportedMimeParser(max_attachments=1).parse(multipart.as_bytes())


def test_malformed_multipart_and_transfer_encoding_are_rejected() -> None:
    malformed_boundary = b"Content-Type: multipart/mixed; boundary=missing\r\n\r\nno boundary"
    with pytest.raises(ReportedMimeError, match="malformed"):
        ReportedMimeParser().parse(malformed_boundary)

    malformed_base64 = (
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Disposition: attachment; filename=original.eml\r\n"
        b"Content-Transfer-Encoding: base64\r\n\r\n!!!!"
    )
    with pytest.raises(ReportedMimeError, match="malformed"):
        ReportedMimeParser().parse(malformed_base64)


def test_correlation_header_count_and_value_work_are_independently_bounded() -> None:
    headers = b"".join(f"X-KP-Report-Correlation: bounded-candidate-{index:04d}\r\n".encode() for index in range(3))
    with pytest.raises(ReportedMimeError, match="correlation header limit"):
        ReportedMimeParser(max_correlation_headers=2).parse(headers + b"\r\nbody")

    oversized = b"X-KP-Report-Correlation: " + b"A" * 1025 + b"\r\n\r\nbody"
    result = ReportedMimeParser().parse(oversized)
    assert result.disposition == "none"
    assert result.invalid_candidate_count == 1


@pytest.mark.parametrize(
    "raw",
    [
        b"Content-Transfer-Encoding: x-private\r\n\r\nbody",
        b"Content-Transfer-Encoding: quoted-printable\r\n\r\nbad=ZZvalue",
        b"Content-Transfer-Encoding: base64\r\n\r\n!!!!",
    ],
)
def test_unknown_or_malformed_transfer_encodings_fail_closed(raw: bytes) -> None:
    with pytest.raises(ReportedMimeError, match="transfer encoding is malformed"):
        ReportedMimeParser().parse(raw)


@pytest.mark.parametrize("name", ["X Header", "ümlaut", "X" * 79])
def test_custom_correlation_header_must_be_a_bounded_ascii_field_name(name: str) -> None:
    with pytest.raises(ValueError, match="correlation header is malformed"):
        ReportedMimeParser(correlation_header=name)

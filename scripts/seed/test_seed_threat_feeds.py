"""Tests for the threat-feed source manifest and its validator.

Run (no DB, no network):
    cd scripts/seed && KP_DISABLE_DOTENV=1 python -m pytest test_seed_threat_feeds.py -q
    # or: uv run python -m pytest scripts/seed/test_seed_threat_feeds.py -q
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import seed_threat_feeds as stf  # noqa: E402

MANIFEST = stf.DEFAULT_MANIFEST


@pytest.fixture(scope="module")
def loaded() -> dict:
    return stf.load_manifest(MANIFEST)


@pytest.fixture(scope="module")
def feeds(loaded: dict) -> list[dict]:
    return stf.validate_manifest(loaded)


def test_manifest_parses(loaded: dict) -> None:
    assert isinstance(loaded, dict)
    assert isinstance(loaded.get("feeds"), list)
    assert loaded["feeds"], "manifest must define at least one feed"


def test_reasonable_source_count(feeds: list[dict]) -> None:
    assert 8 <= len(feeds) <= 15


def test_required_fields_present(feeds: list[dict]) -> None:
    for entry in feeds:
        for field in stf.REQUIRED_FIELDS:
            assert field in entry, f"{entry.get('id')!r} missing {field}"


def test_ids_are_unique(feeds: list[dict]) -> None:
    ids = [entry["id"] for entry in feeds]
    assert len(ids) == len(set(ids))


def test_every_url_is_http(feeds: list[dict]) -> None:
    for entry in feeds:
        assert stf._is_http_url(entry["url"]), entry["id"]


def test_kinds_in_allowed_set(feeds: list[dict]) -> None:
    for entry in feeds:
        assert entry["kind"] in stf.ALLOWED_KINDS, entry["id"]


def test_categories_non_empty_strings(feeds: list[dict]) -> None:
    for entry in feeds:
        assert entry["categories"]
        assert all(isinstance(c, str) and c for c in entry["categories"])


def test_check_passes_on_committed_manifest() -> None:
    assert stf.main(["--check"]) == 0


def test_default_run_emits_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert stf.main([]) == 0
    out = capsys.readouterr().out
    import json

    parsed = json.loads(out)
    assert isinstance(parsed, list) and parsed


def test_out_file_is_idempotent(tmp_path: Path) -> None:
    first = tmp_path / "a.json"
    second = tmp_path / "b.json"
    assert stf.main(["--out", str(first)]) == 0
    assert stf.main(["--out", str(second)]) == 0
    assert first.read_text() == second.read_text()


def _base_entry() -> dict:
    return {
        "id": "example",
        "name": "Example",
        "url": "https://example.com/feed",
        "kind": "rss",
        "publisher": "example.com",
        "categories": ["phishing"],
        "enabled": True,
    }


def test_malformed_bad_url_rejected() -> None:
    bad = _base_entry()
    bad["url"] = "ftp://example.com/feed"
    with pytest.raises(stf.ManifestError):
        stf.validate_manifest({"feeds": [bad]})


def test_malformed_bad_kind_rejected() -> None:
    bad = _base_entry()
    bad["kind"] = "gopher"
    with pytest.raises(stf.ManifestError):
        stf.validate_manifest({"feeds": [bad]})


def test_malformed_missing_field_rejected() -> None:
    bad = _base_entry()
    del bad["publisher"]
    with pytest.raises(stf.ManifestError):
        stf.validate_manifest({"feeds": [bad]})


def test_malformed_duplicate_id_rejected() -> None:
    with pytest.raises(stf.ManifestError):
        stf.validate_manifest({"feeds": [_base_entry(), _base_entry()]})


def test_malformed_unknown_field_rejected() -> None:
    bad = _base_entry()
    bad["danger"] = "extra"
    with pytest.raises(stf.ManifestError):
        stf.validate_manifest({"feeds": [bad]})


def test_malformed_non_bool_enabled_rejected() -> None:
    bad = _base_entry()
    bad["enabled"] = "yes"
    with pytest.raises(stf.ManifestError):
        stf.validate_manifest({"feeds": [bad]})


def test_yaml_round_trips_through_validator() -> None:
    text = MANIFEST.read_text(encoding="utf-8")
    data = yaml.safe_load(text)
    feeds = stf.validate_manifest(data)
    assert feeds is data["feeds"]

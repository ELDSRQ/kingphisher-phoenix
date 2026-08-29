from __future__ import annotations

import importlib.util
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "operator" / "release" / "supply_chain_evidence.py"
SPEC = importlib.util.spec_from_file_location("supply_chain_evidence", SCRIPT)
assert SPEC and SPEC.loader
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)

DIGEST = "sha256:" + "a" * 64
POSTGRES_IMAGE = "postgres:16-alpine@sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777"
REDIS_IMAGE = "redis:7-alpine@sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2"


def _raw_sbom(*, reverse: bool = False) -> dict[str, object]:
    packages = [
        {"SPDXID": "SPDXRef-Package-b", "name": "b", "versionInfo": "2"},
        {"SPDXID": "SPDXRef-Package-a", "name": "a", "versionInfo": "1"},
    ]
    if reverse:
        packages.reverse()
    return {
        "spdxVersion": "SPDX-2.3",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "volatile",
        "documentNamespace": "https://example.invalid/random",
        "creationInfo": {"created": "2099-01-01T00:00:00Z", "creators": ["Tool: Syft", "Organization: Test"]},
        "dataLicense": "CC0-1.0",
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": "SPDXRef-Package-a",
            }
        ],
    }


def test_canonical_sbom_is_stable_and_bound_to_the_image_digest(tmp_path: Path) -> None:
    first = evidence.canonicalize_sbom(
        _raw_sbom(), image_name="registry.example/operator-api", image_digest=DIGEST, source_date_epoch=1_700_000_000
    )
    second = evidence.canonicalize_sbom(
        _raw_sbom(reverse=True),
        image_name="registry.example/operator-api",
        image_digest=DIGEST,
        source_date_epoch=1_700_000_000,
    )
    first_path = tmp_path / "first.spdx.json"
    second_path = tmp_path / "second.spdx.json"
    evidence._dump_canonical(first, first_path)
    evidence._dump_canonical(second, second_path)

    assert first_path.read_bytes() == second_path.read_bytes()
    assert first["name"] == f"registry.example/operator-api@{DIGEST}"
    assert first["creationInfo"]["created"] == "2023-11-14T22:13:20Z"
    assert [package["SPDXID"] for package in first["packages"]] == ["SPDXRef-Package-a", "SPDXRef-Package-b"]


@pytest.mark.parametrize("digest", ["latest", "sha256:abc", "sha512:" + "a" * 128])
def test_canonical_sbom_rejects_mutable_or_malformed_digests(digest: str) -> None:
    with pytest.raises(evidence.EvidenceError, match="immutable image digest"):
        evidence.canonicalize_sbom(
            _raw_sbom(), image_name="registry.example/operator-api", image_digest=digest, source_date_epoch=0
        )


def test_manifest_requires_all_four_images_and_validates_sbom_checksums(tmp_path: Path) -> None:
    lines = []
    for index, image in enumerate(evidence.RELEASE_IMAGES):
        digest = f"sha256:{index + 1:064x}"
        repository = f"registry.example/{image}"
        sbom_name = f"{image}.spdx.json"
        normalized = evidence.canonicalize_sbom(
            _raw_sbom(), image_name=repository, image_digest=digest, source_date_epoch=1_700_000_000
        )
        evidence._dump_canonical(normalized, tmp_path / sbom_name)
        lines.append(f"{image}\t{repository}\t{digest}\t{sbom_name}")
    entries = tmp_path / "entries.tsv"
    entries.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_path = tmp_path / "release-manifest.json"

    manifest = evidence.build_manifest(entries_path=entries, output_path=manifest_path, source_revision="b" * 40)
    assert tuple(manifest["images"]) == evidence.RELEASE_IMAGES
    assert evidence.validate_manifest(manifest_path) == manifest

    (tmp_path / "migration.spdx.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(evidence.EvidenceError, match="checksum mismatch"):
        evidence.validate_manifest(manifest_path)


def test_manifest_fails_closed_when_any_release_image_is_missing(tmp_path: Path) -> None:
    entries = tmp_path / "entries.tsv"
    entries.write_text("", encoding="utf-8")
    with pytest.raises(evidence.EvidenceError, match="incomplete"):
        evidence.build_manifest(entries_path=entries, output_path=tmp_path / "manifest.json", source_revision="b" * 40)


def test_manifest_rejects_an_empty_spdx_inventory_even_when_subject_matches(tmp_path: Path) -> None:
    lines = []
    for index, image in enumerate(evidence.RELEASE_IMAGES):
        digest = f"sha256:{index + 1:064x}"
        repository = f"registry.example/{image}"
        sbom_name = f"{image}.spdx.json"
        normalized = evidence.canonicalize_sbom(
            _raw_sbom(), image_name=repository, image_digest=digest, source_date_epoch=1_700_000_000
        )
        if image == "worker":
            normalized["packages"] = []
        evidence._dump_canonical(normalized, tmp_path / sbom_name)
        lines.append(f"{image}\t{repository}\t{digest}\t{sbom_name}")
    entries = tmp_path / "entries.tsv"
    entries.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(evidence.EvidenceError, match="inventory mismatch for worker"):
        evidence.build_manifest(entries_path=entries, output_path=tmp_path / "manifest.json", source_revision="b" * 40)


def test_compose_stateful_images_are_exactly_pinned_to_qualified_indexes() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    qualification = compose["x-kp-base-image-qualification"]

    assert qualification == {
        "command": ["bash", "scripts/operator/base-image-qualification/run.sh"],
        "stateful_services": ["postgres", "redis"],
    }
    assert compose["services"]["postgres"]["image"] == POSTGRES_IMAGE
    assert compose["services"]["redis"]["image"] == REDIS_IMAGE
    for service in qualification["stateful_services"]:
        reference = compose["services"][service]["image"]
        assert re.fullmatch(r"[a-z0-9][a-z0-9./:_-]*@sha256:[0-9a-f]{64}", reference)

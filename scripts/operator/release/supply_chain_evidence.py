#!/usr/bin/env python3
"""Create and validate deterministic release-image supply-chain evidence.

The network-facing tools (ACR and Syft) stay in the release workflow.  This
module only canonicalizes their output and validates the resulting release
set, so its policy can be exercised offline and without registry credentials.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

RELEASE_IMAGES = ("operator-api", "tracking-api", "worker", "migration")
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class EvidenceError(ValueError):
    """The supplied release evidence does not satisfy the release policy."""


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"cannot read JSON evidence {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EvidenceError(f"JSON evidence must be an object: {path}")
    return value


def _require_digest(digest: str) -> None:
    if not SHA256_RE.fullmatch(digest):
        raise EvidenceError(f"invalid immutable image digest: {digest!r}")


def _created_at(source_date_epoch: int) -> str:
    if source_date_epoch < 0:
        raise EvidenceError("SOURCE_DATE_EPOCH cannot be negative")
    return datetime.fromtimestamp(source_date_epoch, tz=UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonicalize_sbom(
    document: dict[str, Any], *, image_name: str, image_digest: str, source_date_epoch: int
) -> dict[str, Any]:
    """Normalize Syft SPDX JSON while retaining its complete package inventory."""
    _require_digest(image_digest)
    if document.get("spdxVersion") != "SPDX-2.3" or document.get("SPDXID") != "SPDXRef-DOCUMENT":
        raise EvidenceError("SBOM must be an SPDX 2.3 document")
    if not image_name or ":" in image_name.rsplit("/", 1)[-1] or "@" in image_name:
        raise EvidenceError("image name must be a fully qualified, tag-free OCI repository")
    if not isinstance(document.get("packages"), list) or not document["packages"]:
        raise EvidenceError("SBOM contains no packages")

    digest_hex = image_digest.removeprefix("sha256:")
    normalized = dict(document)
    normalized["name"] = f"{image_name}@{image_digest}"
    normalized["documentNamespace"] = f"https://kingphisher.invalid/spdx/{quote(image_name, safe='')}/{digest_hex}"
    creation_info = dict(normalized.get("creationInfo") or {})
    creators = creation_info.get("creators")
    if not isinstance(creators, list) or not creators:
        raise EvidenceError("SBOM creationInfo.creators is required")
    creation_info["created"] = _created_at(source_date_epoch)
    creation_info["creators"] = sorted(str(value) for value in creators)
    normalized["creationInfo"] = creation_info

    for collection, keys in (
        ("packages", ("SPDXID", "name", "versionInfo")),
        ("files", ("SPDXID", "fileName")),
        ("relationships", ("spdxElementId", "relationshipType", "relatedSpdxElement")),
        ("externalDocumentRefs", ("externalDocumentId", "spdxDocument")),
        ("hasExtractedLicensingInfos", ("licenseId", "name")),
    ):
        values = normalized.get(collection)
        if values is None:
            continue
        if not isinstance(values, list) or any(not isinstance(value, dict) for value in values):
            raise EvidenceError(f"SBOM {collection} must be a list of objects")
        normalized[collection] = sorted(
            values,
            key=lambda value: tuple(str(value.get(key, "")) for key in keys),
        )
    return normalized


def _dump_canonical(document: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _validate_sbom_subject(document: dict[str, Any], *, repository: str, digest: str, image: str) -> None:
    expected_namespace = (
        f"https://kingphisher.invalid/spdx/{quote(repository, safe='')}/{digest.removeprefix('sha256:')}"
    )
    if (
        document.get("spdxVersion") != "SPDX-2.3"
        or document.get("SPDXID") != "SPDXRef-DOCUMENT"
        or document.get("name") != f"{repository}@{digest}"
        or document.get("documentNamespace") != expected_namespace
        or not isinstance(document.get("packages"), list)
        or not document["packages"]
    ):
        raise EvidenceError(f"SBOM subject or SPDX inventory mismatch for {image}")


def build_manifest(*, entries_path: Path, output_path: Path, source_revision: str) -> dict[str, Any]:
    if not REVISION_RE.fullmatch(source_revision):
        raise EvidenceError("source revision must be a lowercase 40-character Git SHA")
    entries: dict[str, dict[str, str]] = {}
    for line_number, raw_line in enumerate(entries_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip():
            continue
        fields = raw_line.split("\t")
        if len(fields) != 4:
            raise EvidenceError(f"entry line {line_number} must have four tab-separated fields")
        image, repository, digest, sbom_name = fields
        if image not in RELEASE_IMAGES or image in entries:
            raise EvidenceError(f"unexpected or duplicate release image {image!r}")
        _require_digest(digest)
        if not repository or ":" in repository.rsplit("/", 1)[-1] or "@" in repository:
            raise EvidenceError(f"invalid tag-free repository for {image}: {repository!r}")
        sbom_path = entries_path.parent / sbom_name
        sbom = _load_object(sbom_path)
        _validate_sbom_subject(sbom, repository=repository, digest=digest, image=image)
        entries[image] = {
            "repository": repository,
            "digest": digest,
            "sbom": sbom_name,
            "sbomDigest": _sha256(sbom_path),
        }
    if tuple(sorted(entries)) != tuple(sorted(RELEASE_IMAGES)):
        missing = sorted(set(RELEASE_IMAGES) - set(entries))
        raise EvidenceError(f"release evidence is incomplete; missing: {', '.join(missing)}")
    manifest: dict[str, Any] = {
        "schemaVersion": 1,
        "sourceRevision": source_revision,
        "images": {image: entries[image] for image in RELEASE_IMAGES},
    }
    _dump_canonical(manifest, output_path)
    return manifest


def validate_manifest(path: Path) -> dict[str, Any]:
    manifest = _load_object(path)
    if manifest.get("schemaVersion") != 1 or not REVISION_RE.fullmatch(str(manifest.get("sourceRevision", ""))):
        raise EvidenceError("invalid release manifest metadata")
    images = manifest.get("images")
    if not isinstance(images, dict) or set(images) != set(RELEASE_IMAGES):
        raise EvidenceError("release manifest must contain exactly the four release images")
    for image, evidence in images.items():
        if not isinstance(evidence, dict):
            raise EvidenceError(f"invalid evidence record for {image}")
        digest = str(evidence.get("digest", ""))
        _require_digest(digest)
        sbom_name = str(evidence.get("sbom", ""))
        if Path(sbom_name).name != sbom_name:
            raise EvidenceError(f"unsafe SBOM path for {image}")
        sbom_path = path.parent / sbom_name
        if _sha256(sbom_path) != evidence.get("sbomDigest"):
            raise EvidenceError(f"SBOM checksum mismatch for {image}")
        sbom = _load_object(sbom_path)
        _validate_sbom_subject(
            sbom,
            repository=str(evidence.get("repository", "")),
            digest=digest,
            image=image,
        )
    return manifest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    canonicalize = commands.add_parser("canonicalize-sbom")
    canonicalize.add_argument("--input", type=Path, required=True)
    canonicalize.add_argument("--output", type=Path, required=True)
    canonicalize.add_argument("--image-name", required=True)
    canonicalize.add_argument("--image-digest", required=True)
    canonicalize.add_argument("--source-date-epoch", required=True, type=int)
    manifest = commands.add_parser("build-manifest")
    manifest.add_argument("--entries", type=Path, required=True)
    manifest.add_argument("--output", type=Path, required=True)
    manifest.add_argument("--source-revision", required=True)
    validate = commands.add_parser("validate-manifest")
    validate.add_argument("--manifest", type=Path, required=True)
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        if args.command == "canonicalize-sbom":
            document = canonicalize_sbom(
                _load_object(args.input),
                image_name=args.image_name,
                image_digest=args.image_digest,
                source_date_epoch=args.source_date_epoch,
            )
            _dump_canonical(document, args.output)
        elif args.command == "build-manifest":
            build_manifest(entries_path=args.entries, output_path=args.output, source_revision=args.source_revision)
        else:
            validate_manifest(args.manifest)
    except (EvidenceError, OSError) as exc:
        print(f"supply-chain evidence rejected: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

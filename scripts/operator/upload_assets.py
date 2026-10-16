#!/usr/bin/env python3
"""Upload (and optionally approve) reusable image assets into the template-asset
library via the operator-api.

Reads a JSON manifest describing one or more raster images (banners, logos) and
POSTs each to ``/api/v1/assets`` as a DRAFT, then — with ``--approve`` — promotes
each to APPROVED so it can be applied to templates. Idempotent by content hash:
an asset whose sha256 already exists in the library is skipped unless ``--force``.

Runs where the operator-api is reachable (on .105: http://127.0.0.1:8000). Pure
stdlib, so it needs no extra install on the host.

Manifest (JSON):
    {
      "assets": [
        {"file": "banner_ms365_s07.png", "kind": "banner", "brand": "microsoft",
         "name": "MS365 security banner",
         "provenance": {"generator": "FLUX.2-klein-4B", "seed": 7, "host": "ALICE"}},
        {"file": "logo_microsoft.png", "kind": "logo", "brand": "microsoft",
         "name": "Microsoft 4-square logo", "provenance": {"source": "asset-library"}}
      ]
    }

Usage:
    python3 upload_assets.py --manifest assets.json --dir /path/to/pngs --approve
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

DEFAULT_BASE = "http://127.0.0.1:8000"
DEFAULT_ENV = "/home/builder/phishing-awareness-platform/.env"
_VALID_KINDS = {"banner", "logo", "decorative"}


def req(method: str, url: str, base: str, tok: str | None = None, body: dict | None = None, timeout: int = 60):
    if url.startswith("/"):
        url = base + url
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method)  # noqa: S310 (operator-controlled URL)
    r.add_header("Content-Type", "application/json")
    if tok:
        r.add_header("Authorization", "Bearer " + tok)
    try:
        with urllib.request.urlopen(r, timeout=timeout) as x:  # noqa: S310 (operator-controlled URL)
            raw = x.read().decode()
            return x.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:  # noqa: BLE001
            return e.code, {"raw": raw[:600]}


def console_token(base: str, env_path: str) -> str:
    """Mint a console session token from KP_CONSOLE_PASSWORD in the .env."""

    password = None
    for line in pathlib.Path(env_path).read_text().splitlines():
        if line.startswith("KP_CONSOLE_PASSWORD="):
            password = line.split("=", 1)[1].strip().strip("\"'")
            break
    if not password:
        raise SystemExit(f"KP_CONSOLE_PASSWORD not found in {env_path}")
    status, out = req("POST", "/api/v1/console/session", base, body={"password": password})
    if status != 200 or not out.get("token"):
        raise SystemExit(f"console auth failed ({status}): {out}")
    return out["token"]


def existing_sha256(base: str, tok: str) -> set[str]:
    """Return the sha256 of every asset already in the library (for idempotency)."""

    status, out = req("GET", "/api/v1/assets", base, tok)
    if status != 200:
        return set()
    return {a.get("sha256") for a in out.get("assets", []) if a.get("sha256")}


def main() -> int:
    ap = argparse.ArgumentParser(description="Upload image assets into the template-asset library.")
    ap.add_argument("--manifest", required=True, help="JSON manifest of assets to upload")
    ap.add_argument("--dir", default=".", help="directory holding the asset files named in the manifest")
    ap.add_argument("--base-url", default=DEFAULT_BASE, help=f"operator-api base URL (default {DEFAULT_BASE})")
    ap.add_argument("--env", default=DEFAULT_ENV, help="path to .env holding KP_CONSOLE_PASSWORD")
    ap.add_argument("--token", default=None, help="use this bearer token instead of console password auth")
    ap.add_argument("--approve", action="store_true", help="also approve each uploaded asset")
    ap.add_argument("--force", action="store_true", help="upload even if an asset with the same sha256 exists")
    ap.add_argument(
        "--dry-run", action="store_true", help="validate files and print the planned requests without calling the API"
    )
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    manifest = json.loads(pathlib.Path(args.manifest).read_text())
    assets = manifest.get("assets") if isinstance(manifest, dict) else manifest
    if not isinstance(assets, list) or not assets:
        raise SystemExit("manifest has no 'assets' list")
    asset_dir = pathlib.Path(args.dir)

    if args.dry_run:
        tok = None
        seen = set()
    else:
        tok = args.token or console_token(base, args.env)
        seen = set() if args.force else existing_sha256(base, tok)

    uploaded = approved = skipped = failed = 0
    for spec in assets:
        name = spec.get("name") or spec.get("file")
        kind = spec.get("kind")
        if kind not in _VALID_KINDS:
            print(f"  SKIP {name}: invalid kind {kind!r} (must be one of {sorted(_VALID_KINDS)})")
            failed += 1
            continue
        path = asset_dir / spec["file"]
        if not path.is_file():
            print(f"  SKIP {name}: file not found: {path}")
            failed += 1
            continue
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest in seen:
            print(f"  SKIP {name}: already in library (sha256 {digest[:12]})")
            skipped += 1
            continue

        body = {
            "kind": kind,
            "name": name,
            "brand": spec.get("brand"),
            "content_base64": base64.b64encode(content).decode("ascii"),
            "provenance": spec.get("provenance", {}),
        }
        if args.dry_run:
            tail = "  then approve" if args.approve else ""
            print(
                f"  DRY-RUN {name}: would POST /api/v1/assets kind={kind} brand={body['brand']} "
                f"bytes={len(content)} sha256={digest[:12]} b64={len(body['content_base64'])}{tail}"
            )
            uploaded += 1
            seen.add(digest)
            continue
        status, out = req("POST", "/api/v1/assets", base, tok, body=body)
        if status != 201:
            print(f"  FAIL {name}: upload {status}: {out}")
            failed += 1
            continue
        asset_id = out["asset_id"]
        print(
            f"  UPLOADED {name}: {asset_id} "
            f"({out['media_type']} {out['width']}x{out['height']}, {out['byte_size']}B) DRAFT"
        )
        uploaded += 1
        seen.add(digest)

        if args.approve:
            astatus, aout = req(
                "POST",
                f"/api/v1/assets/{asset_id}/approve",
                base,
                tok,
                body={"decision": "approved", "rationale": "vetted asset upload"},
            )
            if astatus == 200 and aout.get("approval_state") == "approved":
                print(f"    APPROVED {asset_id}")
                approved += 1
            elif astatus == 403:
                print(f"    NOT approved (separation of duties): a different operator must approve {asset_id}")
            else:
                print(f"    approve failed {astatus}: {aout}")

    print(f"\nDone: uploaded={uploaded} approved={approved} skipped={skipped} failed={failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

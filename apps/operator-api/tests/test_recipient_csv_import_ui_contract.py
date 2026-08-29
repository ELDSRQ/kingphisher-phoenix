from pathlib import Path

APP = (Path(__file__).resolve().parents[2] / "operator-ui" / "src" / "console" / "app.js").read_text(encoding="utf-8")
RECIPIENTS = APP[APP.index("views.recipients = async (root) =>") : APP.index("/* ---------- privacy ---------- */")]


def test_gui_enforces_browser_bounds_before_preview() -> None:
    assert "const MAX_RECIPIENT_CSV_BYTES = 512 * 1024;" in APP
    assert "const MAX_RECIPIENT_CSV_ROWS = 5000;" in APP
    assert "new TextEncoder().encode(csvText).byteLength" in APP
    assert "file.size > MAX_RECIPIENT_CSV_BYTES" in RECIPIENTS
    assert "validateRecipientCsvText(text);" in RECIPIENTS


def test_gui_golden_path_previews_then_applies_exact_digest() -> None:
    assert 'api("/recipients/import/preview"' in RECIPIENTS
    assert 'api("/recipients/import/apply"' in RECIPIENTS
    assert 'api("/recipients/import",' not in RECIPIENTS
    assert "preview_digest: currentPreview.preview_digest" in RECIPIENTS
    assert 'text: "Apply exact preview", disabled: "disabled"' in RECIPIENTS
    assert "function invalidateImportPreview()" in RECIPIENTS


def test_gui_exposes_mapping_merge_and_second_deactivation_confirmation() -> None:
    for field in ("mailbox", "display_name", "department"):
        assert f'{field}: el("select"' in RECIPIENTS
    assert 'value: "skip", text: "Skip existing recipients"' in RECIPIENTS
    assert 'value: "update", text: "Update existing non-directory recipients"' in RECIPIENTS
    assert "Deactivate CSV-managed recipients missing from this file" in RECIPIENTS
    assert "Deactivate CSV recipients missing from this file?" in RECIPIENTS
    assert "deactivate_missing_confirm: deactivating" in RECIPIENTS
    assert "never hard-deletes" in RECIPIENTS


def test_gui_supports_reviewed_arbitrary_first_row_headers() -> None:
    assert 'const headerMode = el("select", { id: "r-header-mode" }' in RECIPIENTS
    assert 'value: "auto", text: "Auto-detect conventional headers"' in RECIPIENTS
    assert 'value: "first_row", text: "Use the first populated row as headers"' in RECIPIENTS
    assert 'value: "none", text: "Treat every populated row as recipient data"' in RECIPIENTS
    assert "header_mode: headerMode.value" in RECIPIENTS
    assert 'headerMode.value === "first_row" && !explicitHeaderColumnsReviewed' in RECIPIENTS
    assert "Review every column mapping" in RECIPIENTS
    assert "Preview again to bind the exact mapping before Apply" in RECIPIENTS


def test_gui_preview_is_non_pii_and_surfaces_all_required_counts() -> None:
    assert "Preview is non-mutating and shows only counts plus bounded row-number error codes" in RECIPIENTS
    for count in ("created", "updateable", "existing", "blocked", "invalid", "duplicate"):
        assert f'"{count}"' in RECIPIENTS
    assert "text: `Row ${issue.row}: ${issue.code}`" in RECIPIENTS

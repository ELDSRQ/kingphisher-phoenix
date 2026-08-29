from __future__ import annotations

import importlib.util
from pathlib import Path
from urllib.parse import urlparse

from starlette.testclient import TestClient

MODULE = Path(__file__).parents[1] / "infrastructure" / "mock-services" / "mock_graph.py"


def _app() -> object:
    spec = importlib.util.spec_from_file_location("kp_mock_graph_contract", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.app


def test_mock_graph_delta_is_complete_member_snapshot_with_same_origin_cursor() -> None:
    with TestClient(_app(), base_url="http://localhost:8181") as client:
        response = client.get("/users/delta", params={"$select": "id,mail,accountEnabled,userType"})

    assert response.status_code == 200
    payload = response.json()
    assert payload["value"]
    assert all(row["accountEnabled"] is True and row["userType"] == "Member" for row in payload["value"])
    assert all(row["mail"] == row["userPrincipalName"] for row in payload["value"])
    cursor = urlparse(payload["@odata.deltaLink"])
    assert (cursor.scheme, cursor.hostname, cursor.port, cursor.path) == (
        "http",
        "localhost",
        8181,
        "/users/delta",
    )
    assert cursor.query == "$deltatoken=mock-v1"

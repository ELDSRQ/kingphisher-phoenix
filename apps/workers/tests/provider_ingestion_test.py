from __future__ import annotations

import uuid

import pytest
from kp_domain_models import models as dm
from kp_source_adapters import BulkDownloadAdapter, RssAdapter, StixAdapter
from kp_workers.jobs import _source_adapter


def _source(source_type: dm.SourceType) -> dm.Source:
    return dm.Source(
        source_id=uuid.uuid4(),
        source_key="provider-test",
        name="Provider test",
        source_type=source_type,
        base_domain="feed.example",
    )


@pytest.mark.parametrize(
    ("source_type", "expected"),
    [
        (dm.SourceType.RSS, RssAdapter),
        (dm.SourceType.ADVISORY, RssAdapter),
        (dm.SourceType.CURATED, RssAdapter),
        (dm.SourceType.STIX, StixAdapter),
        (dm.SourceType.BULK_DOWNLOAD, BulkDownloadAdapter),
    ],
)
def test_source_type_dispatch(source_type: dm.SourceType, expected: type[object]) -> None:
    assert isinstance(_source_adapter(_source(source_type), object()), expected)

from kp_workers.jobs import _retry_delay


def test_retry_delay_grows_and_is_bounded() -> None:
    assert [_retry_delay(attempt) for attempt in range(1, 5)] == [0.5, 1.0, 2.0, 4.0]
    assert _retry_delay(7) == 30.0
    assert _retry_delay(100) == 30.0

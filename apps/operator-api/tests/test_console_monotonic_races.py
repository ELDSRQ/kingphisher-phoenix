"""Semantic reversed-completion and cached-row regressions on synthetic state."""

from __future__ import annotations

import fcntl
import json
import multiprocessing
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from kp_database.models import ConsoleSessionEpoch, ProviderConfigGeneration
from kp_operator_api import console
from kp_operator_api.auth import console_session_epoch_floor
from kp_operator_api.console import ai_providers
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session


def test_delayed_epoch_commit_shadow_cannot_unrevoke_a_newer_epoch(tmp_path):
    settings = SimpleNamespace(env_file=str(tmp_path / ".env"))
    # DB commit1 was delayed after commit2 finished publishing. Completion
    # order is deliberately reversed; no scheduler timing is involved.
    console._write_session_epoch_marker(settings, 2)
    console._write_session_epoch_marker(settings, 1)
    assert console_session_epoch_floor(settings) == 2
    console._verify_session_epoch_marker(settings, 1)  # a newer floor satisfies it


def test_delayed_provider_commit_shadow_cannot_revert_a_newer_selection(tmp_path):
    settings = SimpleNamespace(env_file=str(tmp_path / ".env"))
    ai_providers._write_generation_marker(settings, 2, "anthropic")
    with pytest.raises(ai_providers.ProviderConfigApplyError):
        ai_providers._write_generation_marker(settings, 1, "openai")
    assert json.loads(ai_providers._generation_path(settings).read_text()) == {"generation": 2, "provider": "anthropic"}


def test_equal_generation_cannot_change_provider_and_corruption_is_not_accepted(tmp_path):
    settings = SimpleNamespace(env_file=str(tmp_path / ".env"))
    ai_providers._write_generation_marker(settings, 2, "anthropic")
    with pytest.raises(ai_providers.ProviderConfigApplyError):
        ai_providers._write_generation_marker(settings, 2, "openai")
    ai_providers._generation_path(settings).write_text("malformed")
    with pytest.raises(ai_providers.ProviderConfigApplyError):
        ai_providers._write_generation_marker(settings, 3, "openai")
    assert ai_providers._generation_path(settings).read_text() == "malformed"


def test_private_lock_is_reentrant_private_and_keeps_one_inode_across_marker_replacement(tmp_path):
    import stat

    from kp_operator_api.console.private_lock import lock_path, private_file_lock

    settings = SimpleNamespace(env_file=str(tmp_path / ".env"))
    path = lock_path(settings, "epoch-marker")
    with private_file_lock(path):
        before = path.stat().st_ino
        console._write_session_epoch_marker(settings, 1)
        console._write_session_epoch_marker(settings, 2)
    assert path.stat().st_ino == before
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert console_session_epoch_floor(settings) == 2


@pytest.mark.parametrize("kind", ["epoch", "provider"])
def test_locked_bump_refreshes_an_existing_identity_map_value(tmp_path, kind):
    engine = create_engine("sqlite:///" + str(tmp_path / "counter.db"))
    event.listen(
        engine,
        "connect",
        lambda connection, _: connection.create_function(
            "now", 0, lambda: datetime.now(UTC).replace(tzinfo=None).isoformat(" ")
        ),
    )
    model = ConsoleSessionEpoch if kind == "epoch" else ProviderConfigGeneration
    model.__table__.create(engine)
    with Session(engine) as session:
        session.add(model(id=1, **({"epoch": 0} if kind == "epoch" else {"generation": 0, "applied_generation": 0})))
        session.commit()
    with Session(engine, expire_on_commit=False) as delayed, Session(engine) as newer:
        cached = delayed.get(model, 1)
        assert cached is not None
        field = "epoch" if kind == "epoch" else "generation"
        setattr(newer.get(model, 1), field, 1)
        newer.commit()
        assert getattr(cached, field) == 0
        actual = (
            console._bump_session_epoch_row(delayed)
            if kind == "epoch"
            else ai_providers._bump_generation(delayed, "local")
        )
        assert actual == 2
        delayed.commit()
    engine.dispose()


@pytest.mark.parametrize("kind", ["epoch", "provider"])
def test_repeated_bumps_in_one_transaction_preserve_the_pending_increment(tmp_path, kind):
    engine = create_engine("sqlite:///" + str(tmp_path / "repeat.db"))
    event.listen(
        engine,
        "connect",
        lambda connection, _: connection.create_function(
            "now", 0, lambda: datetime.now(UTC).replace(tzinfo=None).isoformat(" ")
        ),
    )
    model = ConsoleSessionEpoch if kind == "epoch" else ProviderConfigGeneration
    model.__table__.create(engine)
    with Session(engine) as session:
        bump = (
            (lambda: console._bump_session_epoch_row(session))
            if kind == "epoch"
            else (lambda: ai_providers._bump_generation(session, "local"))
        )
        assert [bump(), bump()] == [1, 2]
        session.commit()
    engine.dispose()


def _sqlite_provider_engine(path):
    engine = create_engine("sqlite:///" + str(path))
    event.listen(
        engine,
        "connect",
        lambda connection, _: connection.create_function(
            "now", 0, lambda: datetime.now(UTC).replace(tzinfo=None).isoformat(" ")
        ),
    )
    return engine


def _password_actor(env, actor, ready, go, entered, release, results):
    from test_session_epoch_rotation import (
        NEW_PASSWORD,
        OLD_PASSWORD,
        _FakeAudit,
        _FakeSession,
        _principal,
        _request,
        _settings,
    )

    settings = _settings(Path(env))  # deliberately constructed before the other process changes persisted state
    request = _request(settings)
    session = _FakeSession()
    if actor == "A":
        original = console._apply_console_password_rotation

        def delayed(path, password):
            entered.set()
            if not release.wait(20):
                raise RuntimeError("test release missing")
            original(path, password)

        console._apply_console_password_rotation = delayed
    ready.set()
    if not go.wait(20):
        return
    try:
        console.rotate_console_password(
            console.PasswordRotateRequest(
                current_password=OLD_PASSWORD,
                new_password=NEW_PASSWORD if actor == "A" else "LaterSyntheticPasswordA7",
                confirm=NEW_PASSWORD if actor == "A" else "LaterSyntheticPasswordA7",
            ),
            request,
            session=session,
            audit=_FakeAudit(),
            settings=settings,
            principal=_principal(),
        )
        results.put((actor, "success", session.commits))
    except Exception as error:
        results.put((actor, type(error).__name__, session.commits))


def _provider_actor(env, database, actor, ready, go, entered, release, results):
    from kp_database.models import AiGenerationProvider, CipherText
    from test_ai_providers import _Audit, _principal, _request, _settings

    CipherText.configure_key(b"r" * 32)
    engine = _sqlite_provider_engine(database)
    settings = _settings(Path(env))
    settings.ai_model_id = "stale-process-pin"
    with Session(engine, expire_on_commit=False) as session:
        cached = list(session.query(AiGenerationProvider))
        session.commit()  # release read transaction, retain strongly referenced stale ORM objects
        if actor == "A":
            original = ai_providers._apply_provider_side_effects

            def delayed(*args, **kwargs):
                entered.set()
                if not release.wait(20):
                    raise RuntimeError("test release missing")
                original(*args, **kwargs)

            ai_providers._apply_provider_side_effects = delayed
        ready.set()
        if not go.wait(20):
            return
        try:
            ai_providers.save_ai_provider(
                "anthropic",
                ai_providers.ProviderSaveRequest(
                    api_key="synthetic-new-provider-key" if actor == "A" else "",
                    model_id=None if actor == "A" else "newer-reviewed-model",
                ),
                request=_request(Path(env)),
                session=session,
                audit=_Audit(),
                principal=_principal(),
            )
            response = ai_providers.select_ai_provider(
                ai_providers.ProviderSelectRequest(provider="openai" if actor == "A" else "anthropic"),
                request=_request(Path(env)),
                session=session,
                audit=_Audit(),
                settings=settings,
                principal=_principal(),
            )
            results.put((actor, "success", response["generation"], len(cached)))
        except Exception as error:
            results.put((actor, type(error).__name__, 0, len(cached)))
    engine.dispose()


def _assert_process_holds_operation_lock(settings, purpose):
    from kp_operator_api.console.private_lock import lock_path

    descriptor = os.open(lock_path(settings, purpose), os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError):
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    finally:
        os.close(descriptor)


def _finish_processes(processes, release, go):
    release.set()
    go.set()
    for process in processes:
        process.join(15)
        if process.is_alive():
            process.terminate()
            process.join(5)


def test_two_process_password_rotation_rechecks_persisted_password_after_lock(tmp_path):
    from test_session_epoch_rotation import NEW_PASSWORD, OLD_PASSWORD

    env = tmp_path / ".env"
    env.write_text("KP_CONSOLE_PASSWORD=" + OLD_PASSWORD + "\n")
    context = multiprocessing.get_context("spawn")
    ready_a, ready_b, go_a, go_b, entered, release = [context.Event() for _ in range(6)]
    results = context.Queue()
    process_b = context.Process(target=_password_actor, args=(str(env), "B", ready_b, go_b, entered, release, results))
    process_a = context.Process(target=_password_actor, args=(str(env), "A", ready_a, go_a, entered, release, results))
    process_b.start()
    process_a.start()
    try:
        assert ready_a.wait(15) and ready_b.wait(15)
        go_a.set()
        assert entered.wait(15)  # A committed intent and is paused before application
        _assert_process_holds_operation_lock(SimpleNamespace(env_file=str(env)), "credential-operation")
        go_b.set()
        release.set()
        outcomes = [results.get(timeout=15), results.get(timeout=15)]
        assert sorted((actor, status) for actor, status, _ in outcomes) == [
            ("A", "success"),
            ("B", "AuthenticationError"),
        ]
        assert next(commits for actor, _, commits in outcomes if actor == "B") == 0
        assert console._verify_console_password(env, NEW_PASSWORD)
        assert not console._verify_console_password(env, "LaterSyntheticPasswordA7")
    finally:
        _finish_processes([process_a, process_b], release, go_b)


def test_two_process_provider_selection_keeps_newest_key_pin_and_generation(tmp_path):
    from kp_database.models import CipherText
    from sqlalchemy import text

    env, database = tmp_path / ".env", tmp_path / "providers.db"
    env.write_text("KP_WORKER_AI_MODEL_ID=local-reviewed-model\n")
    engine = _sqlite_provider_engine(database)
    # PostgreSQL's partial unique index is expressed equivalently for SQLite;
    # no production schema/index object is changed for this hermetic exercise.
    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE TABLE ai_generation_providers(provider TEXT PRIMARY KEY,api_key BLOB,"
                "model_id TEXT,base_url TEXT,is_active BOOLEAN NOT NULL DEFAULT 0,updated_at DATETIME DEFAULT(now()))"
            )
        )
        connection.execute(
            text("CREATE UNIQUE INDEX single_active ON ai_generation_providers(is_active) WHERE is_active=1")
        )
    ProviderConfigGeneration.__table__.create(engine)
    previous = (CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys)
    CipherText.configure_key(b"r" * 32)
    from kp_database.models import AiGenerationProvider

    with Session(engine) as session:
        session.add_all(
            [
                AiGenerationProvider(
                    provider=provider, api_key="synthetic-old-key", model_id=provider + "-model", is_active=False
                )
                for provider in ("openai", "anthropic")
            ]
        )
        session.commit()
    engine.dispose()
    context = multiprocessing.get_context("spawn")
    ready_a, ready_b, go_a, go_b, entered, release = [context.Event() for _ in range(6)]
    results = context.Queue()
    process_b = context.Process(
        target=_provider_actor, args=(str(env), str(database), "B", ready_b, go_b, entered, release, results)
    )
    process_a = context.Process(
        target=_provider_actor, args=(str(env), str(database), "A", ready_a, go_a, entered, release, results)
    )
    process_b.start()
    process_a.start()
    try:
        assert ready_a.wait(15) and ready_b.wait(15)
        go_a.set()
        assert entered.wait(15)  # A committed generation1 but has not written marker/state/env
        _assert_process_holds_operation_lock(SimpleNamespace(env_file=str(env)), "provider-operation")
        go_b.set()
        release.set()
        outcomes = [results.get(timeout=15), results.get(timeout=15)]
        assert sorted((actor, status, generation) for actor, status, generation, _ in outcomes) == [
            ("A", "success", 1),
            ("B", "success", 2),
        ]
        settings = SimpleNamespace(env_file=str(env))
        state = json.loads(ai_providers._state_path(settings).read_text())
        assert (state["provider"], state["generation"], state["api_key"], state["model_id"]) == (
            "anthropic",
            2,
            "synthetic-new-provider-key",
            "newer-reviewed-model",
        )
        assert ai_providers._env_values(env)["KP_WORKER_AI_MODEL_ID"] == "newer-reviewed-model"
        engine = _sqlite_provider_engine(database)
        with Session(engine) as session:
            generation = session.get(ProviderConfigGeneration, 1)
            assert generation.generation == generation.applied_generation == 2
        engine.dispose()
    finally:
        _finish_processes([process_a, process_b], release, go_b)
        CipherText._active_key_id, CipherText._active_key, CipherText._prior_keys = previous

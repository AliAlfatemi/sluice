"""Fail-first contract for singleton request ordering across restart."""

from __future__ import annotations

import json
from pathlib import Path
import socket
import sqlite3

import pytest

from sluice_v2.durable_secure import DurableSecureDomain
from sluice_v2.durable_service import (
    MonitorCacheError,
    MonitorServiceConfig,
    _DurableRequestCache,
    connect_model,
)
from sluice_v2.tests.test_v18_durable_singleton_service import (
    CALLER_KEY,
    REAUTH_KEY,
    _abstract,
    _attempt,
    _fork_monitor,
    _make_domain,
    _opener,
    _peer,
    _terminate,
    _wait_exit,
)


def test_unresolved_preexecution_request_owns_its_sequence_after_restart(
    tmp_path: Path,
) -> None:
    """A novel request may not steal a pre-crash PENDING request's slot."""

    path = tmp_path / "pending-order.sqlite3"
    templates, _ = _make_domain(path)
    handlers = {"release-v1": lambda payload: int(payload["slot"])}

    first_address = _abstract("pending-order-one")
    first_pid = _fork_monitor(
        path=path,
        address=first_address,
        templates=templates,
        handler_registry=handlers,
        crash_stage="after_pending_before_domain",
    )
    channel = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    channel.connect(first_address)
    channel.send(
        json.dumps(_attempt("request-A", 11).to_wire(), separators=(",", ":")).encode(
            "ascii"
        )
    )
    assert channel.recv(4096) == b""
    channel.close()
    _wait_exit(first_pid, 73)

    second_address = _abstract("pending-order-two")
    second_pid = _fork_monitor(
        path=path,
        address=second_address,
        templates=templates,
        handler_registry=handlers,
    )
    try:
        # B is well-formed but must not be assigned A's unresolved sequence.
        with pytest.raises((ConnectionError, EOFError, OSError)):
            connect_model(
                second_address,
                _attempt("request-B", 12),
                expected_monitor=_peer(second_pid),
            )

        with sqlite3.connect(path) as connection:
            rows = connection.execute(
                "SELECT request_id, state, expected_sequence "
                "FROM sluice_monitor_request_cache ORDER BY request_id"
            ).fetchall()
        assert rows == [("request-A", "PENDING", 1)]

        original = connect_model(
            second_address,
            _attempt("request-A", 11),
            expected_monitor=_peer(second_pid),
        )
        assert (original.sequence, original.value_code) == (1, 11)

        later = connect_model(
            second_address,
            _attempt("request-B", 12),
            expected_monitor=_peer(second_pid),
        )
        assert (later.sequence, later.value_code) == (2, 12)
    finally:
        _terminate(second_pid)

    domain = DurableSecureDomain.reopen(
        path,
        agent_keys={"worker": CALLER_KEY},
        reauthorization_keys={"admin": REAUTH_KEY},
        handler_registry=handlers,
    )
    try:
        assert domain.attempts_used == 2
        assert [(event.sequence, event.value_code) for event in domain.transcript] == [
            (1, 11),
            (2, 12),
        ]
    finally:
        domain.close()


def test_startup_rejects_legacy_duplicate_sequence_owners(tmp_path: Path) -> None:
    """Adding the sequence index must fail closed on an ambiguous old cache."""

    path = tmp_path / "duplicate-sequence.sqlite3"
    templates, _ = _make_domain(path)
    handlers = {"release-v1": lambda payload: int(payload["slot"])}
    config = MonitorServiceConfig(
        address=_abstract("duplicate-sequence"),
        opener=_opener(path, handlers),
        templates=templates,
        expected_model=_peer(),
    )
    _DurableRequestCache(path, config.binding_sha256)

    with sqlite3.connect(path) as connection:
        connection.execute("DROP INDEX sluice_monitor_expected_sequence_unique")
        connection.executemany(
            "INSERT INTO sluice_monitor_request_cache VALUES (?,?,?,?,?,NULL)",
            (
                ("legacy-A", 1, 11, "PENDING", 1),
                ("legacy-B", 1, 12, "PENDING", 1),
            ),
        )

    with pytest.raises(MonitorCacheError, match="conflicting sequence owners"):
        _DurableRequestCache(path, config.binding_sha256)

    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='index' AND name='sluice_monitor_expected_sequence_unique'"
        ).fetchone() == (0,)

"""Transactional storage for the Sluice reference monitor.

Security decisions use exact integer microbit columns.  Human-readable REAL
columns are mirrors only.  A gate's object, epoch, and charge are committed in
the gate row when it is authored; the atomic claim API accepts only a gate ID,
so a caller cannot substitute a cheaper cost or a different budget row.

SQLite supplies crash atomicity and cross-process locking.  The Python lock
additionally serializes access to the one connection shared by threads in a
``DurableStore`` instance.  The default rollback journal is portable to the
NFS-backed research filesystem; experiments may explicitly request WAL or
unsafe synchronous modes, and record the effective PRAGMAs.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_FLOOR
from enum import Enum
from typing import Any, Dict, Optional

ACCOUNTING_SCALE = 1_000_000
MAX_ACCOUNTING_UNITS = (1 << 63) - 1
SCHEMA_VERSION = 5
GENESIS_HASH = "0" * 64


class StoreInvariantError(RuntimeError):
    """The durable state cannot safely satisfy the current schema."""


class ReplayError(Exception):
    pass


def _bits_to_units(bits: float, rounding: str, field_name: str) -> int:
    if isinstance(bits, bool) or not isinstance(bits, (int, float, Decimal)):
        raise ValueError(f"{field_name} must be a finite non-negative number")
    try:
        # Configuration floats cross a text/API boundary.  Interpret the
        # shortest round-trippable decimal spelling, so a value returned by
        # units_to_bits() maps back to the same integer number of microbits.
        # Decimal.from_float() made e.g. 2.321929 one microbit too small when
        # used as a cap, even though it is the public spelling of 2_321_929
        # microbits.  Values just below a boundary retain their longer repr.
        decimal = Decimal(str(bits)) if isinstance(bits, float) else Decimal(bits)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a finite non-negative number") from exc
    if not decimal.is_finite() or decimal < 0:
        raise ValueError(f"{field_name} must be a finite non-negative number")
    units = int(
        (decimal * ACCOUNTING_SCALE).to_integral_value(rounding=rounding)
    )
    if units > MAX_ACCOUNTING_UNITS:
        raise ValueError(f"{field_name} exceeds SQLite's exact accounting range")
    return units


def cap_bits_to_units(bits: float) -> int:
    """Round a configured cap downward to exact integer accounting units."""
    return _bits_to_units(bits, ROUND_FLOOR, "cap_bits")


def charge_bits_to_units(bits: float) -> int:
    """Round a charge upward to exact integer accounting units."""
    return _bits_to_units(bits, ROUND_CEILING, "charge_bits")


def _require_units(value: int, field_name: str, *, positive: bool = False) -> int:
    # SQLite uses dynamic typing even for INTEGER-affinity columns.  Never
    # coerce values read from durable security state: e.g. ``int(0.9)`` would
    # otherwise turn a corrupted REAL epoch or spend into a valid zero.
    if type(value) is not int:
        raise ValueError(f"{field_name} must be an integer accounting value")
    minimum = 1 if positive else 0
    if value < minimum or value > MAX_ACCOUNTING_UNITS:
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(
            f"{field_name} must be a {qualifier} signed-64-bit accounting value"
        )
    return value


def _require_epoch(value: int, field_name: str = "policy_epoch") -> int:
    if type(value) is not int or value < 0 or value > MAX_ACCOUNTING_UNITS:
        raise StoreInvariantError(
            f"{field_name} must be a non-negative signed-64-bit integer"
        )
    return value


def _require_flag(value: int, field_name: str) -> int:
    if type(value) is not int or value not in (0, 1):
        raise StoreInvariantError(f"{field_name} must be the integer 0 or 1")
    return value


def units_to_bits(units: int) -> float:
    return _require_units(units, "units") / ACCOUNTING_SCALE


SCHEMA_STATEMENTS = (
    """
    CREATE TABLE IF NOT EXISTS gates (
      gate_id TEXT PRIMARY KEY,
      record_json TEXT NOT NULL,
      digest TEXT NOT NULL,
      protected_object TEXT NOT NULL,
      policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' AND policy_epoch >= 0),
      authorized_cost_units INTEGER NOT NULL CHECK(typeof(authorized_cost_units)='integer' AND authorized_cost_units > 0),
      consumed INTEGER NOT NULL DEFAULT 0 CHECK(typeof(consumed)='integer' AND consumed IN (0,1)),
      created_at REAL NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS budgets (
      protected_object TEXT NOT NULL,
      policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' AND policy_epoch >= 0),
      spent_bits REAL NOT NULL DEFAULT 0,
      cap_bits REAL NOT NULL,
      spent_units INTEGER NOT NULL DEFAULT 0 CHECK(typeof(spent_units)='integer' AND spent_units >= 0),
      cap_units INTEGER NOT NULL CHECK(typeof(cap_units)='integer' AND cap_units >= 0),
      reauth_required INTEGER NOT NULL DEFAULT 0 CHECK(typeof(reauth_required)='integer' AND reauth_required IN (0,1)),
      CHECK(spent_units <= cap_units),
      PRIMARY KEY (protected_object, policy_epoch)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS object_epochs (
      protected_object TEXT PRIMARY KEY,
      current_epoch INTEGER NOT NULL CHECK(typeof(current_epoch)='integer' AND current_epoch >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS audit_log (
      seq INTEGER PRIMARY KEY AUTOINCREMENT,
      ts REAL NOT NULL,
      gate_id TEXT,
      event TEXT NOT NULL,
      detail_json TEXT NOT NULL,
      prev_hash TEXT NOT NULL,
      entry_hash TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS monitor_meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS reauth_grants (
      grant_id TEXT PRIMARY KEY,
      protected_object TEXT NOT NULL,
      previous_epoch INTEGER NOT NULL CHECK(typeof(previous_epoch)='integer' AND previous_epoch >= 0),
      new_epoch INTEGER NOT NULL CHECK(typeof(new_epoch)='integer' AND new_epoch = previous_epoch + 1),
      new_cap_bits REAL NOT NULL,
      new_cap_units INTEGER NOT NULL CHECK(typeof(new_cap_units)='integer' AND new_cap_units >= 0),
      authorizer_identity TEXT NOT NULL,
      signature TEXT NOT NULL,
      issued_at REAL NOT NULL,
      consumed INTEGER NOT NULL DEFAULT 1 CHECK(typeof(consumed)='integer' AND consumed IN (0,1))
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS action_capabilities (
      capability_id TEXT PRIMARY KEY,
      gate_id TEXT NOT NULL,
      protected_object TEXT NOT NULL,
      policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' AND policy_epoch >= 0),
      action_json TEXT NOT NULL,
      args_json TEXT NOT NULL,
      capability_tag TEXT NOT NULL,
      consumed INTEGER NOT NULL DEFAULT 0 CHECK(typeof(consumed)='integer' AND consumed IN (0,1)),
      created_at REAL NOT NULL,
      redeemer_agent_id TEXT,
      FOREIGN KEY(gate_id) REFERENCES gates(gate_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS object_sequence (
      protected_object TEXT NOT NULL,
      workflow_id TEXT NOT NULL,
      policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' AND policy_epoch >= 0),
      last_gate_id TEXT NOT NULL,
      chain_opted_in INTEGER NOT NULL DEFAULT 0 CHECK(chain_opted_in IN (0,1)),
      PRIMARY KEY (protected_object, workflow_id, policy_epoch)
    )
    """,
    """
    -- One-time redemption ledger for single-hop delegation grants
    -- (monitor.py's DelegationGrant, multi-agent workflows). A grant_id
    -- present here has already been redeemed; a second redemption attempt
    -- for the same grant_id -- whether a genuine retry, a race between
    -- concurrent redeemers, or a colluding agent replaying an intercepted
    -- grant -- is rejected here even though the grant's HMAC signature
    -- would still independently verify.
    CREATE TABLE IF NOT EXISTS delegation_grants (
      grant_id TEXT PRIMARY KEY,
      delegator_agent_id TEXT NOT NULL,
      delegate_agent_id TEXT NOT NULL,
      gate_id TEXT NOT NULL,
      redeemed_at REAL NOT NULL
    )
    """,
    """
    -- One-time consumption ledger for CallerCredential nonces
    -- (monitor.py's issue_call_credential/_verify_call_credential,
    -- multi-agent workflows). A (agent_id, nonce) pair present here has
    -- already been consumed; a second presentation of the same credential
    -- -- whether a genuine retry or a captured-and-replayed credential --
    -- is rejected here even though its signature and expiry would still
    -- independently verify. Scoped per agent_id, not global, so two
    -- different agents' independently-generated nonces can never collide.
    CREATE TABLE IF NOT EXISTS consumed_call_nonces (
      agent_id TEXT NOT NULL,
      nonce TEXT NOT NULL,
      consumed_at REAL NOT NULL,
      PRIMARY KEY (agent_id, nonce)
    )
    """,
    """
    -- Reverse index of allowed_successor_gates, populated once at authoring
    -- time (put_gate_and_initialize_budget), not derived at claim time. A
    -- gate present here exists to be reached only via the declared
    -- (predecessor, successor) relationship named by the row, never as a
    -- free-standing entry point on an (object, epoch) with no recorded
    -- predecessor yet -- see claim_and_reserve_gate's use of this table.
    CREATE TABLE IF NOT EXISTS declared_successors (
      protected_object TEXT NOT NULL,
      workflow_id TEXT NOT NULL,
      policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' AND policy_epoch >= 0),
      successor_gate_id TEXT NOT NULL,
      predecessor_gate_id TEXT NOT NULL,
      PRIMARY KEY (
        protected_object, workflow_id, policy_epoch,
        successor_gate_id, predecessor_gate_id
      )
    )
    """,
)


class ClaimStatus(str, Enum):
    CLAIMED = "claimed"
    REPLAYED = "replayed"
    BUDGET_EXHAUSTED = "budget_exhausted"
    STALE_EPOCH = "stale_epoch"
    UNAUTHORIZED_SUCCESSOR = "unauthorized_successor"
    AUTH_REPLAYED = "auth_replayed"
    AUTH_INVALID = "auth_invalid"


@dataclass(frozen=True)
class PreparedAuthorization:
    """Purely verified authorization material committed with a gate claim.

    Cryptographic verification happens in the monitor before this value is
    constructed.  The store owns the one-time decision: nonce/grant rows are
    inserted only in the same transaction that successfully claims the gate,
    reserves budget, advances sequencing, and writes audit-start evidence.
    """

    agent_id: str
    nonce: str
    gate_id: str
    workflow_id: str
    policy_epoch: int
    expires_at: float
    grant_id: Optional[str] = None
    delegator_agent_id: Optional[str] = None
    delegate_agent_id: Optional[str] = None
    delegation_expires_at: Optional[float] = None

    def validate_for_scope(
        self, gate_id: str, workflow_id: str, policy_epoch: int
    ) -> None:
        if not all(
            isinstance(value, str) and value
            for value in (self.agent_id, self.nonce, self.gate_id, gate_id)
        ):
            raise ValueError("authorization identifiers must be non-empty strings")
        if not isinstance(self.workflow_id, str) or not isinstance(workflow_id, str):
            raise ValueError("authorization workflow identifiers must be strings")
        if (
            type(self.policy_epoch) is not int
            or type(policy_epoch) is not int
            or self.policy_epoch < 0
            or policy_epoch < 0
        ):
            raise ValueError("authorization epochs must be non-negative integers")
        if (
            self.gate_id != gate_id
            or self.workflow_id != workflow_id
            or self.policy_epoch != policy_epoch
        ):
            raise ValueError("authorization scope differs from the claimed operation")
        if (
            isinstance(self.expires_at, bool)
            or not isinstance(self.expires_at, (int, float))
            or not math.isfinite(self.expires_at)
        ):
            raise ValueError("authorization expiry must be finite")
        grant_fields = (
            self.grant_id,
            self.delegator_agent_id,
            self.delegate_agent_id,
        )
        if any(value is not None for value in grant_fields):
            if not all(isinstance(value, str) and value for value in grant_fields):
                raise ValueError("delegation authorization must be complete")
            if self.delegate_agent_id != self.agent_id:
                raise ValueError("delegation delegate must match credential agent")
            if self.delegation_expires_at is not None and (
                isinstance(self.delegation_expires_at, bool)
                or not isinstance(self.delegation_expires_at, (int, float))
                or not math.isfinite(self.delegation_expires_at)
            ):
                raise ValueError("delegation expiry must be finite or None")
        elif self.delegation_expires_at is not None:
            raise ValueError("delegation expiry requires a delegation grant")


# Authoritative home for the fanout bound and the selection-charge table:
# claim_and_reserve_gate() now resolves successor authorization and its
# fanout *inside* the same atomic transaction as the budget claim (see
# below), so this module -- not monitor.py -- is where that charge must be
# computed. monitor.py imports these names rather than redefining them.
ABSOLUTE_MAX_CARDINALITY = 32

# Reviewed exact values of ceil(10^6 * log2(K)) for K=1..32, generated with
# high-precision Decimal logarithms and checked by the exact integer
# inequalities 2^(u-1) < K^10^6 <= 2^u. Selection charges are over
# publicly committed gate identities, not a typed decode outcome, so their
# support is exactly the fanout N, not N+4.
_SELECTION_COST_UNITS = (
    0, 1_000_000, 1_584_963, 2_000_000,
    2_321_929, 2_584_963, 2_807_355, 3_000_000,
    3_169_926, 3_321_929, 3_459_432, 3_584_963,
    3_700_440, 3_807_355, 3_906_891, 4_000_000,
    4_087_463, 4_169_926, 4_247_928, 4_321_929,
    4_392_318, 4_459_432, 4_523_562, 4_584_963,
    4_643_857, 4_700_440, 4_754_888, 4_807_355,
    4_857_981, 4_906_891, 4_954_197, 5_000_000,
)


def selection_cost_units(fanout: int) -> int:
    """Exact table lookup for ``ceil(10^6 * log2(fanout))`` microbits."""
    if (
        isinstance(fanout, bool)
        or not isinstance(fanout, int)
        or not 1 <= fanout <= ABSOLUTE_MAX_CARDINALITY
    ):
        raise ValueError(
            f"fanout must be an integer in [1, {ABSOLUTE_MAX_CARDINALITY}]"
        )
    return _SELECTION_COST_UNITS[fanout - 1]


@dataclass(frozen=True)
class ClaimResult:
    status: ClaimStatus
    protected_object: str
    policy_epoch: int
    authorized_cost_units: int
    spent_before_units: int
    spent_after_units: int
    cap_units: int

    @property
    def authorized_cost_bits(self) -> float:
        return units_to_bits(self.authorized_cost_units)

    @property
    def spent_before(self) -> float:
        return units_to_bits(self.spent_before_units)

    @property
    def spent_after(self) -> float:
        return units_to_bits(self.spent_after_units)

    @property
    def cap_bits(self) -> float:
        return units_to_bits(self.cap_units)


class DurableStore:
    """Durable transactional substrate used only through ``ReferenceMonitor``."""

    def __init__(
        self,
        db_path: str,
        journal_mode: str = "DELETE",
        synchronous: str = "FULL",
    ):
        journal_mode = journal_mode.upper()
        synchronous = synchronous.upper()
        if journal_mode not in {"DELETE", "TRUNCATE", "PERSIST", "MEMORY", "WAL", "OFF"}:
            raise ValueError(f"unsupported SQLite journal_mode {journal_mode!r}")
        if synchronous not in {"OFF", "NORMAL", "FULL", "EXTRA"}:
            raise ValueError(f"unsupported SQLite synchronous mode {synchronous!r}")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(
            db_path, isolation_level=None, check_same_thread=False, timeout=30.0
        )
        try:
            self._conn.execute("PRAGMA busy_timeout=30000")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute(f"PRAGMA journal_mode={journal_mode}")
            self._conn.execute(f"PRAGMA synchronous={synchronous}")
            self._initialize_schema()
        except BaseException:
            try:
                self._conn.close()
            except BaseException:
                pass
            raise

    def _initialize_schema(self) -> None:
        """Create/migrate under one cross-process exclusive transaction."""
        with self._lock:
            self._conn.execute("BEGIN EXCLUSIVE")
            try:
                previous_version = int(
                    self._conn.execute("PRAGMA user_version").fetchone()[0]
                )
                if previous_version > SCHEMA_VERSION:
                    raise StoreInvariantError(
                        f"database schema {previous_version} is newer than supported "
                        f"schema {SCHEMA_VERSION}"
                    )
                for statement in SCHEMA_STATEMENTS:
                    self._conn.execute(statement)
                self._migrate_legacy_schema(self._conn, previous_version)
                self._validate_and_repair_mirrors(self._conn)
                self._conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
                self._conn.execute("COMMIT")
            except BaseException:
                try:
                    self._conn.execute("ROLLBACK")
                except BaseException:
                    # A connection whose rollback failed cannot safely be
                    # reused for subsequent security decisions.
                    try:
                        self._conn.close()
                    except BaseException:
                        pass
                raise

    @staticmethod
    def _columns(conn: sqlite3.Connection, table: str) -> set[str]:
        return {str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")}

    def _migrate_legacy_schema(self, conn: sqlite3.Connection, previous_version: int) -> None:
        gate_columns = self._columns(conn, "gates")
        for column, declaration in (
            ("protected_object", "TEXT"),
            ("policy_epoch", "INTEGER"),
            ("authorized_cost_units", "INTEGER"),
        ):
            if column not in gate_columns:
                conn.execute(f"ALTER TABLE gates ADD COLUMN {column} {declaration}")
        incomplete_gates = int(
            conn.execute(
                "SELECT COUNT(*) FROM gates WHERE protected_object IS NULL "
                "OR policy_epoch IS NULL OR authorized_cost_units IS NULL"
            ).fetchone()[0]
        )
        if incomplete_gates:
            raise StoreInvariantError(
                "legacy gate rows cannot be safely migrated because their authoritative "
                "object/epoch/cost fields were not committed separately; archive this "
                "database and re-author fresh gates"
            )

        budget_columns = self._columns(conn, "budgets")
        added_budget_units = False
        if "spent_units" not in budget_columns:
            conn.execute("ALTER TABLE budgets ADD COLUMN spent_units INTEGER")
            added_budget_units = True
        if "cap_units" not in budget_columns:
            conn.execute("ALTER TABLE budgets ADD COLUMN cap_units INTEGER")
            added_budget_units = True
        if added_budget_units or previous_version < 3:
            rows = conn.execute(
                "SELECT protected_object, policy_epoch, spent_bits, cap_bits FROM budgets"
            ).fetchall()
            for protected_object, epoch, spent_bits, cap_bits in rows:
                exact_spent = charge_bits_to_units(spent_bits)
                exact_cap = cap_bits_to_units(cap_bits)
                if exact_spent > exact_cap:
                    raise StoreInvariantError(
                        "legacy floating-point budget cannot be conservatively migrated "
                        f"for ({protected_object!r}, {epoch}): rounded spend exceeds "
                        "rounded cap; archive the database and reauthorize a fresh epoch"
                    )
                conn.execute(
                    "UPDATE budgets SET spent_units=?, cap_units=? "
                    "WHERE protected_object=? AND policy_epoch=?",
                    (exact_spent, exact_cap, protected_object, epoch),
                )

        grant_columns = self._columns(conn, "reauth_grants")
        grants_exist = bool(conn.execute("SELECT 1 FROM reauth_grants LIMIT 1").fetchone())
        if "previous_epoch" not in grant_columns:
            if grants_exist:
                raise StoreInvariantError(
                    "legacy reauthorization rows did not bind a previous epoch and "
                    "cannot be safely migrated"
                )
            conn.execute("ALTER TABLE reauth_grants ADD COLUMN previous_epoch INTEGER")
        if "new_cap_units" not in grant_columns:
            if grants_exist:
                raise StoreInvariantError(
                    "legacy reauthorization rows did not bind exact cap units and "
                    "cannot be safely migrated"
                )
            conn.execute("ALTER TABLE reauth_grants ADD COLUMN new_cap_units INTEGER")

        conn.execute(
            "INSERT OR IGNORE INTO object_epochs(protected_object, current_epoch) "
            "SELECT protected_object, MAX(policy_epoch) FROM budgets GROUP BY protected_object"
        )
        self._migrate_scoped_successor_state(conn)

    @staticmethod
    def _workflow_from_record(record_json: str, gate_id: str) -> str:
        try:
            record = json.loads(record_json)
            workflow_id = record["workflow_id"]
        except (TypeError, ValueError, KeyError) as exc:
            raise StoreInvariantError(
                f"gate {gate_id!r} has no recoverable workflow scope"
            ) from exc
        if not isinstance(workflow_id, str) or not workflow_id:
            raise StoreInvariantError(
                f"gate {gate_id!r} has an invalid workflow scope"
            )
        return workflow_id

    def _migrate_scoped_successor_state(self, conn: sqlite3.Connection) -> None:
        """Rebuild v4's global successor/sequence tables with v5 scope.

        SQLite cannot alter a primary key.  Scope is recovered only from the
        authenticated predecessor/last-gate record; a row whose scope cannot
        be established aborts the entire migration instead of being guessed.
        """
        sequence_columns = self._columns(conn, "object_sequence")
        if "workflow_id" not in sequence_columns:
            rows = conn.execute(
                "SELECT protected_object, policy_epoch, last_gate_id, "
                "chain_opted_in FROM object_sequence"
            ).fetchall()
            conn.execute(
                "CREATE TABLE object_sequence_v5 ("
                "protected_object TEXT NOT NULL, workflow_id TEXT NOT NULL, "
                "policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' "
                "AND policy_epoch >= 0), last_gate_id TEXT NOT NULL, "
                "chain_opted_in INTEGER NOT NULL DEFAULT 0 "
                "CHECK(chain_opted_in IN (0,1)), PRIMARY KEY "
                "(protected_object, workflow_id, policy_epoch))"
            )
            for protected_object, epoch, last_gate_id, opted_in in rows:
                gate = conn.execute(
                    "SELECT record_json, protected_object, policy_epoch FROM gates "
                    "WHERE gate_id=?",
                    (last_gate_id,),
                ).fetchone()
                if gate is None or gate[1] != protected_object or gate[2] != epoch:
                    raise StoreInvariantError(
                        "legacy sequence row has no exact scoped last gate"
                    )
                workflow_id = self._workflow_from_record(gate[0], last_gate_id)
                conn.execute(
                    "INSERT INTO object_sequence_v5 VALUES (?,?,?,?,?)",
                    (protected_object, workflow_id, epoch, last_gate_id, opted_in),
                )
            conn.execute("DROP TABLE object_sequence")
            conn.execute("ALTER TABLE object_sequence_v5 RENAME TO object_sequence")

        successor_columns = self._columns(conn, "declared_successors")
        if not {"protected_object", "workflow_id", "policy_epoch"}.issubset(
            successor_columns
        ):
            rows = conn.execute(
                "SELECT successor_gate_id, predecessor_gate_id "
                "FROM declared_successors"
            ).fetchall()
            conn.execute(
                "CREATE TABLE declared_successors_v5 ("
                "protected_object TEXT NOT NULL, workflow_id TEXT NOT NULL, "
                "policy_epoch INTEGER NOT NULL CHECK(typeof(policy_epoch)='integer' "
                "AND policy_epoch >= 0), successor_gate_id TEXT NOT NULL, "
                "predecessor_gate_id TEXT NOT NULL, PRIMARY KEY "
                "(protected_object, workflow_id, policy_epoch, "
                "successor_gate_id, predecessor_gate_id))"
            )
            migrated_predecessors: Dict[tuple[str, str, int, str], str] = {}
            for successor_gate_id, predecessor_gate_id in rows:
                predecessor = conn.execute(
                    "SELECT record_json, protected_object, policy_epoch FROM gates "
                    "WHERE gate_id=?",
                    (predecessor_gate_id,),
                ).fetchone()
                if predecessor is None:
                    raise StoreInvariantError(
                        "legacy successor row references an unknown predecessor"
                    )
                workflow_id = self._workflow_from_record(
                    predecessor[0], predecessor_gate_id
                )
                scope_key = (
                    predecessor[1],
                    workflow_id,
                    predecessor[2],
                    successor_gate_id,
                )
                previous_predecessor = migrated_predecessors.get(scope_key)
                if (
                    previous_predecessor is not None
                    and previous_predecessor != predecessor_gate_id
                ):
                    raise StoreInvariantError(
                        "legacy successor state has conflicting predecessors "
                        "inside one security scope; archive and re-author gates"
                    )
                migrated_predecessors[scope_key] = predecessor_gate_id
                conn.execute(
                    "INSERT INTO declared_successors_v5 VALUES (?,?,?,?,?)",
                    (
                        predecessor[1],
                        workflow_id,
                        predecessor[2],
                        successor_gate_id,
                        predecessor_gate_id,
                    ),
                )
            conn.execute("DROP TABLE declared_successors")
            conn.execute(
                "ALTER TABLE declared_successors_v5 RENAME TO declared_successors"
            )

    def _validate_and_repair_mirrors(self, conn: sqlite3.Connection) -> None:
        bad_budget = conn.execute(
            "SELECT protected_object, policy_epoch FROM budgets WHERE "
            "typeof(policy_epoch) != 'integer' OR policy_epoch < 0 OR "
            "typeof(spent_units) != 'integer' OR spent_units < 0 OR "
            "typeof(cap_units) != 'integer' OR cap_units < 0 OR "
            "spent_units > cap_units OR typeof(reauth_required) != 'integer' OR "
            "reauth_required NOT IN (0,1) LIMIT 1"
        ).fetchone()
        if bad_budget:
            raise StoreInvariantError(f"invalid exact budget row {tuple(bad_budget)!r}")

        for protected_object, epoch, spent_units, cap_units in conn.execute(
            "SELECT protected_object, policy_epoch, spent_units, cap_units FROM budgets"
        ).fetchall():
            _require_units(spent_units, "stored spent_units")
            _require_units(cap_units, "stored cap_units")
            conn.execute(
                "UPDATE budgets SET spent_bits=?, cap_bits=?, reauth_required=? "
                "WHERE protected_object=? AND policy_epoch=?",
                (
                    units_to_bits(spent_units),
                    units_to_bits(cap_units),
                    int(spent_units >= cap_units),
                    protected_object,
                    epoch,
                ),
            )

        invalid_sequence = conn.execute(
            "SELECT last_gate_id FROM object_sequence WHERE protected_object='' "
            "OR workflow_id='' OR typeof(policy_epoch) != 'integer' "
            "OR policy_epoch < 0 OR typeof(chain_opted_in) != 'integer' "
            "OR chain_opted_in NOT IN (0,1) LIMIT 1"
        ).fetchone()
        if invalid_sequence:
            raise StoreInvariantError("invalid scoped sequence row")
        invalid_successor = conn.execute(
            "SELECT predecessor_gate_id FROM declared_successors "
            "WHERE protected_object='' OR workflow_id='' "
            "OR typeof(policy_epoch) != 'integer' OR policy_epoch < 0 "
            "OR successor_gate_id='' OR predecessor_gate_id='' LIMIT 1"
        ).fetchone()
        if invalid_successor:
            raise StoreInvariantError("invalid scoped successor declaration")

        invalid_gate = conn.execute(
            "SELECT gate_id FROM gates WHERE protected_object IS NULL OR "
            "typeof(policy_epoch) != 'integer' OR policy_epoch < 0 OR "
            "typeof(authorized_cost_units) != 'integer' OR authorized_cost_units <= 0 "
            "OR typeof(consumed) != 'integer' OR consumed NOT IN (0,1) LIMIT 1"
        ).fetchone()
        if invalid_gate:
            raise StoreInvariantError(f"invalid gate accounting row {invalid_gate[0]!r}")

        capability_columns = self._columns(conn, "action_capabilities")
        for column, declaration in (
            ("protected_object", "TEXT"),
            ("policy_epoch", "INTEGER"),
            ("action_json", "TEXT"),
            ("args_json", "TEXT"),
            ("redeemer_agent_id", "TEXT"),
        ):
            if column not in capability_columns:
                conn.execute(
                    f"ALTER TABLE action_capabilities ADD COLUMN {column} {declaration}"
                )
        incomplete_capabilities = int(
            conn.execute(
                "SELECT COUNT(*) FROM action_capabilities WHERE protected_object IS NULL "
                "OR policy_epoch IS NULL OR action_json IS NULL OR args_json IS NULL"
            ).fetchone()[0]
        )
        if incomplete_capabilities:
            raise StoreInvariantError(
                "legacy action capabilities lack an epoch binding and must be discarded "
                "before this database can be reopened"
            )
        invalid_capability = conn.execute(
            "SELECT capability_id FROM action_capabilities WHERE "
            "typeof(policy_epoch) != 'integer' OR policy_epoch < 0 OR "
            "typeof(consumed) != 'integer' OR consumed NOT IN (0,1) LIMIT 1"
        ).fetchone()
        if invalid_capability:
            raise StoreInvariantError(
                f"invalid action capability row {invalid_capability[0]!r}"
            )

        invalid_grant = conn.execute(
            "SELECT grant_id FROM reauth_grants WHERE "
            "typeof(previous_epoch) != 'integer' OR previous_epoch < 0 OR "
            "typeof(new_epoch) != 'integer' OR new_epoch != previous_epoch + 1 OR "
            "typeof(new_cap_units) != 'integer' OR new_cap_units < 0 OR "
            "typeof(consumed) != 'integer' OR consumed NOT IN (0,1) LIMIT 1"
        ).fetchone()
        if invalid_grant:
            raise StoreInvariantError(
                f"invalid reauthorization row {invalid_grant[0]!r}"
            )

        objects = conn.execute(
            "SELECT protected_object, current_epoch FROM object_epochs"
        ).fetchall()
        for protected_object, current_epoch in objects:
            _require_epoch(current_epoch, f"current epoch for {protected_object!r}")
            epochs = [
                _require_epoch(row[0], f"budget epoch for {protected_object!r}")
                for row in conn.execute(
                    "SELECT policy_epoch FROM budgets WHERE protected_object=? "
                    "ORDER BY policy_epoch",
                    (protected_object,),
                ).fetchall()
            ]
            if epochs != list(range(current_epoch + 1)):
                raise StoreInvariantError(
                    f"budget epochs for {protected_object!r} are not contiguous through "
                    f"current epoch {current_epoch}"
                )

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def effective_pragmas(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "journal_mode": self._conn.execute("PRAGMA journal_mode").fetchone()[0],
                "synchronous": self._conn.execute("PRAGMA synchronous").fetchone()[0],
                "foreign_keys": self._conn.execute("PRAGMA foreign_keys").fetchone()[0],
                "user_version": self._conn.execute("PRAGMA user_version").fetchone()[0],
            }

    def get_or_create_hmac_key(self) -> bytes:
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT value FROM monitor_meta WHERE key='hmac_key'"
            ).fetchone()
            if row is not None:
                try:
                    key = bytes.fromhex(row[0])
                except (TypeError, ValueError) as exc:
                    raise StoreInvariantError("stored monitor HMAC key is malformed") from exc
                if len(key) < 32:
                    raise StoreInvariantError("stored monitor HMAC key is too short")
                return key
            import secrets

            key = secrets.token_bytes(32)
            conn.execute(
                "INSERT INTO monitor_meta(key, value) VALUES ('hmac_key', ?)",
                (key.hex(),),
            )
            return key

    @contextmanager
    def transaction(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except BaseException:
                try:
                    self._conn.execute("ROLLBACK")
                except BaseException:
                    try:
                        self._conn.close()
                    except BaseException:
                        pass
                raise

    def put_gate_and_initialize_budget(
        self,
        gate_id: str,
        record_json: str,
        digest: str,
        protected_object: str,
        epoch: int,
        cap_units: int,
        authorized_cost_units: int,
        audit_detail: Dict[str, Any],
    ) -> None:
        if not all(isinstance(value, str) and value for value in (
            gate_id, record_json, digest, protected_object
        )):
            raise ValueError("gate storage identifiers and record fields must be non-empty strings")
        if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
            raise ValueError("policy epoch must be a non-negative integer")
        cap_units = _require_units(cap_units, "cap_units")
        authorized_cost_units = _require_units(
            authorized_cost_units, "authorized_cost_units", positive=True
        )
        if not isinstance(audit_detail, dict):
            raise ValueError("gate audit detail must be a dictionary")
        try:
            stored_record = json.loads(record_json)
        except (TypeError, ValueError) as exc:
            raise ValueError("gate record_json must contain valid JSON") from exc
        workflow_id = stored_record.get("workflow_id")
        if not isinstance(workflow_id, str) or not workflow_id:
            raise ValueError("gate record must bind a non-empty workflow_id")
        if (
            stored_record.get("gate_id") != gate_id
            or stored_record.get("protected_object") != protected_object
            or stored_record.get("policy_epoch") != epoch
        ):
            raise ValueError("gate record scope differs from authoritative columns")

        with self.transaction() as conn:
            if conn.execute("SELECT 1 FROM gates WHERE gate_id=?", (gate_id,)).fetchone():
                raise ReplayError(f"gate {gate_id!r} already authored; cannot re-author")
            epoch_row = conn.execute(
                "SELECT current_epoch FROM object_epochs WHERE protected_object=?",
                (protected_object,),
            ).fetchone()
            if epoch_row is None:
                if epoch != 0:
                    raise ValueError("a protected object must start at policy epoch 0")
                conn.execute(
                    "INSERT INTO object_epochs(protected_object, current_epoch) VALUES (?,0)",
                    (protected_object,),
                )
            elif _require_epoch(epoch_row[0], "stored current epoch") != epoch:
                raise ValueError(
                    f"policy epoch {epoch} is not current for {protected_object!r} "
                    f"(current={epoch_row[0]})"
                )

            budget = conn.execute(
                "SELECT cap_units FROM budgets WHERE protected_object=? AND policy_epoch=?",
                (protected_object, epoch),
            ).fetchone()
            if budget is None:
                conn.execute(
                    "INSERT INTO budgets(protected_object, policy_epoch, spent_bits, cap_bits, "
                    "spent_units, cap_units, reauth_required) VALUES (?,?,0,?,0,?,0)",
                    (protected_object, epoch, units_to_bits(cap_units), cap_units),
                )
            elif _require_units(budget[0], "stored cap_units") != cap_units:
                raise ValueError(
                    f"conflicting cap for ({protected_object!r}, {epoch}): "
                    f"stored_units={budget[0]}, requested_units={cap_units}"
                )

            conn.execute(
                "INSERT INTO gates(gate_id, record_json, digest, protected_object, "
                "policy_epoch, authorized_cost_units, consumed, created_at) "
                "VALUES (?,?,?,?,?,?,0,?)",
                (
                    gate_id,
                    record_json,
                    digest,
                    protected_object,
                    epoch,
                    authorized_cost_units,
                    time.time(),
                ),
            )
            # Populate the reverse successor index from this gate's own
            # declared allowed_successor_gates, so each named successor is
            # marked reserved *before* anyone can attempt to claim it as a
            # free-standing entry point. This must happen at authoring time:
            # resolving "is g reserved" at claim time would require scanning
            # every gate's record_json on every claim, and doing it lazily
            # (only once a predecessor is actually consumed) would leave the
            # exact window this fix closes -- a successor claimed before its
            # predecessor ever runs, paying only its own entry_fanout charge
            # instead of the predecessor's declared selection charge.
            declared_successors = stored_record.get(
                "allowed_successor_gates"
            ) or []
            for successor_gate_id in declared_successors:
                conflicting = conn.execute(
                    "SELECT predecessor_gate_id FROM declared_successors WHERE "
                    "protected_object=? AND workflow_id=? AND policy_epoch=? "
                    "AND successor_gate_id=? AND predecessor_gate_id<>? LIMIT 1",
                    (
                        protected_object,
                        workflow_id,
                        epoch,
                        successor_gate_id,
                        gate_id,
                    ),
                ).fetchone()
                if conflicting is not None:
                    raise ValueError(
                        f"successor {successor_gate_id!r} already has a different "
                        "predecessor in this security scope"
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO declared_successors"
                    "(protected_object, workflow_id, policy_epoch, "
                    "successor_gate_id, predecessor_gate_id) VALUES (?,?,?,?,?)",
                    (
                        protected_object,
                        workflow_id,
                        epoch,
                        successor_gate_id,
                        gate_id,
                    ),
                )
            # Authorship and its audit evidence are one commit.  An audit
            # serialization/write failure rolls back the gate and budget row,
            # so callers can safely retry instead of receiving an unusable
            # half-authored capability.
            self.append_audit(
                gate_id,
                "gate_authored",
                audit_detail,
                conn=conn,
            )

    def get_gate(self, gate_id: str) -> Optional[Dict[str, Any]]:
        if not isinstance(gate_id, str):
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT record_json, digest, consumed, protected_object, policy_epoch, "
                "authorized_cost_units FROM gates WHERE gate_id=?",
                (gate_id,),
            ).fetchone()
        if row is None:
            return None
        if (
            not isinstance(row[0], str)
            or not isinstance(row[1], str)
            or type(row[2]) is not int
            or row[2] not in (0, 1)
            or not isinstance(row[3], str)
        ):
            raise StoreInvariantError(f"gate {gate_id!r} has malformed durable fields")
        _require_epoch(row[4], f"gate {gate_id!r} policy epoch")
        _require_units(row[5], f"gate {gate_id!r} authorized cost", positive=True)
        try:
            record = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise StoreInvariantError(f"gate {gate_id!r} has malformed JSON") from exc
        return {
            "record": record,
            "digest": row[1],
            "consumed": bool(row[2]),
            "protected_object": row[3],
            "policy_epoch": row[4],
            "authorized_cost_units": row[5],
        }

    def get_last_invoked_gate(
        self,
        protected_object: str,
        epoch: int,
        workflow_id: Optional[str] = None,
    ) -> Optional[str]:
        """Predecessor gate_id for successor-set/selection-charge sequencing.

        Returns ``None`` for the first charged invocation of a (protected
        object, epoch) pair, or after a reauthorization opens a fresh epoch
        (the row is keyed by epoch, so a new epoch starts with no
        predecessor -- an intentional reset, not a bug: prior-epoch spend
        already accounted for prior-epoch sequencing choices).
        """
        if not isinstance(protected_object, str) or not protected_object:
            raise ValueError("protected_object must be a non-empty string")
        epoch = _require_epoch(epoch)
        if workflow_id is not None and (
            not isinstance(workflow_id, str) or not workflow_id
        ):
            raise ValueError("workflow_id must be a non-empty string or None")
        with self._lock:
            if workflow_id is None:
                rows = self._conn.execute(
                    "SELECT last_gate_id FROM object_sequence "
                    "WHERE protected_object=? AND policy_epoch=?",
                    (protected_object, epoch),
                ).fetchall()
                if len(rows) > 1:
                    raise StoreInvariantError(
                        "workflow_id is required when multiple sequences share an object"
                    )
                row = rows[0] if rows else None
            else:
                row = self._conn.execute(
                    "SELECT last_gate_id FROM object_sequence WHERE "
                    "protected_object=? AND workflow_id=? AND policy_epoch=?",
                    (protected_object, workflow_id, epoch),
                ).fetchone()
        return row[0] if row is not None else None

    def claim_and_reserve_gate(
        self,
        gate_id: str,
        entry_fanout: int = 1,
        authorization: Optional[PreparedAuthorization] = None,
    ) -> ClaimResult:
        """Atomically claim and charge the server-committed gate metadata.

        Successor authorization is resolved *inside* this same transaction,
        not by the caller beforehand. An earlier revision had the monitor
        read the sequencing pointer, check successor membership, and
        compute the selection charge before calling this method -- three
        non-atomic steps followed by the atomic reserve. Two callers could
        each pass that pre-check against the same predecessor and then each
        independently win their own ``claim_and_reserve_gate`` call for two
        *mutually exclusive* declared successors, since neither transaction
        alone re-validated the predecessor's still-current status. Here,
        the predecessor lookup, the successor-membership check, the fanout
        computation, the resulting selection charge, the budget claim, and
        the sequencing-pointer update all happen inside one
        ``BEGIN IMMEDIATE`` transaction, so a second caller's transaction
        (necessarily serialized after the first, since SQLite's IMMEDIATE
        lock blocks concurrent writers) re-reads the pointer *after* the
        first caller's update and correctly sees the new predecessor -- not
        the stale one it would have seen under a separate pre-check.

        ``entry_fanout`` is the caller's own authenticated
        ``GateRecord.entry_fanout``, used only when this gate has no
        recorded predecessor (the first gate in a chain, or a chain that
        never declares successors); it is ignored once a predecessor with a
        nonempty ``allowed_successor_gates`` is found, in favor of that
        predecessor's own declared fanout.
        """
        if not isinstance(gate_id, str) or not gate_id:
            raise ValueError("gate_id must be a non-empty string")
        if (
            isinstance(entry_fanout, bool)
            or not isinstance(entry_fanout, int)
            or not 1 <= entry_fanout <= ABSOLUTE_MAX_CARDINALITY
        ):
            raise ValueError(
                f"entry_fanout must be an integer in [1, {ABSOLUTE_MAX_CARDINALITY}]"
            )
        if authorization is not None:
            if not isinstance(authorization, PreparedAuthorization):
                raise ValueError("authorization must be PreparedAuthorization or None")
            authorization.validate_for_scope(
                gate_id, authorization.workflow_id, authorization.policy_epoch
            )
        with self.transaction() as conn:
            gate = conn.execute(
                "SELECT consumed, protected_object, policy_epoch, authorized_cost_units, "
                "record_json "
                "FROM gates WHERE gate_id=?",
                (gate_id,),
            ).fetchone()
            if gate is None:
                raise KeyError(f"unknown gate {gate_id!r}")
            consumed, protected_object, epoch, cost_units, record_json = gate
            if (
                type(consumed) is not int
                or consumed not in (0, 1)
                or not isinstance(protected_object, str)
            ):
                raise StoreInvariantError(f"gate {gate_id!r} has invalid budget binding")
            _require_epoch(epoch, f"gate {gate_id!r} policy epoch")
            cost_units = _require_units(
                cost_units, "stored authorized_cost_units", positive=True
            )
            workflow_id = self._workflow_from_record(record_json, gate_id)
            try:
                scoped_record = json.loads(record_json)
            except (TypeError, ValueError) as exc:
                raise StoreInvariantError(
                    f"gate {gate_id!r} has malformed scoped record"
                ) from exc
            if (
                scoped_record.get("protected_object") != protected_object
                or scoped_record.get("policy_epoch") != epoch
                or scoped_record.get("gate_id") != gate_id
            ):
                raise StoreInvariantError(
                    f"gate {gate_id!r} has inconsistent durable scope"
                )
            if authorization is not None:
                authorization.validate_for_scope(gate_id, workflow_id, epoch)
            budget = conn.execute(
                "SELECT spent_units, cap_units, reauth_required FROM budgets "
                "WHERE protected_object=? AND policy_epoch=?",
                (protected_object, epoch),
            ).fetchone()
            if budget is None:
                raise StoreInvariantError(
                    f"gate {gate_id!r} references a missing budget row"
                )
            spent_units = _require_units(budget[0], "stored spent_units")
            cap_units = _require_units(budget[1], "stored cap_units")
            reauth_required = _require_flag(budget[2], "stored reauthorization flag")
            if spent_units > cap_units:
                raise StoreInvariantError("stored budget invariant is invalid")

            def result(
                status: ClaimStatus, total: int, after: int = spent_units
            ) -> ClaimResult:
                return ClaimResult(
                    status=status,
                    protected_object=protected_object,
                    policy_epoch=epoch,
                    authorized_cost_units=total,
                    spent_before_units=spent_units,
                    spent_after_units=after,
                    cap_units=cap_units,
                )

            # These are read-only replay checks.  Durable authentication
            # state is written only after every gate/scope/epoch/budget check
            # succeeds, later in this same BEGIN IMMEDIATE transaction.
            if authorization is not None:
                now = time.time()
                if authorization.expires_at < now or (
                    authorization.delegation_expires_at is not None
                    and authorization.delegation_expires_at < now
                ):
                    return result(ClaimStatus.AUTH_INVALID, cost_units)
                if conn.execute(
                    "SELECT 1 FROM consumed_call_nonces "
                    "WHERE agent_id=? AND nonce=?",
                    (authorization.agent_id, authorization.nonce),
                ).fetchone():
                    return result(ClaimStatus.AUTH_REPLAYED, cost_units)
                if authorization.grant_id is not None and conn.execute(
                    "SELECT 1 FROM delegation_grants WHERE grant_id=?",
                    (authorization.grant_id,),
                ).fetchone():
                    return result(ClaimStatus.AUTH_REPLAYED, cost_units)

            current = conn.execute(
                "SELECT current_epoch FROM object_epochs WHERE protected_object=?",
                (protected_object,),
            ).fetchone()
            if current is None:
                return result(ClaimStatus.STALE_EPOCH, cost_units)
            current_epoch = _require_epoch(current[0], "stored current epoch")
            if current_epoch != epoch:
                return result(ClaimStatus.STALE_EPOCH, cost_units)
            if consumed == 1:
                return result(ClaimStatus.REPLAYED, cost_units)
            if consumed != 0:
                raise StoreInvariantError(f"gate {gate_id!r} has invalid consumed state")

            # Successor authorization and its fanout, resolved against the
            # *current* sequencing pointer for this (protected_object,
            # epoch) -- read here, inside the transaction, not before it.
            #
            # ``chain_opted_in`` closes a second, subtler gap the atomicity
            # fix alone does not: once *any* transition on this chain has
            # charged a real (fanout > 1) selection cost, the chain has
            # committed to being tracked, and a later predecessor that
            # itself declares no successors must mean "no further
            # transition is authorized from here," not "the mechanism is
            # unused, allow anything." Without this flag, once gate P
            # (declaring successors {X, Y}) is resolved to X, X's own empty
            # ``allowed_successor_gates`` would silently fall back to
            # "unconstrained" and let Y through anyway as a supposed
            # successor of X -- defeating the mutual exclusion the fanout
            # charge is supposed to buy. A chain that never uses the
            # mechanism at all (every gate declares no successors) never
            # sets this flag, so it stays exactly backward compatible.
            predecessor_row = conn.execute(
                "SELECT last_gate_id, chain_opted_in FROM object_sequence "
                "WHERE protected_object=? AND workflow_id=? AND policy_epoch=?",
                (protected_object, workflow_id, epoch),
            ).fetchone()
            if predecessor_row is None:
                last_gate_id, opted_in = None, 0
            else:
                last_gate_id, opted_in = predecessor_row
                opted_in = _require_flag(opted_in, "stored chain_opted_in flag")
            reserved_predecessors = {
                row[0]
                for row in conn.execute(
                    "SELECT predecessor_gate_id FROM declared_successors WHERE "
                    "protected_object=? AND workflow_id=? AND policy_epoch=? "
                    "AND successor_gate_id=?",
                    (protected_object, workflow_id, epoch, gate_id),
                ).fetchall()
            }
            if last_gate_id is None:
                # No predecessor is recorded for this (object, epoch) yet --
                # but that is also true the very first time *any* declared
                # successor is attempted, before its predecessor has ever
                # been claimed. Without this check, a gate named in some
                # other gate's allowed_successor_gates could be claimed
                # directly, skipping its predecessor entirely and paying
                # only its own entry_fanout (typically 1) instead of the
                # predecessor's declared K-way selection charge. This check
                # enforces chain entry eligibility and mutual exclusion; it
                # does not relax the theorem's separate public-routing
                # premise. TLC caught the missing check by violating
                # AtMostOneSuccessorClaimed with the predecessor unconsumed.
                if reserved_predecessors:
                    return result(ClaimStatus.UNAUTHORIZED_SUCCESSOR, cost_units)
                fanout = entry_fanout
            else:
                # A reserved successor remains reserved even if some
                # unrelated unconstrained gate most recently advanced this
                # workflow.  It is reachable only when its exact declared
                # predecessor is the current sequencing pointer.
                if (
                    reserved_predecessors
                    and last_gate_id not in reserved_predecessors
                ):
                    return result(ClaimStatus.UNAUTHORIZED_SUCCESSOR, cost_units)
                predecessor = conn.execute(
                    "SELECT record_json, protected_object, policy_epoch "
                    "FROM gates WHERE gate_id=?",
                    (last_gate_id,),
                ).fetchone()
                if predecessor is None:
                    raise StoreInvariantError(
                        f"sequencing pointer for {protected_object!r}/{epoch} "
                        f"references unknown gate {last_gate_id!r}"
                    )
                predecessor_workflow = self._workflow_from_record(
                    predecessor[0], last_gate_id
                )
                if (
                    predecessor[1] != protected_object
                    or predecessor[2] != epoch
                    or predecessor_workflow != workflow_id
                ):
                    raise StoreInvariantError(
                        "sequencing pointer crossed a security scope"
                    )
                declared_successors = json.loads(predecessor[0]).get(
                    "allowed_successor_gates"
                ) or []
                if declared_successors:
                    fanout = len(declared_successors)
                    if gate_id not in declared_successors:
                        # Free, pre-decode rejection: decided from the
                        # predecessor's already-committed, previously
                        # revealed successor set, not from this gate's
                        # content. Charged cost_units only in the returned
                        # ClaimResult's bookkeeping field (authorized_cost_
                        # units is informational on a rejection); no spend
                        # is recorded and this gate remains unconsumed, so a
                        # legitimately authorized caller may still claim it.
                        return result(ClaimStatus.UNAUTHORIZED_SUCCESSOR, cost_units)
                elif opted_in:
                    # The predecessor declares no successors of its own,
                    # but this chain has already charged a real selection
                    # cost earlier -- the predecessor is a declared leaf,
                    # not an unconstrained default. Same free rejection as
                    # above, same reasoning, just a different predecessor
                    # state triggering it.
                    return result(ClaimStatus.UNAUTHORIZED_SUCCESSOR, cost_units)
                else:
                    fanout = 1
            selection_units = selection_cost_units(fanout)
            # The reservation covers this gate's own content charge plus the
            # (possibly zero) selection charge for which permitted successor
            # was chosen, atomically, as one worst-case-support commitment.
            total_units = cost_units + selection_units

            # A request can be too expensive while a lower-cost request is
            # still affordable.  Denial is read-only and never latches the
            # entire epoch closed; reauth_required is only a derived mirror
            # of exact exhaustion after a committed claim.
            if spent_units + total_units > cap_units:
                return result(ClaimStatus.BUDGET_EXHAUSTED, total_units)

            if authorization is not None:
                consumed_at = time.time()
                conn.execute(
                    "INSERT INTO consumed_call_nonces(agent_id, nonce, consumed_at) "
                    "VALUES (?,?,?)",
                    (authorization.agent_id, authorization.nonce, consumed_at),
                )
                if authorization.grant_id is not None:
                    conn.execute(
                        "INSERT INTO delegation_grants(grant_id, delegator_agent_id, "
                        "delegate_agent_id, gate_id, redeemed_at) VALUES (?,?,?,?,?)",
                        (
                            authorization.grant_id,
                            authorization.delegator_agent_id,
                            authorization.delegate_agent_id,
                            gate_id,
                            consumed_at,
                        ),
                    )
                    self.append_audit(
                        gate_id,
                        "delegation_redeemed",
                        {
                            "grant_id": authorization.grant_id,
                            "delegator_agent_id": authorization.delegator_agent_id,
                            "delegate_agent_id": authorization.delegate_agent_id,
                        },
                        conn=conn,
                    )

            updated = conn.execute(
                "UPDATE gates SET consumed=1 WHERE gate_id=? AND consumed=0",
                (gate_id,),
            ).rowcount
            if updated != 1:
                return result(ClaimStatus.REPLAYED, total_units)
            new_spent_units = spent_units + total_units
            conn.execute(
                "UPDATE budgets SET spent_bits=?, spent_units=?, reauth_required=? "
                "WHERE protected_object=? AND policy_epoch=?",
                (
                    units_to_bits(new_spent_units),
                    new_spent_units,
                    int(new_spent_units >= cap_units),
                    protected_object,
                    epoch,
                ),
            )
            # Sequencing state advances only on an actual charged claim, the
            # same rule already used for `consumed`: a rejected attempt
            # (replay/stale-epoch/budget-exhausted/unauthorized-successor)
            # leaves the chain's predecessor pointer untouched. Because this
            # write and the successor-authorization read above share one
            # transaction, a second racing caller's transaction (blocked
            # until this one commits) will re-read *this* gate as the new
            # predecessor and correctly reject any other declared successor
            # of the old predecessor as no longer authorized -- mutual
            # exclusion falls out of atomicity, not a separate lock.
            # chain_opted_in is sticky: once a real (fanout > 1) selection
            # charge has occurred anywhere on this chain, it stays set for
            # the rest of this epoch, even through a later fanout == 1
            # step, so a leaf reached after branching cannot silently
            # revert to "unconstrained."
            new_opted_in = 1 if (fanout > 1 or opted_in) else 0
            conn.execute(
                "INSERT INTO object_sequence"
                "(protected_object, workflow_id, policy_epoch, last_gate_id, "
                "chain_opted_in) VALUES (?,?,?,?,?) ON CONFLICT"
                "(protected_object, workflow_id, policy_epoch) "
                "DO UPDATE SET last_gate_id=excluded.last_gate_id, "
                "chain_opted_in=excluded.chain_opted_in",
                (protected_object, workflow_id, epoch, gate_id, new_opted_in),
            )
            self.append_audit(
                gate_id,
                "invocation_started",
                {
                    "cost_bits": units_to_bits(cost_units),
                    "cost_units": cost_units,
                    "selection_units": selection_units,
                    "selection_bits": units_to_bits(selection_units),
                    "policy_epoch": epoch,
                },
                conn=conn,
            )
            return result(ClaimStatus.CLAIMED, total_units, new_spent_units)

    def spent_units(self, protected_object: str, epoch: int) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT spent_units FROM budgets WHERE protected_object=? AND policy_epoch=?",
                (protected_object, epoch),
            ).fetchone()
        return _require_units(row[0], "stored spent_units") if row else 0

    def spent(self, protected_object: str, epoch: int) -> float:
        return units_to_bits(self.spent_units(protected_object, epoch))

    def reauth_required(self, protected_object: str, epoch: int) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT reauth_required FROM budgets WHERE protected_object=? AND policy_epoch=?",
                (protected_object, epoch),
            ).fetchone()
        return bool(_require_flag(row[0], "stored reauthorization flag")) if row else False

    def current_epoch(self, protected_object: str) -> Optional[int]:
        with self._lock:
            row = self._conn.execute(
                "SELECT current_epoch FROM object_epochs WHERE protected_object=?",
                (protected_object,),
            ).fetchone()
        return _require_epoch(row[0], "stored current epoch") if row else None

    def redeem_grant(
        self,
        grant_id: str,
        protected_object: str,
        previous_epoch: int,
        new_epoch: int,
        new_cap_units: int,
        authorizer_identity: str,
        signature: str,
    ) -> None:
        if not all(isinstance(value, str) and value for value in (
            grant_id, protected_object, authorizer_identity, signature
        )):
            raise ValueError("reauthorization identifiers must be non-empty strings")
        if (
            isinstance(previous_epoch, bool)
            or isinstance(new_epoch, bool)
            or not isinstance(previous_epoch, int)
            or not isinstance(new_epoch, int)
            or previous_epoch < 0
            or new_epoch != previous_epoch + 1
        ):
            raise ValueError("reauthorization must advance exactly one non-negative epoch")
        new_cap_units = _require_units(new_cap_units, "new_cap_units")

        with self.transaction() as conn:
            if conn.execute(
                "SELECT 1 FROM reauth_grants WHERE grant_id=?", (grant_id,)
            ).fetchone():
                raise ReplayError(f"reauthorization grant {grant_id!r} already redeemed")
            current = conn.execute(
                "SELECT current_epoch FROM object_epochs WHERE protected_object=?",
                (protected_object,),
            ).fetchone()
            if current is None:
                raise ValueError(f"unknown protected object {protected_object!r}")
            current_epoch = _require_epoch(current[0], "stored current epoch")
            if current_epoch != previous_epoch:
                raise ValueError(
                    f"reauthorization expected current epoch {previous_epoch}, "
                    f"found {current_epoch}"
                )
            if conn.execute(
                "SELECT 1 FROM budgets WHERE protected_object=? AND policy_epoch=?",
                (protected_object, new_epoch),
            ).fetchone():
                raise ReplayError(
                    f"budget epoch {new_epoch} already exists for {protected_object!r}"
                )
            conn.execute(
                "INSERT INTO reauth_grants(grant_id, protected_object, previous_epoch, "
                "new_epoch, new_cap_bits, new_cap_units, authorizer_identity, signature, "
                "issued_at, consumed) VALUES (?,?,?,?,?,?,?,?,?,1)",
                (
                    grant_id,
                    protected_object,
                    previous_epoch,
                    new_epoch,
                    units_to_bits(new_cap_units),
                    new_cap_units,
                    authorizer_identity,
                    signature,
                    time.time(),
                ),
            )
            conn.execute(
                "INSERT INTO budgets(protected_object, policy_epoch, spent_bits, cap_bits, "
                "spent_units, cap_units, reauth_required) VALUES (?,?,0,?,0,?,0)",
                (protected_object, new_epoch, units_to_bits(new_cap_units), new_cap_units),
            )
            updated = conn.execute(
                "UPDATE object_epochs SET current_epoch=? WHERE protected_object=? "
                "AND current_epoch=?",
                (new_epoch, protected_object, previous_epoch),
            ).rowcount
            if updated != 1:
                raise StoreInvariantError("concurrent epoch update violated serialization")
            self.append_audit(
                None,
                "reauthorized",
                {
                    "protected_object": protected_object,
                    "previous_epoch": previous_epoch,
                    "new_epoch": new_epoch,
                    "new_cap_bits": units_to_bits(new_cap_units),
                    "new_cap_units": new_cap_units,
                    "authorizer_identity": authorizer_identity,
                },
                conn=conn,
            )

    def redeem_delegation_grant(
        self,
        grant_id: str,
        delegator_agent_id: str,
        delegate_agent_id: str,
        gate_id: str,
    ) -> bool:
        """Atomically mark ``grant_id`` redeemed; ``False`` if it already
        was. Signature/expiration/permitted-caller validity is the caller's
        (monitor.py's) responsibility -- this method only enforces the
        one-time property, the one part of delegation redemption that must
        be serialized against concurrent/repeated attempts rather than
        checked from in-memory state."""
        if not all(isinstance(value, str) and value for value in (
            grant_id, delegator_agent_id, delegate_agent_id, gate_id
        )):
            raise ValueError("delegation grant identifiers must be non-empty strings")
        with self.transaction() as conn:
            if conn.execute(
                "SELECT 1 FROM delegation_grants WHERE grant_id=?", (grant_id,)
            ).fetchone():
                return False
            conn.execute(
                "INSERT INTO delegation_grants(grant_id, delegator_agent_id, "
                "delegate_agent_id, gate_id, redeemed_at) VALUES (?,?,?,?,?)",
                (grant_id, delegator_agent_id, delegate_agent_id, gate_id, time.time()),
            )
            self.append_audit(
                gate_id,
                "delegation_redeemed",
                {
                    "grant_id": grant_id,
                    "delegator_agent_id": delegator_agent_id,
                    "delegate_agent_id": delegate_agent_id,
                },
                conn=conn,
            )
        return True

    def consume_call_nonce(self, agent_id: str, nonce: str) -> bool:
        """Atomically mark (agent_id, nonce) consumed; ``False`` if it
        already was. This is the one step in CallerCredential authentication
        that must be serialized against concurrent/repeated presentation of
        the same credential rather than checked from in-memory state --
        signature and expiry are pure functions of the credential's own
        fields and can be checked without touching durable state, but
        one-time-use cannot be."""
        if not all(isinstance(value, str) and value for value in (agent_id, nonce)):
            raise ValueError("agent_id and nonce must be non-empty strings")
        with self.transaction() as conn:
            if conn.execute(
                "SELECT 1 FROM consumed_call_nonces WHERE agent_id=? AND nonce=?",
                (agent_id, nonce),
            ).fetchone():
                return False
            conn.execute(
                "INSERT INTO consumed_call_nonces(agent_id, nonce, consumed_at) "
                "VALUES (?,?,?)",
                (agent_id, nonce, time.time()),
            )
        return True

    def lifetime_spent_units(self, protected_object: str) -> int:
        with self._lock:
            rows = self._conn.execute(
                "SELECT spent_units FROM budgets WHERE protected_object=?",
                (protected_object,),
            ).fetchall()
        return sum(_require_units(row[0], "stored spent_units") for row in rows)

    def lifetime_spent(self, protected_object: str) -> float:
        total = self.lifetime_spent_units(protected_object)
        return total / ACCOUNTING_SCALE

    def put_action_capability(
        self,
        capability_id: str,
        gate_id: str,
        protected_object: str,
        policy_epoch: int,
        action_json: str,
        args_json: str,
        capability_tag: str,
        redeemer_agent_id: Optional[str] = None,
    ) -> None:
        if not all(isinstance(value, str) and value for value in (
            capability_id,
            gate_id,
            protected_object,
            action_json,
            args_json,
            capability_tag,
        )):
            raise ValueError("action capability fields must be non-empty strings")
        if redeemer_agent_id is not None and (
            not isinstance(redeemer_agent_id, str) or not redeemer_agent_id
        ):
            raise ValueError("redeemer_agent_id must be a non-empty string or None")
        if (
            isinstance(policy_epoch, bool)
            or not isinstance(policy_epoch, int)
            or policy_epoch < 0
        ):
            raise ValueError("action capability epoch must be non-negative")
        with self.transaction() as conn:
            gate = conn.execute(
                "SELECT protected_object, policy_epoch FROM gates WHERE gate_id=?",
                (gate_id,),
            ).fetchone()
            if gate is None:
                raise StoreInvariantError("action capability references an unknown gate")
            gate_epoch = _require_epoch(gate[1], "stored gate epoch")
            if gate[0] != protected_object or gate_epoch != policy_epoch:
                raise StoreInvariantError("action capability gate binding is inconsistent")
            conn.execute(
                "INSERT INTO action_capabilities(capability_id, gate_id, protected_object, "
                "policy_epoch, action_json, args_json, capability_tag, consumed, created_at, "
                "redeemer_agent_id) VALUES (?,?,?,?,?,?,?,0,?,?)",
                (
                    capability_id,
                    gate_id,
                    protected_object,
                    policy_epoch,
                    action_json,
                    args_json,
                    capability_tag,
                    time.time(),
                    redeemer_agent_id,
                ),
            )

    def consume_action_capability(
        self,
        capability_id: str,
        capability_tag: str,
        authorization: Optional[PreparedAuthorization] = None,
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(capability_id, str) or not isinstance(capability_tag, str):
            return None
        if authorization is not None:
            if not isinstance(authorization, PreparedAuthorization):
                raise ValueError("authorization must be PreparedAuthorization or None")
            authorization.validate_for_scope(
                authorization.gate_id,
                authorization.workflow_id,
                authorization.policy_epoch,
            )
            if authorization.grant_id is not None:
                raise ValueError("delegation is not valid for capability redemption")
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT gate_id, protected_object, policy_epoch, action_json, args_json, "
                "consumed, redeemer_agent_id FROM action_capabilities "
                "WHERE capability_id=? AND capability_tag=?",
                (capability_id, capability_tag),
            ).fetchone()
            if row is None:
                return None
            consumed = _require_flag(row[5], "stored action capability consumed flag")
            if consumed != 0:
                return None
            gate_id, protected_object, policy_epoch, action_json, args_json, _, redeemer_agent_id = row
            if not all(isinstance(value, str) and value for value in (
                gate_id, protected_object, action_json, args_json
            )):
                raise StoreInvariantError("stored action capability fields are malformed")
            policy_epoch = _require_epoch(policy_epoch, "stored action capability epoch")
            if authorization is not None:
                authorization.validate_for_scope(gate_id, "", policy_epoch)
            gate = conn.execute(
                "SELECT protected_object, policy_epoch, consumed FROM gates WHERE gate_id=?",
                (gate_id,),
            ).fetchone()
            if gate is None:
                raise StoreInvariantError("stored action capability references a missing gate")
            gate_epoch = _require_epoch(gate[1], "stored gate epoch")
            gate_consumed = _require_flag(gate[2], "stored gate consumed flag")
            if (
                gate[0] != protected_object
                or gate_epoch != policy_epoch
                or gate_consumed != 1
            ):
                raise StoreInvariantError("stored action capability gate binding is inconsistent")
            current = conn.execute(
                "SELECT current_epoch FROM object_epochs WHERE protected_object=?",
                (protected_object,),
            ).fetchone()
            if current is None:
                return None
            current_epoch = _require_epoch(current[0], "stored current epoch")
            if current_epoch != policy_epoch:
                return None
            if authorization is not None:
                if authorization.expires_at < time.time():
                    return None
                if conn.execute(
                    "SELECT 1 FROM consumed_call_nonces "
                    "WHERE agent_id=? AND nonce=?",
                    (authorization.agent_id, authorization.nonce),
                ).fetchone():
                    return None
            if authorization is not None:
                conn.execute(
                    "INSERT INTO consumed_call_nonces(agent_id, nonce, consumed_at) "
                    "VALUES (?,?,?)",
                    (authorization.agent_id, authorization.nonce, time.time()),
                )
            updated = conn.execute(
                "UPDATE action_capabilities SET consumed=1 WHERE capability_id=? "
                "AND capability_tag=? AND consumed=0",
                (capability_id, capability_tag),
            ).rowcount
            if updated == 1:
                self.append_audit(
                    None,
                    "action_capability_consumed",
                    {"capability_id": capability_id},
                    conn=conn,
                )
                try:
                    action = json.loads(action_json)
                    args = json.loads(args_json)
                except (TypeError, ValueError) as exc:
                    raise StoreInvariantError(
                        "stored action capability payload is malformed"
                    ) from exc
                return {
                    "gate_id": gate_id,
                    "protected_object": protected_object,
                    "policy_epoch": policy_epoch,
                    "action": action,
                    "args": args,
                    "redeemer_agent_id": redeemer_agent_id,
                }
            return None

    def _last_hash(self, conn: sqlite3.Connection) -> str:
        row = conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else GENESIS_HASH

    @staticmethod
    def _audit_entry_hash(
        previous: str,
        sequence: int,
        timestamp: float,
        gate_id: Optional[str],
        event: str,
        detail_json: str,
    ) -> str:
        payload = json.dumps(
            {
                "previous": previous,
                "sequence": sequence,
                "timestamp_hex": timestamp.hex(),
                "gate_id": gate_id,
                "event": event,
                "detail_json": detail_json,
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def append_audit(
        self,
        gate_id: Optional[str],
        event: str,
        detail: Dict[str, Any],
        conn: Optional[sqlite3.Connection] = None,
    ) -> str:
        if gate_id is not None and not isinstance(gate_id, str):
            raise ValueError("audit gate_id must be a string or None")
        if not isinstance(event, str) or not event:
            raise ValueError("audit event must be a non-empty string")
        try:
            detail_json = json.dumps(
                detail, sort_keys=True, separators=(",", ":"), allow_nan=False
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("audit detail must be finite JSON data") from exc

        def write(active: sqlite3.Connection) -> str:
            previous = self._last_hash(active)
            timestamp = time.time()
            cursor = active.execute(
                "INSERT INTO audit_log(ts, gate_id, event, detail_json, prev_hash, "
                "entry_hash) VALUES (?,?,?,?,?,?)",
                (timestamp, gate_id, event, detail_json, previous, "pending"),
            )
            sequence = int(cursor.lastrowid)
            entry_hash = self._audit_entry_hash(
                previous, sequence, timestamp, gate_id, event, detail_json
            )
            active.execute(
                "UPDATE audit_log SET entry_hash=? WHERE seq=?",
                (entry_hash, sequence),
            )
            return entry_hash

        if conn is not None:
            return write(conn)
        with self.transaction() as active:
            return write(active)

    def verify_audit_chain(self) -> bool:
        """Verify present rows; suffix deletion needs an external checkpoint."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, gate_id, event, detail_json, ts, prev_hash, entry_hash "
                "FROM audit_log ORDER BY seq"
            ).fetchall()
        expected_previous = GENESIS_HASH
        expected_sequence = 1
        for sequence, gate_id, event, detail_json, timestamp, previous, entry_hash in rows:
            if sequence != expected_sequence:
                return False
            if previous != expected_previous:
                return False
            if self._audit_entry_hash(
                previous, sequence, timestamp, gate_id, event, detail_json
            ) != entry_hash:
                return False
            expected_previous = entry_hash
            expected_sequence += 1
        return True

    def audit_head(self) -> Dict[str, Any]:
        with self._lock:
            count, last_seq = self._conn.execute(
                "SELECT COUNT(*), COALESCE(MAX(seq),0) FROM audit_log"
            ).fetchone()
            last = self._conn.execute(
                "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
        return {
            "entry_count": int(count),
            "last_seq": int(last_seq),
            "last_hash": last[0] if last else GENESIS_HASH,
        }

    def audit_log(self):
        with self._lock:
            rows = self._conn.execute(
                "SELECT seq, ts, gate_id, event, detail_json FROM audit_log ORDER BY seq"
            ).fetchall()
        return [
            {
                "seq": row[0],
                "ts": row[1],
                "gate_id": row[2],
                "event": row[3],
                "detail": json.loads(row[4]),
            }
            for row in rows
        ]

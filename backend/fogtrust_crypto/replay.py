"""
Replay defence: the stateful part of verifying a node request (contract steps 5 and 6, plus the counter).

WHY THIS ORDER (answers to the Week 3 design questions):

  1. Signature first. Only an authenticated node may touch the replay state, so an anonymous
     attacker cannot fill the nonce store or advance a counter.
  2. Timestamp window second. It needs no stored state, and it is what makes purging safe:
     a request older than the window is refused before the store is consulted, so a nonce only
     has to be remembered until `timestamp + window`.
  3. Nonce third, with an ATOMIC "add if unseen". Check-then-store would let two copies of the
     same request both pass; the store operation itself must decide.
  4. Counter last (heartbeats only), again atomic: "advance if greater".
  A rejected request never advances the counter. The one deliberate exception is the nonce of a
  request that fails a LATER check: it stays burned, which is harmless because an honest node never
  reuses a nonce.

The store is an interface so the Django layer can back it with the database
(unique (node, nonce) constraint; conditional UPDATE ... WHERE last_counter < new).
`InMemoryReplayStore` is the reference implementation used by tests and the simulator's stub broker.
"""

from __future__ import annotations

import threading
from typing import Optional, Protocol

from . import codes
from .result import Run, VerificationResult

DEFAULT_WINDOW_S = 30


class ReplayStore(Protocol):
    def add_nonce(self, node_id: str, nonce: str, expires_at: int) -> bool:
        """Atomically remember the nonce. True if it was new, False if this node already used it."""

    def advance_counter(self, node_id: str, counter: int) -> bool:
        """Atomically set the node's last counter to `counter` if it is greater. True if advanced."""

    def last_counter(self, node_id: str) -> int:
        """The last accepted counter for evidence (0 if none)."""


class InMemoryReplayStore:
    """Thread-safe reference implementation. State is lost on restart (the database version is not)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._nonces: dict[tuple[str, str], int] = {}
        self._counters: dict[str, int] = {}

    def add_nonce(self, node_id: str, nonce: str, expires_at: int) -> bool:
        with self._lock:
            key = (node_id, nonce)
            if key in self._nonces:
                return False
            self._nonces[key] = expires_at
            return True

    def advance_counter(self, node_id: str, counter: int) -> bool:
        with self._lock:
            if counter > self._counters.get(node_id, 0):
                self._counters[node_id] = counter
                return True
            return False

    def last_counter(self, node_id: str) -> int:
        with self._lock:
            return self._counters.get(node_id, 0)

    def purge(self, now: float) -> int:
        """Forget nonces whose window has passed. Returns how many were removed."""
        with self._lock:
            expired = [key for key, expires_at in self._nonces.items() if expires_at < now]
            for key in expired:
                del self._nonces[key]
            return len(expired)

    def nonce_count(self) -> int:
        with self._lock:
            return len(self._nonces)


def check_freshness(run: Run, now: float, window_s: int) -> Optional[VerificationResult]:
    """Contract step 5. Returns a denial, or None when the timestamp is inside the window."""
    skew = now - run.timestamp
    if abs(skew) > window_s:
        run.rule("timestamp_window", False, f"skew {skew:+.1f} s, limit {window_s} s")
        return run.deny(codes.HEARTBEAT_STALE, "The request timestamp is outside the allowed window.", skew_s=round(skew, 1))
    run.rule("timestamp_window", True, f"skew {skew:+.1f} s, limit {window_s} s")
    return None


def check_nonce(run: Run, store: ReplayStore, window_s: int) -> Optional[VerificationResult]:
    """Contract step 6. Returns a denial, or None when the nonce was unused (and is now remembered)."""
    if not store.add_nonce(run.node_id, run.nonce, run.timestamp + window_s):
        run.rule("nonce_unique", False, "nonce already used by this node inside the window")
        return run.deny(codes.HEARTBEAT_REPLAYED, "This request was already received.")
    run.rule("nonce_unique", True, "nonce not seen before; remembered until the window closes")
    return None
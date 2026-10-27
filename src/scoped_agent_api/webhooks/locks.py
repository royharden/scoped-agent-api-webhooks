"""Process-local revoke/send serialization; no distributed fencing claim."""

from collections.abc import Iterator
from contextlib import contextmanager
from threading import Lock, RLock


class GrantLocks:
    """A single registry shared by dispatch and grant revocation.

    Locks intentionally remain for the fixture lifetime: removing an idle entry
    could give a waiter and a new caller different locks for the same grant.
    """

    def __init__(self) -> None:
        self._guard = Lock()
        self._locks: dict[str, RLock] = {}

    @contextmanager
    def hold(self, grant_id: str) -> Iterator[None]:
        if not grant_id:
            raise ValueError("grant_id_required")
        with self._guard:
            lock = self._locks.setdefault(grant_id, RLock())
        with lock:
            yield


GRANT_LOCKS = GrantLocks()

import threading
from typing import Generic, TypeVar, Optional

T = TypeVar("T")


class BroadcastLatest(Generic[T]):
    """Thread-safe, latest-value channel with multi-consumer fanout."""
    def __init__(self) -> None:
        self._cond = threading.Condition()
        self._value: Optional[T] = None
        self._version: int = 0
        self._closed = False

    def publish(self, item: T) -> None:
        with self._cond:
            self._value = item
            self._version += 1
            self._cond.notify_all()

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def subscribe(self) -> "Subscriber[T]":
        return Subscriber(self)


class Subscriber(Generic[T]):
    def __init__(self, parent: BroadcastLatest[T]) -> None:
        self._p = parent
        self._seen = 0

    def next(self, timeout: Optional[float] = None) -> Optional[T]:
        """Block until a newer value than last_seen is available, or closed."""
        with self._p._cond:
            ok = self._p._cond.wait_for(
                lambda: self._p._closed or self._p._version > self._seen,
                timeout
            )
            if not ok or self._p._closed:
                return None
            self._seen = self._p._version
            return self._p._value

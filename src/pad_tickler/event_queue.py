from typing import Generic, TypeVar, Optional
import threading


# ---- Size-1, latest-only queue (single consumer) ----
T = TypeVar("T")

class SingleSlotQueue(Generic[T]):
    """Thread-safe, size=1, latest-wins queue. One consumer reads the newest item."""
    def __init__(self) -> None:
        self._cv = threading.Condition()
        self._has_value = False
        self._value: Optional[T] = None
        self._closed = False

    def publish(self, item: T) -> None:
        with self._cv:
            self._value = item       # overwrite any stale value
            self._has_value = True
            self._cv.notify()        # wake exactly one waiting consumer

    def close(self) -> None:
        with self._cv:
            self._closed = True
            self._cv.notify_all()

    def get(self, timeout: Optional[float] = None) -> Optional[T]:
        """Blocks until a value is available or the queue is closed. Returns None on close."""
        with self._cv:
            ok = self._cv.wait_for(lambda: self._has_value or self._closed, timeout)
            if not ok:
                raise TimeoutError("queue get() timed out")
            if self._closed and not self._has_value:
                return None
            v = self._value
            self._value = None
            self._has_value = False
            return v

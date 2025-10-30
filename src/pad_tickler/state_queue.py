from typing import Generic, TypeVar, Optional
import threading


T = TypeVar("T")


class SingleSlotQueue(Generic[T]):
    """Thread-safe, size=1, latest-wins queue. Consumers read the latest item."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._has_value = False
        self._value: Optional[T] = None
        self._closed = False

    def publish(self, item: T) -> None:
        """Publish an item to the queue. Overwrites any stale value."""
        with self._condition:
            self._value = item  # Overwrite any stale value.
            self._has_value = True
            self._condition.notify()  # Wake exactly one waiting consumer.

    def close(self) -> None:
        """Close the queue. No more items will be published."""
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    def get(self, timeout: Optional[float] = None) -> Optional[T]:
        """Blocks until a value is available or the queue is closed. Returns None on close."""
        with self._condition:
            ok = self._condition.wait_for(
                lambda: self._has_value or self._closed, timeout
            )
            if not ok:
                raise TimeoutError("queue get() timed out")
            if self._closed and not self._has_value:
                return None
            v = self._value
            self._value = None
            self._has_value = False
            return v

import asyncio
from typing import Generic, TypeVar

T = TypeVar("T")


class CoalescingQueue(Generic[T]):
    def __init__(self):
        self._q: asyncio.Queue[T] = asyncio.Queue(maxsize=1)
        self._lock = asyncio.Lock()

    async def publish(self, item: T) -> None:
        async with self._lock:
            if self._q.full():
                try:
                    _ = self._q.get_nowait()
                    self._q.task_done()
                except asyncio.QueueEmpty:
                    pass
            await self._q.put(item)  # now ok to await; producers are serialized


class CoalescingQueue(Generic[T]):
    """Always keeps the most recent item. Never grows beyond 1."""
    def __init__(self) -> None:
        self._q: asyncio.Queue[T] = asyncio.Queue(maxsize=1)
        self._closed = False

    async def publish(self, item: T) -> None:
        if self._closed:
            return
        try:
            self._q.put_nowait(item)
        except asyncio.QueueFull:
            try:
                _ = self._q.get_nowait()      # drop stale
                self._q.task_done()
            except asyncio.QueueEmpty:
                pass
            self._q.put_nowait(item)           # now it must succeed

    async def get(self) -> T:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()

    async def close(self) -> None:
        self._closed = True
        # Optionally wake consumers with a sentinel if you like.

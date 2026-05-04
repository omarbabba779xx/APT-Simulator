"""In-process event bus for live dashboard streaming.

Bridges sync producers (audit log writes from any thread) to async consumers
(WebSocket connections in the event loop). Slow subscribers drop events rather
than back-pressuring producers, since dashboard liveness is best-effort.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any


class EventBus:
    def __init__(self, queue_size: int = 256) -> None:
        self._queue_size = queue_size
        self._subscribers: list[asyncio.Queue] = []
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=self._queue_size)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def publish(self, event: dict[str, Any]) -> None:
        if self._loop is None:
            return
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            self._loop.call_soon_threadsafe(self._safe_put, q, event)

    @staticmethod
    def _safe_put(q: asyncio.Queue, event: dict[str, Any]) -> None:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass

    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subscribers)

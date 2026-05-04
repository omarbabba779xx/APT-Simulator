from __future__ import annotations

import asyncio

import pytest

from orchestrator.core.bus import EventBus


@pytest.mark.asyncio
async def test_publish_to_subscriber() -> None:
    bus = EventBus()
    bus.attach_loop(asyncio.get_running_loop())
    q = bus.subscribe()
    bus.publish({"event": "x", "payload": {"k": 1}})
    await asyncio.sleep(0)  # let call_soon_threadsafe land
    item = await asyncio.wait_for(q.get(), timeout=1.0)
    assert item == {"event": "x", "payload": {"k": 1}}


@pytest.mark.asyncio
async def test_unsubscribe_removes_queue() -> None:
    bus = EventBus()
    bus.attach_loop(asyncio.get_running_loop())
    q = bus.subscribe()
    assert bus.subscriber_count() == 1
    bus.unsubscribe(q)
    assert bus.subscriber_count() == 0


@pytest.mark.asyncio
async def test_full_subscriber_drops_event() -> None:
    bus = EventBus(queue_size=1)
    bus.attach_loop(asyncio.get_running_loop())
    q = bus.subscribe()
    bus.publish({"event": "a"})
    bus.publish({"event": "b"})  # dropped
    await asyncio.sleep(0)
    first = await asyncio.wait_for(q.get(), timeout=0.5)
    assert first == {"event": "a"}
    assert q.empty()


def test_publish_without_loop_no_error() -> None:
    bus = EventBus()
    bus.publish({"event": "x"})  # must not raise

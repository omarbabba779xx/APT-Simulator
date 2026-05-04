"""WebSocket endpoint that broadcasts audit events to connected clients."""
from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .state import get_state


router = APIRouter(tags=["ws"])


@router.websocket("/ws")
async def ws(websocket: WebSocket) -> None:
    await websocket.accept()
    s = get_state()
    if s.bus is None:
        await websocket.send_json({"event": "error", "payload": {"reason": "bus unavailable"}})
        await websocket.close()
        return
    queue = s.bus.subscribe()
    await websocket.send_json({"event": "ws.hello", "payload": {"subscribers": s.bus.subscriber_count()}})
    try:
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                # Heartbeat keeps proxies from killing idle connections.
                await websocket.send_json({"event": "ws.heartbeat", "payload": {}})
    except WebSocketDisconnect:
        pass
    finally:
        s.bus.unsubscribe(queue)

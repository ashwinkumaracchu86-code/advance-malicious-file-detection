import asyncio
import json
import logging
from typing import Dict, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and broadcasts scan results in real-time."""

    def __init__(self):
        self._connections: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        logger.info(f"WebSocket client connected. Total: {len(self._connections)}")

    async def disconnect(self, ws: WebSocket):
        async with self._lock:
            self._connections.discard(ws)
        logger.info(f"WebSocket client disconnected. Total: {len(self._connections)}")

    async def broadcast(self, event_type: str, data: dict):
        message = json.dumps({"type": event_type, "data": data})
        disconnected = []
        async with self._lock:
            for ws in self._connections:
                try:
                    await ws.send_text(message)
                except Exception:
                    disconnected.append(ws)
            for ws in disconnected:
                self._connections.discard(ws)

    async def broadcast_scan_result(self, scan_result: dict):
        await self.broadcast("scan_result", scan_result)

    async def broadcast_notification(self, notification: dict):
        await self.broadcast("notification", notification)

    async def broadcast_protection_status(self, status: dict):
        await self.broadcast("protection_status", status)

    async def broadcast_monitoring_event(self, event: dict):
        await self.broadcast("monitoring_event", event)

    async def broadcast_health_update(self, health: dict):
        await self.broadcast("health_update", health)

    @property
    def connection_count(self):
        return len(self._connections)


manager = ConnectionManager()

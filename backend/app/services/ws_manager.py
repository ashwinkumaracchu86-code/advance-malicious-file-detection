import asyncio
import json
import logging
from collections import defaultdict
from typing import Dict, Iterable, Optional, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and delivers scan results in real-time.

    Connections are grouped by the authenticated user id so that a scan event
    belonging to one user is only ever delivered to that user's own socket(s).
    """

    def __init__(self):
        self._connections: Dict[int, Set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, user_id: int):
        await ws.accept()
        async with self._lock:
            self._connections[int(user_id)].add(ws)
        logger.info(
            f"WebSocket client connected for user {user_id}. Total: {self.connection_count}"
        )

    async def disconnect(self, ws: WebSocket, user_id: Optional[int] = None):
        async with self._lock:
            if user_id is not None:
                self._connections.get(int(user_id), set()).discard(ws)
            else:
                for sockets in self._connections.values():
                    sockets.discard(ws)
        logger.info(f"WebSocket client disconnected. Total: {self.connection_count}")

    def _sockets_for(self, user_id: Optional[int]) -> Iterable[WebSocket]:
        if user_id is None:
            seen: Set[WebSocket] = set()
            for sockets in self._connections.values():
                seen.update(sockets)
            return list(seen)
        return list(self._connections.get(int(user_id), set()))

    async def _send(self, sockets: Iterable[WebSocket], message: str) -> None:
        disconnected = []
        for ws in sockets:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)
        if disconnected:
            async with self._lock:
                for ws in disconnected:
                    for sockets_set in self._connections.values():
                        sockets_set.discard(ws)

    async def send_to_user(self, user_id: int, event_type: str, data: dict):
        """Deliver an event to a single user's connected sessions only."""
        message = json.dumps({"type": event_type, "data": data})
        await self._send(self._sockets_for(user_id), message)

    async def broadcast(self, event_type: str, data: dict):
        """Deliver a system-wide event (never carries private user data)."""
        message = json.dumps({"type": event_type, "data": data})
        async with self._lock:
            sockets = [ws for sockets_set in self._connections.values() for ws in sockets_set]
        await self._send(sockets, message)

    async def broadcast_scan_result(self, scan_result: dict, user_id: Optional[int] = None):
        """Scan results are private: route them to their owner when known."""
        if user_id is None:
            user_id = scan_result.get("user_id")
        if user_id is not None:
            await self.send_to_user(user_id, "scan_result", scan_result)
        else:
            await self.broadcast("scan_result", scan_result)

    async def broadcast_notification(self, notification: dict, user_id: Optional[int] = None):
        if user_id is None:
            user_id = notification.get("user_id")
        if user_id is not None:
            await self.send_to_user(user_id, "notification", notification)
        else:
            await self.broadcast("notification", notification)

    async def broadcast_protection_status(self, status: dict):
        await self.broadcast("protection_status", status)

    async def broadcast_monitoring_event(self, event: dict):
        await self.broadcast("monitoring_event", event)

    async def broadcast_health_update(self, health: dict):
        await self.broadcast("health_update", health)

    @property
    def connection_count(self):
        return sum(len(sockets) for sockets in self._connections.values())


manager = ConnectionManager()

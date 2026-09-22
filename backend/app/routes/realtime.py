import asyncio
import logging
import os
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from sqlalchemy.orm import Session
from ..database import get_db
from ..security.auth import get_current_user, verify_token
from ..models.models import User
from ..services.ws_manager import manager
from ..services import folder_monitor

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Realtime"])


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query(None)):
    """WebSocket endpoint for real-time scan notifications with token authentication."""
    if not token:
        await ws.close(code=4001, reason="Authentication token required")
        return

    payload = verify_token(token, token_type="access")
    if not payload:
        await ws.close(code=4003, reason="Invalid or expired token")
        return

    user_id = payload.get("sub")
    if not user_id:
        await ws.close(code=4003, reason="Invalid token payload")
        return

    await manager.connect(ws)
    try:
        await ws.send_json({
            "type": "connected",
            "data": {"message": "Connected to real-time scan feed", "user_id": int(user_id)},
        })
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong", "data": {}})
    except WebSocketDisconnect:
        await manager.disconnect(ws)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        await manager.disconnect(ws)


@router.post("/realtime/auto-scan/start")
async def start_realtime_auto_scan(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Start real-time auto-scanning of all monitored folders."""
    from ..routes.antivirus import _monitored_paths, _protection_enabled
    if not _monitored_paths:
        return {
            "status": "error",
            "message": "No monitored paths configured. Add a path first.",
        }

    results = []
    for path in _monitored_paths:
        result = folder_monitor.start_monitoring(path, db)
        results.append({"path": path, **result})

    await manager.broadcast_monitoring_event({
        "action": "auto_scan_started",
        "paths": _monitored_paths,
    })

    return {
        "status": "started",
        "results": results,
        "message": f"Auto-scan started for {len(_monitored_paths)} path(s)",
    }


@router.post("/realtime/auto-scan/stop")
async def stop_realtime_auto_scan(
    current_user: User = Depends(get_current_user),
):
    """Stop all real-time auto-scanning."""
    result = folder_monitor.stop_monitoring()

    await manager.broadcast_monitoring_event({
        "action": "auto_scan_stopped",
    })

    return result


@router.get("/realtime/status")
async def get_realtime_status(
    current_user: User = Depends(get_current_user),
):
    """Get real-time system status."""
    from ..routes.antivirus import _monitored_paths, _auto_scan_enabled, _protection_enabled
    monitor_status = folder_monitor.get_monitoring_status()
    return {
        "websocket_connections": manager.connection_count,
        "monitoring_active": monitor_status["active"],
        "watchdog_available": monitor_status["watchdog_available"],
        "protection_enabled": _protection_enabled,
        "auto_scan_enabled": _auto_scan_enabled,
        "monitored_paths": _monitored_paths,
    }


@router.get("/realtime/notifications")
async def get_realtime_notifications(
    current_user: User = Depends(get_current_user),
):
    """Get all notifications from both antivirus and folder monitor."""
    from ..routes.antivirus import _notification_queue
    monitor_notifs = folder_monitor.get_monitor_notifications()
    return {
        "notifications": _notification_queue[:50],
        "monitor_notifications": monitor_notifs[:50],
    }

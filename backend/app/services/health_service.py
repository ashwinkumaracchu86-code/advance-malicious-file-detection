import os
import platform
import logging
import time
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from collections import deque
from fastapi import HTTPException

logger = logging.getLogger(__name__)

_psutil = None


def _get_psutil():
    global _psutil
    if _psutil is None:
        try:
            import psutil as _p
            _psutil = _p
        except ImportError:
            logger.warning("psutil not installed. System health metrics will be limited.")
            return None
    return _psutil


# Thread-safe storage for health telemetry
_telemetry_lock = threading.Lock()
_history_buffer = deque(maxlen=30)
_latest_health: Dict[str, Any] = {}
_cached_processes: List[Dict[str, Any]] = []
_last_net_bytes_sent = 0
_last_net_bytes_recv = 0
_last_net_time = 0.0
_cached_clamav_status: Dict[str, Any] = {"available": False, "enabled": False}
_last_clamav_check = time.time()
_collector_thread: Optional[threading.Thread] = None
_stop_collector = threading.Event()


def _get_system_info() -> Dict[str, Any]:
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "hostname": platform.node(),
        "processor": platform.processor() or "Unknown",
    }


def _collect_telemetry_snapshot():
    global _latest_health, _cached_processes, _last_net_bytes_sent, _last_net_bytes_recv, _last_net_time, _cached_clamav_status, _last_clamav_check
    p = _get_psutil()
    now_ts = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()
    now_time_str = datetime.now().strftime("%H:%M:%S")

    if not p:
        return

    # 1. CPU & Memory
    cores = p.cpu_count(logical=True) or 1
    cpu_pct = round(p.cpu_percent(interval=None), 1)

    mem = p.virtual_memory()
    mem_used_mb = round(mem.used / (1024 * 1024), 1)
    mem_total_mb = round(mem.total / (1024 * 1024), 1)
    mem_avail_mb = round(mem.available / (1024 * 1024), 1)
    mem_pct = round(mem.percent, 1)

    # Swap
    try:
        swap = p.swap_memory()
        swap_total_mb = round(swap.total / (1024 * 1024), 1)
        swap_used_mb = round(swap.used / (1024 * 1024), 1)
        swap_pct = round(swap.percent, 1)
    except Exception:
        swap_total_mb = 0.0
        swap_used_mb = 0.0
        swap_pct = 0.0

    # 2. Disk
    try:
        disk_path = "C:\\" if platform.system() == "Windows" else "/"
        disk = p.disk_usage(disk_path)
        disk_used_gb = round(disk.used / (1024 ** 3), 2)
        disk_total_gb = round(disk.total / (1024 ** 3), 2)
        disk_pct = round(disk.percent, 1)
    except Exception:
        disk_used_gb = 0.0
        disk_total_gb = 0.0
        disk_pct = 0.0

    # Partitions
    partitions = []
    try:
        for part in p.disk_partitions():
            try:
                usage = p.disk_usage(part.mountpoint)
                partitions.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent": round(usage.percent, 1),
                })
            except (PermissionError, OSError):
                pass
    except Exception:
        pass

    # 3. Network I/O and rates
    upload_kbps = 0.0
    download_kbps = 0.0
    net_info = {
        "bytes_sent": 0,
        "bytes_recv": 0,
        "packets_sent": 0,
        "packets_recv": 0,
        "bytes_sent_mb": 0.0,
        "bytes_recv_mb": 0.0,
        "upload_kbps": 0.0,
        "download_kbps": 0.0,
        "interfaces": [],
    }
    try:
        io_counters = p.net_io_counters()
        net_info["bytes_sent"] = io_counters.bytes_sent
        net_info["bytes_recv"] = io_counters.bytes_recv
        net_info["packets_sent"] = io_counters.packets_sent
        net_info["packets_recv"] = io_counters.packets_recv
        net_info["bytes_sent_mb"] = round(io_counters.bytes_sent / (1024 * 1024), 2)
        net_info["bytes_recv_mb"] = round(io_counters.bytes_recv / (1024 * 1024), 2)

        if _last_net_time > 0:
            delta_t = max(0.1, now_ts - _last_net_time)
            upload_kbps = round(max(0.0, (io_counters.bytes_sent - _last_net_bytes_sent) / 1024.0 / delta_t), 1)
            download_kbps = round(max(0.0, (io_counters.bytes_recv - _last_net_bytes_recv) / 1024.0 / delta_t), 1)
            net_info["upload_kbps"] = upload_kbps
            net_info["download_kbps"] = download_kbps

        _last_net_bytes_sent = io_counters.bytes_sent
        _last_net_bytes_recv = io_counters.bytes_recv
        _last_net_time = now_ts

        addrs = p.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family.name == 'AF_INET':
                    net_info["interfaces"].append({
                        "name": iface,
                        "ip": addr.address,
                        "netmask": addr.netmask,
                    })
    except Exception:
        pass

    # 4. Processes Scan (Task Manager)
    procs = []
    total_count = 0
    running_count = 0
    sleeping_count = 0
    try:
        attrs = ['pid', 'name', 'cpu_percent', 'memory_percent']
        for proc in p.process_iter(attrs):
            total_count += 1
            try:
                info = proc.info
                pid = info['pid']
                name = info['name'] or 'Unknown'

                raw_cpu = info.get('cpu_percent') or 0.0
                normalized_cpu = round(raw_cpu / cores, 1) if raw_cpu > 0 else 0.0
                mem_pct = round(info.get('memory_percent') or 0.0, 1)
                mem_mb = round((mem_pct / 100.0) * mem_total_mb, 1)
                st = 'running' if normalized_cpu > 0.0 else 'idle'

                if st == 'running':
                    running_count += 1
                else:
                    sleeping_count += 1

                if pid == 0:
                    normalized_cpu = 0.0
                    st = 'idle'

                procs.append({
                    "pid": pid,
                    "name": name,
                    "status": st,
                    "cpu": normalized_cpu,
                    "memory_percent": mem_pct,
                    "memory_mb": mem_mb,
                    "is_critical": pid <= 4 or pid == os.getpid(),
                })
            except Exception:
                pass
    except Exception as e:
        logger.debug(f"Process scan error: {e}")

    top_cpu = sorted(procs, key=lambda x: (x["cpu"], x["memory_mb"]), reverse=True)[:15]
    top_memory = sorted(procs, key=lambda x: (x["memory_mb"], x["cpu"]), reverse=True)[:15]
    all_sorted = sorted(procs, key=lambda x: (x["cpu"], x["memory_mb"]), reverse=True)

    # 5. Uptime & CPU info
    uptime_info = {
        "boot_time": "",
        "uptime_seconds": 0,
        "uptime_human": "",
    }
    try:
        boot = p.boot_time()
        boot_dt = datetime.fromtimestamp(boot, tz=timezone.utc)
        uptime_info["boot_time"] = boot_dt.isoformat()
        delta = time.time() - boot
        uptime_info["uptime_seconds"] = int(delta)
        days = int(delta // 86400)
        hours = int((delta % 86400) // 3600)
        mins = int((delta % 3600) // 60)
        uptime_info["uptime_human"] = f"{days}d {hours}h {mins}m"
    except Exception:
        pass

    cpu_details = {
        "physical_cores": 0,
        "logical_cores": cores,
        "frequency_current": 0,
        "frequency_max": 0,
        "frequency_min": 0,
        "load_avg_1m": 0,
        "load_avg_5m": 0,
        "load_avg_15m": 0,
        "ctx_switches": 0,
        "interrupts": 0,
    }
    try:
        cpu_details["physical_cores"] = p.cpu_count(logical=False) or cores
        freq = p.cpu_freq()
        if freq:
            cpu_details["frequency_current"] = round(freq.current, 0)
            cpu_details["frequency_max"] = round(freq.max, 0) if freq.max else 0
            cpu_details["frequency_min"] = round(freq.min, 0) if freq.min else 0
        if hasattr(p, 'getloadavg'):
            load = p.getloadavg()
            cpu_details["load_avg_1m"] = round(load[0], 2)
            cpu_details["load_avg_5m"] = round(load[1], 2)
            cpu_details["load_avg_15m"] = round(load[2], 2)
        ctx = p.cpu_stats()
        cpu_details["ctx_switches"] = ctx.ctx_switches
        cpu_details["interrupts"] = ctx.interrupts
    except Exception:
        pass

    # 6. ClamAV Status check (cached for 30 seconds)
    if now_ts - _last_clamav_check > 30:
        try:
            from ..scanner.clamav_scanner import get_clamav_status
            _cached_clamav_status = get_clamav_status()
            _last_clamav_check = now_ts
        except Exception:
            _cached_clamav_status = {"available": False, "enabled": False}

    clamav_active = _cached_clamav_status.get("available", False)

    status_verdict = "healthy"
    if cpu_pct > 90 or mem_pct > 90 or disk_pct > 95:
        status_verdict = "critical"
    elif cpu_pct > 75 or mem_pct > 75 or disk_pct > 85:
        status_verdict = "warning"

    snapshot = {
        "status": status_verdict,
        "timestamp": now_iso,
        "system": _get_system_info(),
        "resources": {
            "cpu_percent": cpu_pct,
            "memory_percent": mem_pct,
            "memory_used_mb": mem_used_mb,
            "memory_total_mb": mem_total_mb,
            "memory_available_mb": mem_avail_mb,
            "disk_percent": disk_pct,
            "disk_used_gb": disk_used_gb,
            "disk_total_gb": disk_total_gb,
        },
        "services": {
            "database": "active",
            "firewall": "active",
            "clamav": "active" if clamav_active else "unavailable",
            "realtime_protection": "active",
            "email_monitor": "active",
        },
        "network": net_info,
        "processes": {
            "total_count": total_count,
            "running": running_count,
            "sleeping": sleeping_count,
            "top_cpu": top_cpu,
            "top_memory": top_memory,
            "all_processes": all_sorted[:150],
        },
        "uptime": uptime_info,
        "cpu_info": cpu_details,
        "memory_detail": {
            "swap_total_mb": swap_total_mb,
            "swap_used_mb": swap_used_mb,
            "swap_percent": swap_pct,
            "available_mb": mem_avail_mb,
            "total_bytes": mem.total,
            "used_bytes": mem.used,
            "available_bytes": mem.available,
            "buffers_mb": round(getattr(mem, 'buffers', 0) / (1024 * 1024), 1),
            "cached_mb": round(getattr(mem, 'cached', 0) / (1024 * 1024), 1),
        },
        "disk_partitions": partitions,
    }

    _history_buffer.append({
        "time": now_time_str,
        "cpu": cpu_pct,
        "memory": mem_pct,
        "upload_kbps": upload_kbps,
        "download_kbps": download_kbps,
    })
    snapshot["history"] = list(_history_buffer)

    with _telemetry_lock:
        _latest_health = snapshot
        _cached_processes = all_sorted


def _background_worker():
    p = _get_psutil()
    if p:
        try:
            p.cpu_percent(interval=None)
            for proc in p.process_iter(['pid', 'cpu_percent']):
                pass
        except Exception:
            pass

    time.sleep(0.5)

    while not _stop_collector.is_set():
        try:
            _collect_telemetry_snapshot()
        except Exception as e:
            logger.error(f"Error in telemetry collector: {e}")
        time.sleep(1.5)


def start_collector_thread():
    global _collector_thread
    if _collector_thread is None or not _collector_thread.is_alive():
        _collector_thread = threading.Thread(target=_background_worker, name="HealthCollector", daemon=True)
        _collector_thread.start()
        logger.info("System Health background collector thread started.")


def get_system_health() -> Dict[str, Any]:
    """Get comprehensive system health information (instantaneous response)."""
    start_collector_thread()
    with _telemetry_lock:
        if _latest_health:
            return dict(_latest_health)

    _collect_telemetry_snapshot()
    with _telemetry_lock:
        return dict(_latest_health)


def get_processes(
    search: Optional[str] = None,
    sort_by: str = "cpu",
    order: str = "desc",
    limit: int = 150
) -> Dict[str, Any]:
    """Filter, sort, and return running processes for Task Manager."""
    start_collector_thread()
    with _telemetry_lock:
        procs = list(_cached_processes)
        total_count = _latest_health.get("processes", {}).get("total_count", len(procs))

    if search:
        s = search.lower().strip()
        procs = [p for p in procs if s in p["name"].lower() or s in str(p["pid"])]

    reverse = (order.lower() == "desc")
    if sort_by == "cpu":
        procs.sort(key=lambda x: x.get("cpu", 0.0), reverse=reverse)
    elif sort_by in ("memory", "memory_mb"):
        procs.sort(key=lambda x: x.get("memory_mb", 0.0), reverse=reverse)
    elif sort_by == "name":
        procs.sort(key=lambda x: x.get("name", "").lower(), reverse=reverse)
    elif sort_by == "pid":
        procs.sort(key=lambda x: x.get("pid", 0), reverse=reverse)
    elif sort_by == "status":
        procs.sort(key=lambda x: x.get("status", ""), reverse=reverse)

    return {
        "processes": procs[:limit],
        "total_matching": len(procs),
        "total_running": total_count,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def kill_process(pid: int, force: bool = False) -> Dict[str, Any]:
    """Terminate or kill a process by PID."""
    if pid <= 4:
        raise HTTPException(status_code=400, detail="Cannot terminate core operating system process (PID <= 4)")
    if pid == os.getpid():
        raise HTTPException(status_code=400, detail="Cannot terminate the ThreatShield server process")

    p = _get_psutil()
    if not p:
        raise HTTPException(status_code=500, detail="psutil not available on server")

    try:
        proc = p.Process(pid)
        proc_name = proc.name()
        if force:
            proc.kill()
        else:
            proc.terminate()

        threading.Thread(target=_collect_telemetry_snapshot, daemon=True).start()

        return {
            "success": True,
            "message": f"Process '{proc_name}' (PID: {pid}) terminated successfully.",
            "pid": pid,
            "name": proc_name,
        }
    except p.NoSuchProcess:
        raise HTTPException(status_code=404, detail=f"Process with PID {pid} not found or has already exited.")
    except p.AccessDenied:
        raise HTTPException(status_code=403, detail=f"Access denied: insufficient administrative permissions to terminate PID {pid}.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to terminate process {pid}: {str(e)}")


# Auto-start collector daemon on module load
try:
    start_collector_thread()
except Exception as e:
    logger.warning(f"Could not auto-start health collector: {e}")

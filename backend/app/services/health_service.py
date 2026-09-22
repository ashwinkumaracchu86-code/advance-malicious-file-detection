import os
import platform
import logging
import time
from typing import Dict, Any, List
from datetime import datetime, timezone

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


def get_system_health() -> Dict[str, Any]:
    """Get comprehensive system health information."""
    resources = _get_resource_usage()
    health = {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "system": _get_system_info(),
        "resources": resources,
        "services": _get_service_status(),
        "network": _get_network_io(),
        "processes": _get_process_info(),
        "uptime": _get_uptime(),
        "cpu_info": _get_cpu_info(),
        "memory_detail": _get_memory_detail(),
        "disk_partitions": _get_disk_partitions(),
    }

    cpu = resources["cpu_percent"]
    memory = resources["memory_percent"]
    disk = resources["disk_percent"]

    if cpu > 90 or memory > 90 or disk > 95:
        health["status"] = "critical"
    elif cpu > 70 or memory > 70 or disk > 80:
        health["status"] = "warning"

    return health


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


def _get_resource_usage() -> Dict[str, Any]:
    result = {
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "memory_used_mb": 0,
        "memory_total_mb": 0,
        "disk_percent": 0.0,
        "disk_used_gb": 0,
        "disk_total_gb": 0,
    }

    p = _get_psutil()
    if not p:
        return result

    try:
        result["cpu_percent"] = p.cpu_percent(interval=None)
    except Exception:
        pass

    try:
        mem = p.virtual_memory()
        result["memory_percent"] = mem.percent
        result["memory_used_mb"] = round(mem.used / (1024 * 1024), 1)
        result["memory_total_mb"] = round(mem.total / (1024 * 1024), 1)
    except Exception:
        pass

    try:
        disk_path = "C:\\" if platform.system() == "Windows" else "/"
        disk = p.disk_usage(disk_path)
        result["disk_percent"] = disk.percent
        result["disk_used_gb"] = round(disk.used / (1024 ** 3), 2)
        result["disk_total_gb"] = round(disk.total / (1024 ** 3), 2)
    except Exception:
        pass

    return result


def _get_cpu_info() -> Dict[str, Any]:
    info = {
        "physical_cores": 0,
        "logical_cores": 0,
        "frequency_current": 0,
        "frequency_max": 0,
        "frequency_min": 0,
        "load_avg_1m": 0,
        "load_avg_5m": 0,
        "load_avg_15m": 0,
        "ctx_switches": 0,
        "interrupts": 0,
    }
    p = _get_psutil()
    if not p:
        return info

    try:
        info["physical_cores"] = p.cpu_count(logical=False) or 0
        info["logical_cores"] = p.cpu_count(logical=True) or 0
        freq = p.cpu_freq()
        if freq:
            info["frequency_current"] = round(freq.current, 0)
            info["frequency_max"] = round(freq.max, 0) if freq.max else 0
            info["frequency_min"] = round(freq.min, 0) if freq.min else 0
        if hasattr(p, 'getloadavg'):
            load = p.getloadavg()
            info["load_avg_1m"] = round(load[0], 2)
            info["load_avg_5m"] = round(load[1], 2)
            info["load_avg_15m"] = round(load[2], 2)
        ctx = p.cpu_stats()
        info["ctx_switches"] = ctx.ctx_switches
        info["interrupts"] = ctx.interrupts
    except Exception as e:
        logger.debug(f"CPU info partial: {e}")
    return info


def _get_memory_detail() -> Dict[str, Any]:
    detail = {
        "swap_total_mb": 0,
        "swap_used_mb": 0,
        "swap_percent": 0,
        "available_mb": 0,
        "buffers_mb": 0,
        "cached_mb": 0,
        "total_bytes": 0,
        "used_bytes": 0,
        "available_bytes": 0,
    }
    p = _get_psutil()
    if not p:
        return detail

    try:
        mem = p.virtual_memory()
        detail["total_bytes"] = mem.total
        detail["used_bytes"] = mem.used
        detail["available_bytes"] = mem.available
        detail["available_mb"] = round(mem.available / (1024 * 1024), 1)
        detail["buffers_mb"] = round(getattr(mem, 'buffers', 0) / (1024 * 1024), 1)
        detail["cached_mb"] = round(getattr(mem, 'cached', 0) / (1024 * 1024), 1)
        swap = p.swap_memory()
        detail["swap_total_mb"] = round(swap.total / (1024 * 1024), 1)
        detail["swap_used_mb"] = round(swap.used / (1024 * 1024), 1)
        detail["swap_percent"] = swap.percent
    except Exception:
        pass
    return detail


def _get_network_io() -> Dict[str, Any]:
    net = {
        "bytes_sent": 0,
        "bytes_recv": 0,
        "packets_sent": 0,
        "packets_recv": 0,
        "bytes_sent_mb": 0,
        "bytes_recv_mb": 0,
        "interfaces": [],
    }
    p = _get_psutil()
    if not p:
        return net

    try:
        io = p.net_io_counters()
        net["bytes_sent"] = io.bytes_sent
        net["bytes_recv"] = io.bytes_recv
        net["packets_sent"] = io.packets_sent
        net["packets_recv"] = io.packets_recv
        net["bytes_sent_mb"] = round(io.bytes_sent / (1024 * 1024), 2)
        net["bytes_recv_mb"] = round(io.bytes_recv / (1024 * 1024), 2)
        addrs = p.net_if_addrs()
        for iface, addr_list in addrs.items():
            for addr in addr_list:
                if addr.family.name == 'AF_INET':
                    net["interfaces"].append({
                        "name": iface,
                        "ip": addr.address,
                        "netmask": addr.netmask,
                    })
    except Exception:
        pass
    return net


def _get_process_info() -> Dict[str, Any]:
    proc = {
        "total_count": 0,
        "running": 0,
        "sleeping": 0,
        "top_cpu": [],
        "top_memory": [],
    }
    p = _get_psutil()
    if not p:
        return proc

    try:
        procs = p.pids()
        proc["total_count"] = len(procs)

        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

        snapshots = []
        for pid in procs:
            try:
                ps = p.Process(pid)
                status = ps.status()
                if status == p.STATUS_RUNNING:
                    proc["running"] += 1
                elif status in (p.STATUS_SLEEPING, p.STATUS_IDLE, p.STATUS_DISK_SLEEP):
                    proc["sleeping"] += 1
                cpu_pct = ps.cpu_percent(interval=None)
                mem_pct = ps.memory_percent()
                name = ps.name()
                snapshots.append({"pid": pid, "name": name, "cpu": round(cpu_pct, 1), "memory": round(mem_pct, 1)})
            except (p.NoSuchProcess, p.AccessDenied, p.ZombieProcess):
                pass

        proc["top_cpu"] = sorted(snapshots, key=lambda x: x["cpu"], reverse=True)[:10]
        proc["top_memory"] = sorted(snapshots, key=lambda x: x["memory"], reverse=True)[:10]
    except Exception as e:
        logger.debug(f"Process info partial: {e}")
    return proc


def _get_uptime() -> Dict[str, Any]:
    up = {
        "boot_time": "",
        "uptime_seconds": 0,
        "uptime_human": "",
    }
    p = _get_psutil()
    if not p:
        return up

    try:
        boot = p.boot_time()
        boot_dt = datetime.fromtimestamp(boot, tz=timezone.utc)
        up["boot_time"] = boot_dt.isoformat()
        delta = time.time() - boot
        up["uptime_seconds"] = int(delta)
        days = int(delta // 86400)
        hours = int((delta % 86400) // 3600)
        mins = int((delta % 3600) // 60)
        up["uptime_human"] = f"{days}d {hours}h {mins}m"
    except Exception:
        pass
    return up


def _get_disk_partitions() -> List[Dict[str, Any]]:
    parts = []
    p = _get_psutil()
    if not p:
        return parts

    try:
        for part in p.disk_partitions():
            try:
                usage = p.disk_usage(part.mountpoint)
                parts.append({
                    "device": part.device,
                    "mountpoint": part.mountpoint,
                    "fstype": part.fstype,
                    "total_gb": round(usage.total / (1024 ** 3), 2),
                    "used_gb": round(usage.used / (1024 ** 3), 2),
                    "free_gb": round(usage.free / (1024 ** 3), 2),
                    "percent": usage.percent,
                })
            except (PermissionError, OSError):
                pass
    except Exception:
        pass
    return parts


def _get_service_status() -> Dict[str, Any]:
    from ..scanner.clamav_scanner import get_clamav_status

    clamav = get_clamav_status()

    return {
        "database": "active",
        "clamav": "active" if clamav["available"] else "unavailable",
        "realtime_protection": "active",
    }

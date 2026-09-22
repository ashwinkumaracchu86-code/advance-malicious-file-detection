import os
import json
import time
import socket
import logging
import threading
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "system_settings.json")

_firewall_lock = threading.Lock()

_enabled = True
_zones: List[Dict[str, Any]] = []
_inter_zone_rules: List[Dict[str, Any]] = []
_services: List[Dict[str, Any]] = []
_blocked_ips: Dict[str, int] = {}
_connection_log: List[Dict[str, Any]] = []
_stats = {
    "total_blocked": 0,
    "total_allowed": 0,
    "total_connections": 0,
    "public_to_dmz_blocked": 0,
    "public_to_internal_blocked": 0,
    "dmz_to_internal_blocked": 0,
    "intra_zone_allowed": 0,
}
_zone_traffic: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

_ip_zone_cache: Dict[str, str] = {}
_cache_timestamp = 0
_CACHE_TTL = 10

_last_connections = []
_connections_timestamp = 0
_CONNECTIONS_TTL = 3

DEFAULT_ZONES = [
    {"id": 1, "name": "Public", "type": "public", "color": "#ef4444", "description": "Untrusted - Internet-facing", "cidrs": ["0.0.0.0/0"], "enabled": True, "icon": "globe", "default_policy": "allow"},
    {"id": 2, "name": "DMZ", "type": "dmz", "color": "#f59e0b", "description": "Semi-trusted - Public services", "cidrs": ["172.16.0.0/12", "192.168.100.0/24"], "enabled": True, "icon": "shield", "default_policy": "deny"},
    {"id": 3, "name": "Internal", "type": "internal", "color": "#22c55e", "description": "Trusted - Private network", "cidrs": ["192.168.0.0/16", "10.0.0.0/8"], "enabled": True, "icon": "server", "default_policy": "deny"},
    {"id": 4, "name": "Management", "type": "management", "color": "#8b5cf6", "description": "Admin access only", "cidrs": ["192.168.1.1/32", "192.168.1.2/32"], "enabled": True, "icon": "terminal", "default_policy": "deny"},
]

DEFAULT_INTER_ZONE_RULES = [
    {"id": 1, "name": "Public to DMZ - Web", "source_zone": "Public", "dest_zone": "DMZ", "protocol": "tcp", "ports": [80, 443, 8080, 8443], "action": "allow", "enabled": True, "priority": 10, "description": "Web traffic to DMZ"},
    {"id": 2, "name": "Public to DMZ - SMTP", "source_zone": "Public", "dest_zone": "DMZ", "protocol": "tcp", "ports": [25, 587, 465], "action": "allow", "enabled": True, "priority": 11, "description": "Email to DMZ mail server"},
    {"id": 3, "name": "Public to DMZ - DNS", "source_zone": "Public", "dest_zone": "DMZ", "protocol": "udp", "ports": [53], "action": "allow", "enabled": True, "priority": 12, "description": "DNS queries"},
    {"id": 4, "name": "Block Public to Internal", "source_zone": "Public", "dest_zone": "Internal", "protocol": "*", "ports": [], "action": "block", "enabled": True, "priority": 1, "description": "Block direct Internet to Internal"},
    {"id": 5, "name": "Block Public to Management", "source_zone": "Public", "dest_zone": "Management", "protocol": "*", "ports": [], "action": "block", "enabled": True, "priority": 1, "description": "Block Internet to Management"},
    {"id": 6, "name": "DMZ to Internal - Proxy", "source_zone": "DMZ", "dest_zone": "Internal", "protocol": "tcp", "ports": [8080, 8443], "action": "allow", "enabled": True, "priority": 20, "description": "DMZ proxy to internal"},
    {"id": 7, "name": "Block DMZ to Management", "source_zone": "DMZ", "dest_zone": "Management", "protocol": "*", "ports": [], "action": "block", "enabled": True, "priority": 2, "description": "Block DMZ to Management"},
    {"id": 8, "name": "Internal to DMZ - Full", "source_zone": "Internal", "dest_zone": "DMZ", "protocol": "*", "ports": [], "action": "allow", "enabled": True, "priority": 30, "description": "Internal manages DMZ"},
    {"id": 9, "name": "Internal to Public - Outbound", "source_zone": "Internal", "dest_zone": "Public", "protocol": "*", "ports": [], "action": "allow", "enabled": True, "priority": 31, "description": "Internal internet access"},
    {"id": 10, "name": "Management to All", "source_zone": "Management", "dest_zone": "Public", "protocol": "*", "ports": [], "action": "allow", "enabled": True, "priority": 5, "description": "Management full access"},
    {"id": 11, "name": "Management to DMZ", "source_zone": "Management", "dest_zone": "DMZ", "protocol": "*", "ports": [], "action": "allow", "enabled": True, "priority": 5, "description": "Management manages DMZ"},
    {"id": 12, "name": "Management to Internal", "source_zone": "Management", "dest_zone": "Internal", "protocol": "*", "ports": [], "action": "allow", "enabled": True, "priority": 5, "description": "Management manages Internal"},
    {"id": 13, "name": "Block Telnet to DMZ", "source_zone": "Public", "dest_zone": "DMZ", "protocol": "tcp", "ports": [23], "action": "block", "enabled": True, "priority": 0, "description": "Block Telnet"},
    {"id": 14, "name": "Block RDP to Internal", "source_zone": "Public", "dest_zone": "Internal", "protocol": "tcp", "ports": [3389], "action": "block", "enabled": True, "priority": 0, "description": "Block RDP from internet"},
]

DEFAULT_SERVICES = [
    {"id": 1, "name": "Web Server", "zone": "DMZ", "ip": "172.16.0.10", "ports": [80, 443], "protocol": "tcp", "status": "running", "icon": "globe"},
    {"id": 2, "name": "Mail Server", "zone": "DMZ", "ip": "172.16.0.20", "ports": [25, 587, 465, 993, 995], "protocol": "tcp", "status": "running", "icon": "mail"},
    {"id": 3, "name": "DNS Server", "zone": "DMZ", "ip": "172.16.0.30", "ports": [53], "protocol": "udp", "status": "running", "icon": "server"},
    {"id": 4, "name": "Database", "zone": "Internal", "ip": "192.168.1.50", "ports": [3306, 5432], "protocol": "tcp", "status": "running", "icon": "database"},
    {"id": 5, "name": "File Server", "zone": "Internal", "ip": "192.168.1.60", "ports": [445, 139], "protocol": "tcp", "status": "running", "icon": "folder"},
    {"id": 6, "name": "Admin Console", "zone": "Management", "ip": "192.168.1.1", "ports": [22, 443], "protocol": "tcp", "status": "running", "icon": "terminal"},
    {"id": 7, "name": "Log Collector", "zone": "Management", "ip": "192.168.1.2", "ports": [514, 1514], "protocol": "tcp", "status": "running", "icon": "activity"},
    {"id": 8, "name": "Load Balancer", "zone": "DMZ", "ip": "172.16.0.5", "ports": [80, 443, 8080], "protocol": "tcp", "status": "running", "icon": "shuffle"},
]


def _load_settings():
    global _enabled, _zones, _inter_zone_rules, _services
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
            fw = data.get("firewall", {})
            if fw:
                _enabled = fw.get("enabled", True)
                _zones = fw.get("zones", None) or DEFAULT_ZONES
                _inter_zone_rules = fw.get("inter_zone_rules", None) or DEFAULT_INTER_ZONE_RULES
                _services = fw.get("services", None) or DEFAULT_SERVICES
            else:
                _zones = DEFAULT_ZONES.copy()
                _inter_zone_rules = DEFAULT_INTER_ZONE_RULES.copy()
                _services = DEFAULT_SERVICES.copy()
                _save_settings()
        else:
            _zones = DEFAULT_ZONES.copy()
            _inter_zone_rules = DEFAULT_INTER_ZONE_RULES.copy()
            _services = DEFAULT_SERVICES.copy()
            _save_settings()
    except Exception as e:
        logger.warning(f"Failed to load firewall settings: {e}")
        _enabled = True
        _zones = DEFAULT_ZONES.copy()
        _inter_zone_rules = DEFAULT_INTER_ZONE_RULES.copy()
        _services = DEFAULT_SERVICES.copy()


def _save_settings():
    try:
        data = {}
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                data = json.load(f)
        data["firewall"] = {
            "enabled": _enabled,
            "zones": _zones,
            "inter_zone_rules": _inter_zone_rules,
            "services": _services,
        }
        with open(SETTINGS_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        logger.error(f"Failed to save firewall settings: {e}")


def _rebuild_ip_cache():
    global _ip_zone_cache, _cache_timestamp
    now = time.time()
    if now - _cache_timestamp < _CACHE_TTL and _ip_zone_cache:
        return
    new_cache = {}
    for zone in _zones:
        if not zone.get("enabled", True):
            continue
        for cidr in zone.get("cidrs", []):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                new_cache[cidr] = zone["name"]
            except Exception:
                pass
    _ip_zone_cache = new_cache
    _cache_timestamp = now


def _get_zone_for_ip(ip: str) -> Optional[Dict[str, Any]]:
    _rebuild_ip_cache()
    best_zone = None
    best_prefix = -1
    try:
        ip_addr = ipaddress.ip_address(ip)
    except Exception:
        return None
    for zone in _zones:
        if not zone.get("enabled", True):
            continue
        for cidr in zone.get("cidrs", []):
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if ip_addr in net:
                    prefix_len = net.prefixlen
                    if prefix_len > best_prefix:
                        best_prefix = prefix_len
                        best_zone = zone
            except Exception:
                pass
    return best_zone


def _find_rule_for_zones(source_zone_name: str, dest_zone_name: str, protocol: str, port: int) -> Optional[Dict[str, Any]]:
    best = None
    best_priority = 999
    for rule in _inter_zone_rules:
        if not rule.get("enabled", True):
            continue
        if rule["source_zone"] != source_zone_name or rule["dest_zone"] != dest_zone_name:
            continue
        if rule["protocol"] != "*" and rule["protocol"].lower() != protocol.lower():
            continue
        if rule.get("ports") and port not in rule["ports"]:
            continue
        pri = rule.get("priority", 99)
        if pri < best_priority:
            best_priority = pri
            best = rule
    return best


def check_connection(remote_ip: str, remote_port: int, local_ip: str, local_port: int, protocol: str = "tcp") -> Dict[str, Any]:
    with _firewall_lock:
        _stats["total_connections"] += 1

        if not _enabled:
            _stats["total_allowed"] += 1
            return {"action": "allow", "reason": "Firewall disabled"}

        source_zone = _get_zone_for_ip(remote_ip)
        dest_zone = _get_zone_for_ip(local_ip)

        source_zone_name = source_zone["name"] if source_zone else "Unknown"
        dest_zone_name = dest_zone["name"] if dest_zone else "Unknown"

        _zone_traffic[source_zone_name][dest_zone_name] += 1

        if source_zone_name == dest_zone_name:
            _stats["intra_zone_allowed"] += 1
            _log_connection(remote_ip, remote_port, local_ip, local_port, protocol, "allowed", "Intra-zone", source_zone_name, dest_zone_name)
            return {"action": "allow", "reason": "Intra-zone", "source_zone": source_zone_name, "dest_zone": dest_zone_name}

        rule = _find_rule_for_zones(source_zone_name, dest_zone_name, protocol, remote_port)
        if rule:
            if rule["action"] == "allow":
                _stats["total_allowed"] += 1
                _log_connection(remote_ip, remote_port, local_ip, local_port, protocol, "allowed", rule["name"], source_zone_name, dest_zone_name)
                return {"action": "allow", "reason": rule["name"], "rule_id": rule["id"], "source_zone": source_zone_name, "dest_zone": dest_zone_name}
            else:
                _stats["total_blocked"] += 1
                _blocked_ips[remote_ip] = _blocked_ips.get(remote_ip, 0) + 1
                if source_zone_name == "Public" and dest_zone_name == "Internal":
                    _stats["public_to_internal_blocked"] += 1
                elif source_zone_name == "Public" and dest_zone_name == "DMZ":
                    _stats["public_to_dmz_blocked"] += 1
                elif source_zone_name == "DMZ" and dest_zone_name == "Internal":
                    _stats["dmz_to_internal_blocked"] += 1
                _log_connection(remote_ip, remote_port, local_ip, local_port, protocol, "blocked", rule["name"], source_zone_name, dest_zone_name)
                return {"action": "block", "reason": rule["name"], "rule_id": rule["id"], "source_zone": source_zone_name, "dest_zone": dest_zone_name}

        dest_policy = dest_zone.get("default_policy", "deny") if dest_zone else "deny"
        if dest_policy == "deny":
            _stats["total_blocked"] += 1
            _blocked_ips[remote_ip] = _blocked_ips.get(remote_ip, 0) + 1
            _log_connection(remote_ip, remote_port, local_ip, local_port, protocol, "blocked", f"Default deny ({dest_zone_name})", source_zone_name, dest_zone_name)
            return {"action": "block", "reason": f"Default deny ({dest_zone_name})", "source_zone": source_zone_name, "dest_zone": dest_zone_name}

        _stats["total_allowed"] += 1
        _log_connection(remote_ip, remote_port, local_ip, local_port, protocol, "allowed", "Default allow", source_zone_name, dest_zone_name)
        return {"action": "allow", "reason": "Default allow", "source_zone": source_zone_name, "dest_zone": dest_zone_name}


def _log_connection(remote_ip, remote_port, local_ip, local_port, protocol, action, reason, source_zone, dest_zone):
    entry = {
        "id": len(_connection_log) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "remote_ip": remote_ip, "remote_port": remote_port,
        "local_ip": local_ip, "local_port": local_port,
        "protocol": protocol, "action": action, "reason": reason,
        "source_zone": source_zone, "dest_zone": dest_zone,
    }
    _connection_log.insert(0, entry)
    if len(_connection_log) > 5000:
        _connection_log[:] = _connection_log[:5000]


def get_active_connections() -> List[Dict[str, Any]]:
    global _last_connections, _connections_timestamp
    now = time.time()
    if now - _connections_timestamp < _CONNECTIONS_TTL and _last_connections:
        return _last_connections
    connections = []
    try:
        import psutil
        for conn in psutil.net_connections(kind="inet"):
            if conn.status == "ESTABLISHED":
                laddr = conn.laddr
                raddr = conn.raddr
                remote_ip = raddr.ip if raddr else ""
                local_ip = laddr.ip if laddr else ""
                source_zone = _get_zone_for_ip(remote_ip)
                dest_zone = _get_zone_for_ip(local_ip)
                connections.append({
                    "local_ip": local_ip, "local_port": laddr.port if laddr else 0,
                    "remote_ip": remote_ip, "remote_port": raddr.port if raddr else 0,
                    "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "status": conn.status, "pid": conn.pid,
                    "process_name": _get_process_name(conn.pid) if conn.pid else "",
                    "source_zone": source_zone["name"] if source_zone else "Unknown",
                    "dest_zone": dest_zone["name"] if dest_zone else "Unknown",
                })
    except Exception as e:
        logger.debug(f"Failed to get connections: {e}")
    _last_connections = connections
    _connections_timestamp = now
    return connections


def _get_process_name(pid: int) -> str:
    try:
        import psutil
        return psutil.Process(pid).name()
    except Exception:
        return ""


def get_firewall_status() -> Dict[str, Any]:
    with _firewall_lock:
        return {
            "enabled": _enabled,
            "zones": [{**z, "service_count": len([s for s in _services if s.get("zone") == z["name"]])} for z in _zones],
            "total_rules": len(_inter_zone_rules),
            "active_rules": len([r for r in _inter_zone_rules if r.get("enabled", True)]),
            "blocked_ips_count": len(_blocked_ips),
            "stats": _stats.copy(),
            "zone_traffic": {z: dict(t) for z, t in _zone_traffic.items()},
        }


def get_zones() -> List[Dict[str, Any]]:
    with _firewall_lock:
        return _zones.copy()


def add_zone(zone: Dict[str, Any]) -> Dict[str, Any]:
    with _firewall_lock:
        max_id = max((z.get("id", 0) for z in _zones), default=0)
        new_zone = {"id": max_id + 1, "name": zone.get("name", "New Zone"), "type": zone.get("type", "custom"), "color": zone.get("color", "#6b7280"), "description": zone.get("description", ""), "cidrs": zone.get("cidrs", []), "enabled": True, "icon": zone.get("icon", "circle"), "default_policy": zone.get("default_policy", "deny")}
        _zones.append(new_zone)
        _ip_zone_cache.clear()
        result = new_zone.copy()
    _save_settings_async()
    return result


def update_zone(zone_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    result = None
    with _firewall_lock:
        for zone in _zones:
            if zone["id"] == zone_id:
                zone.update({k: v for k, v in updates.items() if k != "id"})
                _ip_zone_cache.clear()
                result = zone.copy()
                break
    if result:
        _save_settings_async()
    return result


def delete_zone(zone_id: int) -> bool:
    global _zones
    with _firewall_lock:
        original_len = len(_zones)
        _zones = [z for z in _zones if z["id"] != zone_id]
        deleted = len(_zones) < original_len
        if deleted:
            _ip_zone_cache.clear()
    if deleted:
        _save_settings_async()
    return deleted


def toggle_zone(zone_id: int) -> Optional[Dict[str, Any]]:
    with _firewall_lock:
        for zone in _zones:
            if zone["id"] == zone_id:
                zone["enabled"] = not zone.get("enabled", True)
                _ip_zone_cache.clear()
                result = zone.copy()
    _save_settings_async()
    return result if result else None


def get_inter_zone_rules() -> List[Dict[str, Any]]:
    with _firewall_lock:
        return _inter_zone_rules.copy()


def add_inter_zone_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    with _firewall_lock:
        max_id = max((r.get("id", 0) for r in _inter_zone_rules), default=0)
        new_rule = {"id": max_id + 1, "name": rule.get("name", "Unnamed"), "source_zone": rule.get("source_zone", "Public"), "dest_zone": rule.get("dest_zone", "Internal"), "protocol": rule.get("protocol", "tcp"), "ports": rule.get("ports", []), "action": rule.get("action", "block"), "enabled": True, "priority": rule.get("priority", 50), "description": rule.get("description", "")}
        _inter_zone_rules.append(new_rule)
        result = new_rule.copy()
    _save_settings_async()
    return result


def update_inter_zone_rule(rule_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    result = None
    with _firewall_lock:
        for rule in _inter_zone_rules:
            if rule["id"] == rule_id:
                rule.update({k: v for k, v in updates.items() if k != "id"})
                result = rule.copy()
                break
    if result:
        _save_settings_async()
    return result


def delete_inter_zone_rule(rule_id: int) -> bool:
    global _inter_zone_rules
    with _firewall_lock:
        original_len = len(_inter_zone_rules)
        _inter_zone_rules = [r for r in _inter_zone_rules if r["id"] != rule_id]
        deleted = len(_inter_zone_rules) < original_len
    if deleted:
        _save_settings_async()
    return deleted


def toggle_inter_zone_rule(rule_id: int) -> Optional[Dict[str, Any]]:
    result = None
    with _firewall_lock:
        for rule in _inter_zone_rules:
            if rule["id"] == rule_id:
                rule["enabled"] = not rule.get("enabled", True)
                result = rule.copy()
                break
    if result:
        _save_settings_async()
    return result


def get_services() -> List[Dict[str, Any]]:
    with _firewall_lock:
        return _services.copy()


def add_service(service: Dict[str, Any]) -> Dict[str, Any]:
    with _firewall_lock:
        max_id = max((s.get("id", 0) for s in _services), default=0)
        new_svc = {"id": max_id + 1, "name": service.get("name", "New Service"), "zone": service.get("zone", "DMZ"), "ip": service.get("ip", ""), "ports": service.get("ports", []), "protocol": service.get("protocol", "tcp"), "status": "running", "icon": service.get("icon", "server")}
        _services.append(new_svc)
        result = new_svc.copy()
    _save_settings_async()
    return result


def update_service(service_id: int, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    result = None
    with _firewall_lock:
        for svc in _services:
            if svc["id"] == service_id:
                svc.update({k: v for k, v in updates.items() if k != "id"})
                result = svc.copy()
                break
    if result:
        _save_settings_async()
    return result


def delete_service(service_id: int) -> bool:
    global _services
    with _firewall_lock:
        original_len = len(_services)
        _services = [s for s in _services if s["id"] != service_id]
        deleted = len(_services) < original_len
    if deleted:
        _save_settings_async()
    return deleted


def get_blocked_ips() -> List[Dict[str, Any]]:
    with _firewall_lock:
        return [{"ip": ip, "attempts": count} for ip, count in sorted(_blocked_ips.items(), key=lambda x: x[1], reverse=True)]


def unblock_ip(ip: str) -> bool:
    with _firewall_lock:
        if ip in _blocked_ips:
            del _blocked_ips[ip]
            return True
        return False


def get_connection_logs(limit: int = 200, action_filter: str = None) -> List[Dict[str, Any]]:
    with _firewall_lock:
        logs = _connection_log[:limit]
        if action_filter:
            logs = [l for l in logs if l["action"] == action_filter]
        return logs


def clear_connection_log():
    with _firewall_lock:
        _connection_log.clear()
        _stats.update({"total_blocked": 0, "total_allowed": 0, "total_connections": 0, "public_to_dmz_blocked": 0, "public_to_internal_blocked": 0, "dmz_to_internal_blocked": 0, "intra_zone_allowed": 0})
        _zone_traffic.clear()


def get_zone_traffic_matrix() -> Dict[str, Any]:
    with _firewall_lock:
        return {z1["name"]: {z2["name"]: _zone_traffic[z1["name"]][z2["name"]] for z2 in _zones} for z1 in _zones}


def get_zone_connections(zone_name: str) -> List[Dict[str, Any]]:
    with _firewall_lock:
        return [l for l in _connection_log if l.get("source_zone") == zone_name or l.get("dest_zone") == zone_name]


def _save_settings_async():
    threading.Thread(target=_save_settings, daemon=True).start()


def set_firewall_enabled(enabled: bool):
    global _enabled
    with _firewall_lock:
        _enabled = enabled
    _save_settings_async()


def initialize():
    global _enabled, _zones, _inter_zone_rules, _services
    _enabled = True
    _zones = DEFAULT_ZONES.copy()
    _inter_zone_rules = DEFAULT_INTER_ZONE_RULES.copy()
    _services = DEFAULT_SERVICES.copy()
    _ip_zone_cache.clear()
    _load_settings()
    logger.info(f"Firewall initialized: enabled={_enabled}, zones={len(_zones)}, rules={len(_inter_zone_rules)}, services={len(_services)}")


initialize()

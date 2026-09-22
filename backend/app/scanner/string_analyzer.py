import re
import os
from typing import Dict, List


SUSPICIOUS_URLS = re.compile(
    r"(https?://[^\s\"'<>]{5,})", re.IGNORECASE
)

IP_ADDRESSES = re.compile(
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
)

SHELL_COMMANDS = re.compile(
    r"\b(exec|system|popen|eval|subprocess|shell|cmd|powershell|bash|sh|"
    r"cmd\.exe|/bin/sh|/bin/bash|wscript|cscript|mshta|rundll32|regsvr32|"
    r"certutil|bitsadmin|wmic|net\s+user|net\s+localgroup|netsh)\b",
    re.IGNORECASE,
)

KNOWN_MALWARE_STRINGS = re.compile(
    r"(ransomware|decrypt|bitcoin|wallet|private\s+key|encrypt\s+your\s+files|"
    r"pay\s+ransom|tor\s+browser|onion\s+address|pastebin\.com/raw|"
    r"disable\s+task\s+manager|disable\s+registry|safe\s+mode|"
    r"bootkit|rootkit|keylogger|credential\s+dump|mimikatz|"
    r"metasploit|meterpreter|reverse\s+shell|bind\s+shell)\b",
    re.IGNORECASE,
)

BASE64_CONTENT = re.compile(
    r"[A-Za-z0-9+/]{40,}={0,2}"
)

REGISTRY_KEYS = re.compile(
    r"(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKLM|HKCU|"
    r"\\\\[a-zA-Z0-9_]+\\[a-zA-Z0-9_]+\\[a-zA-Z0-9_]+)",
    re.IGNORECASE,
)

SUSPICIOUS_PATHS = re.compile(
    r"(C:\\Windows\\System32|C:\\Windows\\SysWOW64|"
    r"/etc/passwd|/etc/shadow|/tmp/|/var/tmp/|"
    r"%TEMP%|%APPDATA%|%SYSTEMROOT%|"
    r"\\\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+)",
    re.IGNORECASE,
)

OBFUSCATION_PATTERNS = re.compile(
    r"(\\x[0-9a-fA-F]{2}){4,}|"
    r"(char\s*\(\s*\d+\s*\)\s*,?\s*){4,}|"
    r"(fromCharCode|String\.fromCharCode)|"
    r"(unescape|decodeURIComponent|atob)\s*\(",
    re.IGNORECASE,
)

PRIVILEGE_ESCALATION = re.compile(
    r"(sudo\s+-s|runas|\\\\.\\pipe\\|"
    r"SeDebugPrivilege|SeImpersonatePrivilege|"
    r"token\s+privilege|impersonate)\b",
    re.IGNORECASE,
)


def extract_suspicious_strings(file_path: str) -> Dict[str, any]:
    """Scan file for suspicious strings and patterns."""
    try:
        with open(file_path, "rb") as f:
            raw_data = f.read()
    except (OSError, IOError):
        return {"suspicious_strings": [], "count": 0}

    results = {
        "urls": [],
        "ip_addresses": [],
        "shell_commands": [],
        "known_malware_strings": [],
        "base64_blocks": [],
        "registry_keys": [],
        "suspicious_paths": [],
        "obfuscation_patterns": [],
        "privilege_escalation": [],
    }

    try:
        text_data = raw_data.decode("utf-8", errors="ignore")
    except Exception:
        text_data = ""

    for match in SUSPICIOUS_URLS.finditer(text_data):
        url = match.group(0)
        if "localhost" not in url and "127.0.0.1" not in url:
            results["urls"].append(url)

    for match in IP_ADDRESSES.finditer(text_data):
        ip = match.group(0)
        parts = ip.split(".")
        if not all(0 <= int(p) <= 255 for p in parts):
            continue
        if ip.startswith("0.") or ip.startswith("127."):
            continue
        results["ip_addresses"].append(ip)

    for match in SHELL_COMMANDS.finditer(text_data):
        results["shell_commands"].append(match.group(0))

    for match in KNOWN_MALWARE_STRINGS.finditer(text_data):
        results["known_malware_strings"].append(match.group(0))

    for match in BASE64_CONTENT.finditer(text_data):
        block = match.group(0)
        if len(block) > 100:
            results["base64_blocks"].append(block[:80] + "...")

    for match in REGISTRY_KEYS.finditer(text_data):
        results["registry_keys"].append(match.group(0))

    for match in SUSPICIOUS_PATHS.finditer(text_data):
        results["suspicious_paths"].append(match.group(0))

    for match in OBFUSCATION_PATTERNS.finditer(text_data):
        results["obfuscation_patterns"].append(match.group(0)[:100])

    for match in PRIVILEGE_ESCALATION.finditer(text_data):
        results["privilege_escalation"].append(match.group(0))

    all_suspicious = []
    for key, items in results.items():
        for item in items:
            all_suspicious.append({"type": key, "value": item})

    return {
        "suspicious_strings": all_suspicious,
        "count": len(all_suspicious),
        "details": results,
        "unique_urls": len(set(results["urls"])),
        "unique_ips": len(set(results["ip_addresses"])),
    }

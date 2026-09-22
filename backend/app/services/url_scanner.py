import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import hashlib

logger = logging.getLogger(__name__)

SUSPICIOUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.work', '.buzz']

PHISHING_KEYWORDS_IN_URL = [
    'login', 'signin', 'verify', 'account', 'secure', 'update',
    'confirm', 'password', 'credential', 'auth', 'banking',
    'paypal', 'apple', 'microsoft', 'google', 'amazon',
    'netflix', 'facebook', 'instagram', 'whatsapp',
]

LEGITIMATE_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'github.com', 'linkedin.com',
    'youtube.com', 'instagram.com', 'netflix.com', 'paypal.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
    'office.com', 'outlook.com', 'live.com', 'hotmail.com',
}

SHORTENER_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
    'buff.ly', 'ow.ly', 'shorte.st', 'adf.ly', 'bl.ink',
    'lnkd.in', 'rebrand.ly', 'cutt.ly', 'tiny.cc',
]


def analyze_url(url: str, context: str = "body") -> Dict[str, Any]:
    reasons = []
    score = 0.0

    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "url": url,
            "domain": "",
            "is_https": False,
            "is_ip_url": False,
            "is_shortened": False,
            "is_suspicious": True,
            "risk_score": 50.0,
            "reasons": ["Malformed URL"],
            "reputation": "unknown",
            "found_in": context,
        }

    domain = (parsed.hostname or "").lower()
    scheme = (parsed.scheme or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    is_https = scheme == "https"
    if not is_https:
        reasons.append("URL does not use HTTPS")
        score += 10

    ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    is_ip = bool(ip_pattern.match(domain))
    if is_ip:
        reasons.append(f"URL uses IP address instead of domain: {domain}")
        score += 25

    is_shortened = any(s in domain for s in SHORTENER_DOMAINS)
    if is_shortened:
        reasons.append(f"URL shortener detected: {domain}")
        score += 15

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Suspicious TLD detected: {tld}")
            score += 15
            break

    if domain.count('.') > 3:
        reasons.append(f"Excessive subdomains detected: {domain}")
        score += 10

    if re.search(r'@\w', url):
        reasons.append("URL contains @ symbol (possible obfuscation)")
        score += 20

    if '%' in url and re.search(r'%[0-9a-fA-F]{2}', url):
        encoded_chars = re.findall(r'%[0-9a-fA-F]{2}', url)
        if len(encoded_chars) > 3:
            reasons.append(f"Excessive URL encoding detected ({len(encoded_chars)} encoded characters)")
            score += 10

    punycode = domain.startswith('xn--') or any(part.startswith('xn--') for part in domain.split('.'))
    if punycode:
        reasons.append("Punycode/IDN domain detected (possible homograph attack)")
        score += 20

    for keyword in PHISHING_KEYWORDS_IN_URL:
        if keyword in domain.lower():
            if not any(legit in domain for legit in LEGITIMATE_DOMAINS):
                reasons.append(f"Phishing keyword in domain: '{keyword}'")
                score += 10
                break

    for brand, legit_domains in [
        ('microsoft', ['microsoft.com', 'office.com', 'outlook.com']),
        ('google', ['google.com', 'gmail.com']),
        ('apple', ['apple.com', 'icloud.com']),
        ('paypal', ['paypal.com']),
        ('amazon', ['amazon.com']),
        ('facebook', ['facebook.com', 'fb.com']),
    ]:
        if brand in domain and not any(ld in domain for ld in legit_domains):
            reasons.append(f"Possible brand impersonation: '{brand}' in domain '{domain}'")
            score += 20

    if re.search(r'\.(exe|scr|bat|cmd|com|pif|msi|vbs|js|wsf|ps1)\b', path.lower()):
        reasons.append(f"URL points to executable file: {path}")
        score += 25

    if len(url) > 200:
        reasons.append(f"Unusually long URL ({len(url)} characters)")
        score += 5

    if query and ('redirect' in query.lower() or 'url=' in query.lower() or 'next=' in query.lower()):
        reasons.append("URL contains redirect parameters")
        score += 10

    if re.search(r'//[^/]*@', url):
        reasons.append("URL contains embedded credentials")
        score += 25

    score = min(100.0, score)

    if score >= 60:
        reputation = "malicious"
    elif score >= 30:
        reputation = "suspicious"
    elif score >= 15:
        reputation = "questionable"
    else:
        reputation = "clean"

    return {
        "url": url,
        "domain": domain,
        "is_https": is_https,
        "is_ip_url": is_ip,
        "is_shortened": is_shortened,
        "is_suspicious": score >= 30,
        "is_phishing": score >= 60,
        "risk_score": round(score, 2),
        "reasons": reasons,
        "reputation": reputation,
        "found_in": context,
    }


def extract_and_analyze_urls(text: str, html: str = "", context: str = "body") -> List[Dict[str, Any]]:
    urls = set()

    url_pattern = re.compile(r'https?://[^\s<>"\')\]]+', re.IGNORECASE)
    for match in url_pattern.findall(text or ""):
        urls.add(match)

    href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in href_pattern.findall(html or ""):
        if match.startswith(('http://', 'https://')):
            urls.add(match)

    src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
    for match in src_pattern.findall(html or ""):
        if match.startswith(('http://', 'https://')):
            urls.add(match)

    results = []
    for url in urls:
        analysis = analyze_url(url, context)
        results.append(analysis)

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    return results


def get_url_summary(url_analyses: List[Dict]) -> Dict[str, Any]:
    total = len(url_analyses)
    suspicious = sum(1 for u in url_analyses if u.get("is_suspicious"))
    phishing = sum(1 for u in url_analyses if u.get("is_phishing"))
    https_count = sum(1 for u in url_analyses if u.get("is_https"))
    ip_urls = sum(1 for u in url_analyses if u.get("is_ip_url"))
    shortened = sum(1 for u in url_analyses if u.get("is_shortened"))

    avg_score = 0
    if total > 0:
        avg_score = sum(u.get("risk_score", 0) for u in url_analyses) / total

    return {
        "total_urls": total,
        "suspicious_urls": suspicious,
        "phishing_urls": phishing,
        "https_urls": https_count,
        "ip_urls": ip_urls,
        "shortened_urls": shortened,
        "average_risk_score": round(avg_score, 2),
    }

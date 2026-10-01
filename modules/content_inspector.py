import re
import ssl
import socket
import datetime
from typing import Dict, Any, List
import httpx
from bs4 import BeautifulSoup
from trustee_monitor.config import DEFAULT_TIMEOUT, SUSPICIOUS_KEYWORDS

PARKED_INDICATORS = [
    "buy this domain", "domain for sale", "parked free", "dan.com", "sedo",
    "godaddy", "namecheap", "hugedomains", "afternic", "bodis", "parkingcrew",
    "domain is registered", "under construction", "this website is for sale",
    "renew your domain", "inquire about this domain"
]

LEGAL_INDICATORS = [
    "law firm", "attorney", "legal services", "lawyer", "barrister", "solicitor",
    "адвокат", "адвокатська", "юридичні послуги", "юрист", "закон", "суд", "юридическая",
    "bankruptcy trustee", "court", "litigation", "estate planning", "trustee law",
    "law office", "legal counsel", "fiduciary services", "юридическая фирма"
]

CRITICAL_TRIGGERS = {
    "seed_phrase": [
        "seed phrase", "12 words", "24 words", "mnemonic phrase", "secret phrase",
        "secret recovery phrase", "enter seed", "recovery words", "сід фраза", "сид фраза"
    ],
    "private_key": [
        "private key", "private_key", "export private key", "import private key",
        "приватний ключ", "приватный ключ"
    ],
    "brand_spoofing": [
        "trustee plus", "trustee wallet", "trustee card", "trusteeplus",
        "trusteewallet", "картка trustee", "карта trustee"
    ],
    "malicious_action": [
        "restore wallet", "connect wallet", "claim airdrop", "claim bonus",
        "verify account", "download apk", "install trustee", "завантажити apk"
    ]
}

def get_ssl_info(domain: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """Retrieves SSL certificate issuer and age in days."""
    ssl_data = {
        "has_ssl": False,
        "issuer": None,
        "issued_days_ago": None,
        "valid": False
    }
    clean_domain = domain.lower().strip().rstrip(".")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((clean_domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                cert = ssock.getpeercert()
                ssl_data["has_ssl"] = True
                ssl_data["valid"] = True

                # Extract Issuer
                issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                issuer_name = issuer_dict.get('organizationName') or issuer_dict.get('commonName')
                ssl_data["issuer"] = issuer_name

                # Extract creation date
                not_before_str = cert.get('notBefore')
                if not_before_str:
                    not_before = datetime.datetime.strptime(not_before_str, '%b %d %H:%M:%S %Y %Z')
                    age_days = (datetime.datetime.utcnow() - not_before).days
                    ssl_data["issued_days_ago"] = max(0, age_days)
    except Exception:
        pass
    return ssl_data

async def inspect_content(domain: str, timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """
    Crawls the domain over HTTP/HTTPS, inspects content, titles, and triggers.
    """
    clean_domain = domain.lower().strip().rstrip(".")
    result = {
        "http_status": None,
        "final_url": None,
        "title": None,
        "is_parked": False,
        "matched_keywords": [],
        "triggered_categories": [],
        "trigger_details": [],
        "ssl_info": get_ssl_info(clean_domain, timeout=2.5),
        "content_length": 0,
        "error": None
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "uk,en-US;q=0.9,en;q=0.8"
    }

    # Try HTTPS first, then HTTP fallback
    urls_to_try = [f"https://{clean_domain}", f"http://{clean_domain}"]
    response = None

    async with httpx.AsyncClient(headers=headers, follow_redirects=True, verify=False, timeout=timeout) as client:
        for url in urls_to_try:
            try:
                resp = await client.get(url)
                if resp.status_code:
                    response = resp
                    result["final_url"] = str(resp.url)
                    result["http_status"] = resp.status_code
                    break
            except Exception as e:
                result["error"] = str(e)
                continue

    if not response or not response.text:
        return result

    html_text = response.text
    result["content_length"] = len(html_text)
    lower_text = html_text.lower()

    # Parse title & text
    try:
        soup = BeautifulSoup(html_text, 'html.parser')
        title_tag = soup.find('title')
        if title_tag and title_tag.string:
            result["title"] = title_tag.string.strip()[:200]
        visible_text = soup.get_text(separator=' ', strip=True).lower()
    except Exception:
        visible_text = lower_text

    result["is_legal_site"] = False

    # 1. Check for parked domain indicators
    for parked_phrase in PARKED_INDICATORS:
        if parked_phrase in visible_text:
            result["is_parked"] = True
            break

    # 1.1 Check for legal / attorney indicators (law firm, lawyer, advocate, etc.)
    for legal_phrase in LEGAL_INDICATORS:
        if legal_phrase in visible_text:
            result["is_legal_site"] = True
            break

    # 2. Check general suspicious keywords
    matched_kws = set()
    for kw in SUSPICIOUS_KEYWORDS:
        if re.search(r'\b' + re.escape(kw) + r'\b', visible_text):
            matched_kws.add(kw)
    result["matched_keywords"] = sorted(list(matched_kws))

    # 3. Check critical trigger categories
    for category, patterns in CRITICAL_TRIGGERS.items():
        cat_matches = []
        for pat in patterns:
            if pat in visible_text:
                cat_matches.append(pat)
        if cat_matches:
            result["triggered_categories"].append(category)
            result["trigger_details"].extend(cat_matches)

    return result

from typing import Dict, Any, Tuple, List
from trustee_monitor.config import LEGITIMATE_DOMAINS

def calculate_risk_score(
    dns_res: Dict[str, Any],
    content_res: Dict[str, Any],
    domain_name: str
) -> Tuple[int, str, List[str]]:
    """
    Evaluates heuristics and assigns a Risk Score (0-100), Status, and Triggers.
    Returns:
        (score: int, status: str, triggers: List[str])
    """
    clean_domain = domain_name.lower().strip().rstrip(".")

    # 0. Check Whitelist (Official Trustee domains & subdomains)
    legit_set = [d.lower() for d in LEGITIMATE_DOMAINS]
    if clean_domain in legit_set or any(clean_domain.endswith("." + d) for d in legit_set):
        return 0, "legitimate", ["Офіційний легітимний домен бренду TRUSTEE (Вайтліст)"]

    score = 0
    triggers = []
    status = "clean"

    # 1. Check basic DNS resolvability
    if not dns_res.get("is_resolvable"):
        return 0, "dormant", ["Домен не резолвиться (DNS NXDOMAIN)"]

    # 2. Email spoofing risk (MX records)
    has_mx = dns_res.get("has_mx", False)
    http_status = content_res.get("http_status")

    if has_mx:
        triggers.append(f"Налаштовано поштові сервери MX: {', '.join(dns_res['mx_records'][:2])}")
        if not http_status or http_status >= 400:
            score += 35
            triggers.append("Поштові MX-записи активні за відсутності робочого веб-сайту (ризик Email Spoofing)")
        else:
            score += 15

    # 3. Active Web server
    if http_status and http_status < 400:
        score += 15
        triggers.append(f"Активний веб-сервер (HTTP {http_status})")

    # 4. Parked domain penalty
    is_parked = content_res.get("is_parked", False)
    if is_parked:
        score = min(score, 25)
        return score, "parked", ["Домен припаркований (Parked / For Sale)"]

    # 5. SSL Certificate heuristics
    ssl_info = content_res.get("ssl_info", {})
    if ssl_info.get("has_ssl"):
        issuer = ssl_info.get("issuer") or ""
        age_days = ssl_info.get("issued_days_ago")

        if age_days is not None:
            if age_days <= 2:
                score += 25
                triggers.append(f"Дуже свіжий SSL-сертифікат (видано {age_days} дн. тому)")
            elif age_days <= 14:
                score += 15
                triggers.append(f"Свіжий SSL-сертифікат (вік {age_days} дн.)")

        # Free / automated SSL issuers frequently used in phishing
        if any(ca in issuer.lower() for ca in ["let's encrypt", "zerossl", "cloudflare", "cpanel"]):
            score += 10
            triggers.append(f"Використовується автоматизований безкоштовний SSL ({issuer})")

    # 6. Deep Content Triggers (The heaviest weight)
    triggered_cats = content_res.get("triggered_categories", [])
    trigger_details = content_res.get("trigger_details", [])

    if "seed_phrase" in triggered_cats:
        score += 50
        triggers.append(f"КРИТИЧНО: Виявлено збір сід-фраз/мнемоніки ({', '.join(trigger_details)})")

    if "private_key" in triggered_cats:
        score += 45
        triggers.append(f"КРИТИЧНО: Виявлено запит приватного ключа ({', '.join(trigger_details)})")

    if "brand_spoofing" in triggered_cats:
        score += 30
        triggers.append(f"Імітація бренду TRUSTEE у контенті сторінки ({', '.join(trigger_details)})")

    if "malicious_action" in triggered_cats:
        score += 25
        triggers.append(f"Підозріла дія: завантаження APK / підключення гаманця ({', '.join(trigger_details)})")

    # Matched secondary keywords
    matched_kws = content_res.get("matched_keywords", [])
    if len(matched_kws) >= 3:
        score += 15
        triggers.append(f"Збіг крипто-термінів ({len(matched_kws)} слів): {', '.join(matched_kws[:4])}")

    # Homoglyph / Punycode penalty if domain uses IDN
    if domain_name.startswith("xn--") or any(ord(c) > 127 for c in domain_name):
        score += 25
        triggers.append("Використано гомогліфи (Punycode / IDN маскування)")

    # 7. Legal / Attorney noise filter (Caps risk score for legal firms / lawyers)
    is_legal = content_res.get("is_legal_site", False)
    legal_domain_kws = ["law", "legal", "lawyer", "attorney", "advokat", "jurist", "court", "estate", "solicitor", "fiduciary", "trustee-help"]
    has_legal_domain_kw = any(lkw in clean_domain for lkw in legal_domain_kws)

    if (is_legal or has_legal_domain_kw) and not any(cat in triggered_cats for cat in ["seed_phrase", "private_key", "brand_spoofing"]):
        score = min(score, 20)
        triggers.append("Виявлено ознаки юридичної/адвокатської діяльності (легітимний семантичний шум)")

    # Cap at 100
    final_score = max(0, min(100, score))

    # Determine status
    if final_score >= 80:
        status = "active_phishing"
    elif final_score >= 60:
        status = "suspicious"
    elif final_score >= 30:
        status = "dormant"
    else:
        status = "clean"

    return final_score, status, triggers

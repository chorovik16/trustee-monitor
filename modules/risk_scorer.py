import re
from typing import Dict, Any, Tuple, List
from trustee_monitor.config import LEGITIMATE_DOMAINS

def calculate_risk_score(dns_res: Dict[str, Any], content_res: Dict[str, Any], domain_name: str, is_whitelisted_flag: bool=False) -> Tuple[int, str, List[str]]:
    clean_domain = domain_name.lower().strip().rstrip('.')
    if is_whitelisted_flag:
        return (0, 'whitelisted', ['Домен у білому списку (Whitelist / False Positive)'])
    legit_set = [d.lower() for d in LEGITIMATE_DOMAINS]
    if clean_domain in legit_set or any((clean_domain.endswith('.' + d) for d in legit_set)):
        return (0, 'legitimate', ['Офіційний легітимний домен бренду TRUSTEE (Вайтліст)'])
    score = 0
    triggers = []
    status = 'clean'
    if not dns_res.get('is_resolvable'):
        return (0, 'dormant', ['Домен не резолвиться (DNS NXDOMAIN)'])
    has_mx = dns_res.get('has_mx', False)
    http_status = content_res.get('http_status')
    if has_mx:
        triggers.append(f"Налаштовано поштові сервери MX: {', '.join(dns_res['mx_records'][:2])}")
        if not http_status or http_status >= 400:
            score += 25
            triggers.append('Поштові MX-записи активні за відсутності робочого веб-сайту (ризик Email Spoofing)')
        else:
            score += 10
    if http_status and http_status < 400:
        score += 10
        triggers.append(f'Активний веб-сервер (HTTP {http_status})')
    is_parked = content_res.get('is_parked', False)
    if is_parked:
        score = min(score, 25)
        return (score, 'parked', ['Домен припаркований (Parked / For Sale)'])
    ssl_info = content_res.get('ssl_info', {})
    if ssl_info.get('has_ssl'):
        issuer = ssl_info.get('issuer') or ''
        age_days = ssl_info.get('issued_days_ago')
        if age_days is not None:
            if age_days <= 2:
                score += 15
                triggers.append(f'Дуже свіжий SSL-сертифікат (видано {age_days} дн. тому)')
            elif age_days <= 14:
                score += 10
                triggers.append(f'Свіжий SSL-сертифікат (вік {age_days} дн.)')
        if any((ca in issuer.lower() for ca in ["let's encrypt", 'zerossl', 'cloudflare', 'cpanel'])):
            score += 10
            triggers.append(f'Використовується автоматизований безкоштовний SSL ({issuer})')
    triggered_cats = content_res.get('triggered_categories', [])
    trigger_details = content_res.get('trigger_details', [])
    if 'seed_phrase' in triggered_cats:
        score += 50
        triggers.append(f"КРИТИЧНО: Виявлено збір сід-фраз/мнемоніки ({', '.join(trigger_details)})")
    if 'private_key' in triggered_cats:
        score += 45
        triggers.append(f"КРИТИЧНО: Виявлено запит приватного ключа ({', '.join(trigger_details)})")
    if 'brand_spoofing' in triggered_cats:
        score += 35
        triggers.append(f"Імітація бренду TRUSTEE у контенті сторінки ({', '.join(trigger_details)})")
    if 'malicious_action' in triggered_cats:
        score += 30
        triggers.append(f"Підозріла дія: завантаження APK / підключення гаманця ({', '.join(trigger_details)})")
    matched_kws = content_res.get('matched_keywords', [])
    if len(matched_kws) >= 3:
        score += 15
        triggers.append(f"Збіг крипто-термінів ({len(matched_kws)} слів): {', '.join(matched_kws[:4])}")
    if domain_name.startswith('xn--') or any((ord(c) > 127 for c in domain_name)):
        score += 25
        triggers.append('Використано гомогліфи (Punycode / IDN маскування)')
    high_risk_domain_affixes = ['wallet', 'plus', 'card', 'crypto', 'pay', 'app', 'login', 'auth', 'connect', 'seed', 'apk', 'claim', 'airdrop', 'official', 'support']
    matched_domain_affixes = [aff for aff in high_risk_domain_affixes if aff in clean_domain]
    has_trustee_in_domain = 'trustee' in clean_domain or any((t in clean_domain for t in ['trutsee', 'turstee', 'trusetee']))
    if has_trustee_in_domain and matched_domain_affixes:
        score += 20
        triggers.append(f"Цільова мутація бренду: 'trustee' + {', '.join(matched_domain_affixes)}")
    is_legal = content_res.get('is_legal_site', False)
    legal_domain_kws = ['law', 'legal', 'lawyer', 'attorney', 'advokat', 'jurist', 'court', 'estate', 'solicitor', 'fiduciary']
    has_legal_domain_kw = any((lkw in clean_domain for lkw in legal_domain_kws))
    if (is_legal or has_legal_domain_kw) and (not any((cat in triggered_cats for cat in ['seed_phrase', 'private_key', 'brand_spoofing']))):
        score = min(score, 20)
        triggers.append('Виявлено ознаки юридичної/адвокатської діяльності (легітимний семантичний шум)')
    raw_title = (content_res.get('title') or '').lower()
    title_clean = re.sub('\\btrustees\\b|\\btrusteeship\\b', '', raw_title)
    has_brand_in_title = bool(re.search('\\btrustee\\b|trusteeplus|trusteewallet|trustee[\\s\\-_]*(plus|wallet|card|global)', title_clean))
    has_brand_content = 'brand_spoofing' in triggered_cats or has_brand_in_title
    has_critical_theft = any((cat in triggered_cats for cat in ['seed_phrase', 'private_key']))
    has_crypto_core = any((kw in matched_kws for kw in ['wallet', 'seed', 'mnemonic', 'crypto', 'private key', 'recovery']))
    if not has_trustee_in_domain and (not has_brand_content) and (not has_critical_theft) and (not has_crypto_core):
        score = min(score, 20)
        triggers.append("Відсутній зв'язок з брендом TRUSTEE та крипто-гаманцями (сторонній веб-ресурс / семантичний шум)")
    has_trustees_plural = 'trustees' in clean_domain
    has_explicit_trustee_product = any((prod in clean_domain for prod in ['trusteeplus', 'trustee-plus', 'trusteewallet', 'trustee-wallet']))
    if has_trustees_plural and (not has_explicit_trustee_product):
        if not has_brand_content and (not has_critical_theft):
            score = min(score, 35)
            triggers.append("Використано слово у множині 'trustees' (трастова/інвестиційна компанія) без згадки продуктів Trustee Plus/Wallet")
    has_phishing_content = has_critical_theft or has_brand_content
    has_crypto_context = len(matched_kws) >= 2
    if not has_phishing_content and (not has_crypto_context):
        if not (has_trustee_in_domain and matched_domain_affixes):
            score = min(score, 25)
        else:
            score = min(score, 50)
    final_score = max(0, min(100, score))
    if final_score >= 80:
        status = 'active_phishing'
    elif final_score >= 60:
        status = 'suspicious'
    elif final_score >= 30:
        status = 'dormant'
    else:
        status = 'clean'
    return (final_score, status, triggers)

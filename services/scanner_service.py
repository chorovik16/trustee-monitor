import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from trustee_monitor.database.connection import get_db_session
from trustee_monitor.database.models import Domain, DomainCheck
from trustee_monitor.modules.dns_scanner import scan_dns
from trustee_monitor.modules.content_inspector import inspect_content
from trustee_monitor.modules.risk_scorer import calculate_risk_score
from trustee_monitor.services.whitelist_service import is_whitelisted
logger = logging.getLogger(__name__)
_db_write_lock = asyncio.Lock()

async def analyze_domain(domain_name: str, source: str='manual') -> Dict[str, Any]:
    clean_domain = domain_name.lower().strip().rstrip('.')
    dns_res = await scan_dns(clean_domain)
    if dns_res.get('is_resolvable'):
        content_res = await inspect_content(clean_domain)
    else:
        content_res = {'http_status': None, 'title': None, 'is_parked': False, 'matched_keywords': [], 'triggered_categories': [], 'trigger_details': [], 'ssl_info': {}, 'content_length': 0, 'error': 'DNS unresolvable'}
    is_whl = await is_whitelisted(clean_domain)
    score, status, triggers = calculate_risk_score(dns_res, content_res, clean_domain, is_whitelisted_flag=is_whl)
    old_score = None
    old_status = None
    is_status_change = False
    is_new_domain = False
    async with _db_write_lock:
        async with get_db_session() as session:
            stmt = select(Domain).where(Domain.domain_name == clean_domain)
            result = await session.execute(stmt)
            domain_obj = result.scalar_one_or_none()
            now = datetime.now(timezone.utc)
            if domain_obj is None:
                is_new_domain = True
                domain_obj = Domain(domain_name=clean_domain, source=source, first_seen_at=now, last_checked_at=now, current_risk_score=score, current_status=status)
                session.add(domain_obj)
                try:
                    await session.flush()
                except IntegrityError:
                    await session.rollback()
                    stmt = select(Domain).where(Domain.domain_name == clean_domain)
                    result = await session.execute(stmt)
                    domain_obj = result.scalar_one_or_none()
                    is_new_domain = False
                    if domain_obj:
                        domain_obj.last_checked_at = now
                        domain_obj.current_risk_score = score
                        domain_obj.current_status = status
            else:
                old_score = domain_obj.current_risk_score
                old_status = domain_obj.current_status
                if old_status != status and status in ['suspicious', 'active_phishing']:
                    is_status_change = True
                domain_obj.last_checked_at = now
                domain_obj.current_risk_score = score
                domain_obj.current_status = status
            if domain_obj:
                ssl_info = content_res.get('ssl_info', {})
                check_obj = DomainCheck(domain_id=domain_obj.id, checked_at=now, risk_score=score, status=status, ip_address=dns_res.get('ip'), mx_records=','.join(dns_res.get('mx_records', [])), http_status=content_res.get('http_status'), ssl_issuer=ssl_info.get('issuer'), ssl_age_days=ssl_info.get('issued_days_ago'), matched_keywords=json.dumps(content_res.get('matched_keywords', [])), triggers=json.dumps(triggers), raw_details=json.dumps({'dns': dns_res, 'title': content_res.get('title')}))
                session.add(check_obj)
    from trustee_monitor.notifier.telegram_bot import send_telegram_alert
    from trustee_monitor.config import MIN_ALERT_SCORE
    score_escalated = old_score is not None and score >= old_score + 15 and (score >= MIN_ALERT_SCORE)
    should_alert = source not in ['telegram_manual', 'telegram_recheck'] and status not in ['legitimate', 'whitelisted', 'clean'] and (is_new_domain and score >= MIN_ALERT_SCORE or is_status_change or score_escalated)
    if should_alert:
        await send_telegram_alert(domain_name=clean_domain, risk_score=score, status=status, ip_address=dns_res.get('ip'), triggers=triggers, source=source, is_status_change=is_status_change, old_score=old_score)
    return {'domain': clean_domain, 'risk_score': score, 'status': status, 'ip_address': dns_res.get('ip'), 'http_status': content_res.get('http_status'), 'triggers': triggers, 'is_status_change': is_status_change, 'old_score': old_score}

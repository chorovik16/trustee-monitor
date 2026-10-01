import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from sqlalchemy import select

from trustee_monitor.database.connection import get_db_session
from trustee_monitor.database.models import Domain, DomainCheck
from trustee_monitor.modules.dns_scanner import scan_dns
from trustee_monitor.modules.content_inspector import inspect_content
from trustee_monitor.modules.risk_scorer import calculate_risk_score
from trustee_monitor.notifier.telegram_bot import send_telegram_alert

logger = logging.getLogger(__name__)

async def analyze_domain(domain_name: str, source: str = "manual") -> Dict[str, Any]:
    """
    Full inspection pipeline: DNS -> Content -> Scoring -> PostgreSQL -> Alerting.
    """
    clean_domain = domain_name.lower().strip().rstrip(".")

    # 1. DNS Scan
    dns_res = await scan_dns(clean_domain)

    # 2. Content & SSL Inspection
    if dns_res.get("is_resolvable"):
        content_res = await inspect_content(clean_domain)
    else:
        content_res = {
            "http_status": None,
            "title": None,
            "is_parked": False,
            "matched_keywords": [],
            "triggered_categories": [],
            "trigger_details": [],
            "ssl_info": {},
            "content_length": 0,
            "error": "DNS unresolvable"
        }

    # 3. Calculate Risk Score
    score, status, triggers = calculate_risk_score(dns_res, content_res, clean_domain)

    # 4. Save to Database
    old_score = None
    is_status_change = False

    async with get_db_session() as session:
        # Check if domain already exists
        stmt = select(Domain).where(Domain.domain_name == clean_domain)
        result = await session.execute(stmt)
        domain_obj = result.scalar_one_or_none()

        now = datetime.now(timezone.utc)

        if domain_obj is None:
            # Create new domain record
            domain_obj = Domain(
                domain_name=clean_domain,
                source=source,
                first_seen_at=now,
                last_checked_at=now,
                current_risk_score=score,
                current_status=status
            )
            session.add(domain_obj)
            await session.flush()  # to get domain_obj.id
        else:
            old_score = domain_obj.current_risk_score
            old_status = domain_obj.current_status
            if old_status != status and status in ["suspicious", "active_phishing"]:
                is_status_change = True

            domain_obj.last_checked_at = now
            domain_obj.current_risk_score = score
            domain_obj.current_status = status

        # Save check history record
        ssl_info = content_res.get("ssl_info", {})
        check_obj = DomainCheck(
            domain_id=domain_obj.id,
            checked_at=now,
            risk_score=score,
            status=status,
            ip_address=dns_res.get("ip"),
            mx_records=",".join(dns_res.get("mx_records", [])),
            http_status=content_res.get("http_status"),
            ssl_issuer=ssl_info.get("issuer"),
            ssl_age_days=ssl_info.get("issued_days_ago"),
            matched_keywords=json.dumps(content_res.get("matched_keywords", [])),
            triggers=json.dumps(triggers),
            raw_details=json.dumps({
                "dns": dns_res,
                "title": content_res.get("title")
            })
        )
        session.add(check_obj)

    # 5. Send Alert if needed
    await send_telegram_alert(
        domain_name=clean_domain,
        risk_score=score,
        status=status,
        ip_address=dns_res.get("ip"),
        triggers=triggers,
        source=source,
        is_status_change=is_status_change,
        old_score=old_score
    )

    return {
        "domain": clean_domain,
        "risk_score": score,
        "status": status,
        "ip_address": dns_res.get("ip"),
        "http_status": content_res.get("http_status"),
        "triggers": triggers,
        "is_status_change": is_status_change,
        "old_score": old_score
    }

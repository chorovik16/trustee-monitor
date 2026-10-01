import logging
from typing import Dict, Any, List
from sqlalchemy import select
from trustee_monitor.database.connection import get_db_session
from trustee_monitor.database.models import Domain, DomainCheck
from trustee_monitor.services.scanner_service import analyze_domain

logger = logging.getLogger(__name__)

async def recheck_domain(domain_name: str) -> Dict[str, Any]:
    """
    Re-scans a specific domain, updates PostgreSQL, and builds a comprehensive change timeline.
    """
    clean_domain = domain_name.lower().strip().rstrip(".")

    # 1. Run live inspection
    current_result = await analyze_domain(clean_domain, source="recheck")

    # 2. Query historical checks from database
    history_records = []
    async with get_db_session() as session:
        stmt = (
            select(Domain)
            .where(Domain.domain_name == clean_domain)
        )
        res = await session.execute(stmt)
        domain_obj = res.scalar_one_or_none()

        if domain_obj:
            checks_stmt = (
                select(DomainCheck)
                .where(DomainCheck.domain_id == domain_obj.id)
                .order_by(DomainCheck.checked_at.asc())
            )
            checks_res = await session.execute(checks_stmt)
            history_records = checks_res.scalars().all()

    # 3. Format visual human-readable timeline
    timeline_lines = [
        "=" * 78,
        f"ХРОНОЛОГІЯ ПЕРЕВІРОК ТА ЗМІН СТАНУ: {clean_domain}",
        f"Всього перевірок у базі: {len(history_records)}",
        "=" * 78
    ]

    for idx, chk in enumerate(history_records, start=1):
        dt_str = chk.checked_at.strftime("%d.%m.%Y %H:%M:%S")
        status_badge = chk.status.upper()
        line = f"[{idx}] {dt_str} UTC | Risk Score: {chk.risk_score}/100 [{status_badge}]"
        timeline_lines.append(line)

        details = []
        if chk.ip_address:
            details.append(f"IP: {chk.ip_address}")
        if chk.http_status:
            details.append(f"HTTP: {chk.http_status}")
        if chk.ssl_issuer:
            details.append(f"SSL: {chk.ssl_issuer} (вік: {chk.ssl_age_days or 0} дн.)")
        if chk.mx_records:
            details.append(f"MX: {chk.mx_records}")

        if details:
            timeline_lines.append(f"    • Параметри: {' | '.join(details)}")

        # Print Triggers
        triggers = chk.triggers_list
        if triggers:
            timeline_lines.append("    • Фактори ризику:")
            for trig in triggers:
                timeline_lines.append(f"      - {trig}")
        timeline_lines.append("")

    timeline_lines.append("=" * 78)
    formatted_timeline = "\n".join(timeline_lines)

    return {
        "domain": clean_domain,
        "current_result": current_result,
        "total_checks": len(history_records),
        "history": history_records,
        "formatted_timeline": formatted_timeline
    }

async def recheck_dormant_domains(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Background batch re-checker: finds dormant/parked domains and checks if they became active.
    """
    domains_to_check = []
    async with get_db_session() as session:
        stmt = (
            select(Domain.domain_name)
            .where(Domain.current_status.in_(["dormant", "parked", "suspicious"]))
            .order_by(Domain.last_checked_at.asc())
            .limit(limit)
        )
        res = await session.execute(stmt)
        domains_to_check = res.scalars().all()

    results = []
    for d_name in domains_to_check:
        try:
            res = await analyze_domain(d_name, source="batch_recheck")
            results.append(res)
        except Exception as e:
            logger.error(f"Error re-checking dormant domain {d_name}: {e}")

    return results

import logging
from datetime import datetime, timezone
from typing import List, Dict, Any
from sqlalchemy import select, delete
from trustee_monitor.config import LEGITIMATE_DOMAINS
from trustee_monitor.database.connection import get_db_session
from trustee_monitor.database.models import Whitelist, Domain
logger = logging.getLogger(__name__)

async def is_whitelisted(domain_name: str) -> bool:
    clean_domain = domain_name.lower().strip().rstrip('.')
    legit_set = [d.lower().strip() for d in LEGITIMATE_DOMAINS]
    if clean_domain in legit_set or any((clean_domain.endswith('.' + d) for d in legit_set)):
        return True
    try:
        async with get_db_session() as session:
            stmt = select(Whitelist).where(Whitelist.domain_name == clean_domain)
            res = await session.execute(stmt)
            if res.scalar_one_or_none() is not None:
                return True
            stmt_all = select(Whitelist.domain_name)
            all_whitelisted = (await session.execute(stmt_all)).scalars().all()
            for w in all_whitelisted:
                w_clean = w.lower().strip()
                if clean_domain == w_clean or clean_domain.endswith('.' + w_clean):
                    return True
    except Exception as e:
        logger.error(f'Error checking dynamic whitelist for {clean_domain}: {e}')
    return False

async def get_all_whitelisted() -> Dict[str, Any]:
    db_items: List[Dict[str, Any]] = []
    try:
        async with get_db_session() as session:
            stmt = select(Whitelist).order_by(Whitelist.added_at.desc())
            res = await session.execute(stmt)
            for row in res.scalars().all():
                db_items.append({'domain': row.domain_name, 'added_at': row.added_at, 'added_by': row.added_by, 'comment': row.comment})
    except Exception as e:
        logger.error(f'Error retrieving dynamic whitelist: {e}')
    return {'official': list(LEGITIMATE_DOMAINS), 'custom': db_items}

async def add_to_whitelist(domain_name: str, added_by: str='telegram_admin', comment: str=None) -> bool:
    clean_domain = domain_name.lower().strip().rstrip('.')
    now = datetime.now(timezone.utc)
    try:
        async with get_db_session() as session:
            stmt = select(Whitelist).where(Whitelist.domain_name == clean_domain)
            res = await session.execute(stmt)
            existing = res.scalar_one_or_none()
            if not existing:
                item = Whitelist(domain_name=clean_domain, added_at=now, added_by=added_by, comment=comment)
                session.add(item)
            domain_stmt = select(Domain).where(Domain.domain_name == clean_domain)
            dom_res = await session.execute(domain_stmt)
            dom_obj = dom_res.scalar_one_or_none()
            if dom_obj:
                dom_obj.current_status = 'whitelisted'
                dom_obj.current_risk_score = 0
                dom_obj.last_checked_at = now
        logger.info(f'Domain {clean_domain} added to whitelist by {added_by}')
        return True
    except Exception as e:
        logger.error(f'Failed to add {clean_domain} to whitelist: {e}')
        return False

async def remove_from_whitelist(domain_name: str) -> bool:
    clean_domain = domain_name.lower().strip().rstrip('.')
    try:
        async with get_db_session() as session:
            stmt = delete(Whitelist).where(Whitelist.domain_name == clean_domain)
            await session.execute(stmt)
            dom_stmt = select(Domain).where(Domain.domain_name == clean_domain)
            dom_res = await session.execute(dom_stmt)
            dom_obj = dom_res.scalar_one_or_none()
            if dom_obj and dom_obj.current_status == 'whitelisted':
                dom_obj.current_status = 'clean'
        logger.info(f'Domain {clean_domain} removed from whitelist')
        return True
    except Exception as e:
        logger.error(f'Failed to remove {clean_domain} from whitelist: {e}')
        return False

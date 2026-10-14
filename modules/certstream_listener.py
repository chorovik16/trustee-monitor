import json
import asyncio
import logging
import time
from typing import Callable, Optional, Dict
import websockets
from trustee_monitor.modules.mutation_generator import is_trustee_candidate
from trustee_monitor.services.state import set_certstream_status, record_cert_received
from trustee_monitor.config import CERTSTREAM_URL
logger = logging.getLogger(__name__)
_recent_certstream_domains: Dict[str, float] = {}
_DEDUP_WINDOW_SECONDS = 90.0

def _is_duplicate_certstream(domain: str) -> bool:
    now = time.time()
    if len(_recent_certstream_domains) > 1000:
        expired = [d for d, t in _recent_certstream_domains.items() if now - t > _DEDUP_WINDOW_SECONDS]
        for d in expired:
            _recent_certstream_domains.pop(d, None)
    last_time = _recent_certstream_domains.get(domain)
    if last_time and now - last_time < _DEDUP_WINDOW_SECONDS:
        return True
    _recent_certstream_domains[domain] = now
    return False

async def start_certstream_listener(on_match_callback: Callable[[str], asyncio.Future], url: str=CERTSTREAM_URL, max_retries: Optional[int]=None):
    logger.info(f'Connecting to real-time CertStream at {url}...')
    retry_count = 0
    while True:
        try:
            async with websockets.connect(url, ping_interval=15, ping_timeout=20) as ws:
                logger.info('Connected to CertStream stream. Listening for SSL certificates...')
                set_certstream_status(True)
                retry_count = 0
                async for raw_msg in ws:
                    try:
                        record_cert_received()
                        msg = json.loads(raw_msg)
                        msg_type = msg.get('message_type')
                        if msg_type == 'certificate_update':
                            data = msg.get('data', {})
                            leaf_cert = data.get('leaf_cert', {})
                            all_domains = leaf_cert.get('all_domains', [])
                            matched_domains = set()
                            for domain in all_domains:
                                clean_domain = domain.lstrip('*.').lower()
                                if is_trustee_candidate(clean_domain):
                                    matched_domains.add(clean_domain)
                            for clean_domain in matched_domains:
                                if _is_duplicate_certstream(clean_domain):
                                    logger.debug(f'Skipping rapid duplicate CertStream event for: {clean_domain}')
                                    continue
                                logger.warning(f'🎯 [CERTSTREAM MATCH] Captured certificate for: {clean_domain}')
                                asyncio.create_task(on_match_callback(clean_domain))
                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f'Error processing CertStream message: {e}')
        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info('Зупинка CertStream слухача...')
            break
        except (websockets.ConnectionClosed, asyncio.TimeoutError) as e:
            set_certstream_status(False)
            logger.warning(f'CertStream connection closed ({e}). Reconnecting in 5 seconds...')
            retry_count += 1
            if max_retries and retry_count >= max_retries:
                logger.error('Maximum CertStream retries reached.')
                break
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f'CertStream listener error: {e}. Retrying in 10 seconds...')
            await asyncio.sleep(10)

import json
import asyncio
import logging
from typing import Callable, Optional
import websockets
from trustee_monitor.modules.mutation_generator import is_trustee_candidate

logger = logging.getLogger(__name__)

CERTSTREAM_URL = "wss://certstream.calidog.io/"

async def start_certstream_listener(
    on_match_callback: Callable[[str], asyncio.Future],
    url: str = CERTSTREAM_URL,
    max_retries: Optional[int] = None
):
    """
    Asynchronously streams newly issued SSL certificates in real-time.
    Filters domains for TRUSTEE brand matches and triggers the callback.
    """
    logger.info(f"Connecting to real-time CertStream at {url}...")
    retry_count = 0

    while True:
        try:
            async with websockets.connect(url, ping_interval=15, ping_timeout=20) as ws:
                logger.info("Connected to CertStream stream. Listening for SSL certificates...")
                retry_count = 0

                async for raw_msg in ws:
                    try:
                        msg = json.loads(raw_msg)
                        msg_type = msg.get("message_type")

                        if msg_type == "certificate_update":
                            data = msg.get("data", {})
                            leaf_cert = data.get("leaf_cert", {})
                            all_domains = leaf_cert.get("all_domains", [])

                            for domain in all_domains:
                                # Clean up wildcards
                                clean_domain = domain.lstrip("*.").lower()
                                if is_trustee_candidate(clean_domain):
                                    logger.warning(f"🎯 [CERTSTREAM MATCH] Captured certificate for: {clean_domain}")
                                    # Dispatch analysis asynchronously
                                    asyncio.create_task(on_match_callback(clean_domain))

                    except json.JSONDecodeError:
                        continue
                    except Exception as e:
                        logger.error(f"Error processing CertStream message: {e}")

        except (asyncio.CancelledError, KeyboardInterrupt):
            logger.info("Зупинка CertStream слухача...")
            break
        except (websockets.ConnectionClosed, asyncio.TimeoutError) as e:
            logger.warning(f"CertStream connection closed ({e}). Reconnecting in 5 seconds...")
            retry_count += 1
            if max_retries and retry_count >= max_retries:
                logger.error("Maximum CertStream retries reached.")
                break
            await asyncio.sleep(5)
        except Exception as e:
            logger.error(f"CertStream listener error: {e}. Retrying in 10 seconds...")
            await asyncio.sleep(10)

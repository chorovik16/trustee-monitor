import logging
from typing import List, Optional
import httpx
from trustee_monitor.config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, MIN_ALERT_SCORE

logger = logging.getLogger(__name__)

async def send_telegram_alert(
    domain_name: str,
    risk_score: int,
    status: str,
    ip_address: Optional[str],
    triggers: List[str],
    source: str = "scanner",
    is_status_change: bool = False,
    old_score: Optional[int] = None
) -> bool:
    """
    Sends structured alert to Telegram if token is configured, or logs formatted alert to console.
    """
    # Only alert if score meets minimum threshold or is a significant change
    if risk_score < MIN_ALERT_SCORE and not is_status_change:
        return False

    severity_icon = "🚨 [CRITICAL ALERT]" if risk_score >= 80 else "⚠️ [HIGH ALERT]"
    if is_status_change:
        severity_icon = "🔄 [STATUS CHANGE ALERT]"

    lines = [
        f"{severity_icon} <b>Виявлено загрозу бренду TRUSTEE</b>",
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
        f"🌐 <b>Домен:</b> <code>{domain_name}</code>",
        f"🎯 <b>Risk Score:</b> <b>{risk_score}/100</b> [{status.upper()}]",
        f"📡 <b>Джерело:</b> {source}",
    ]

    if ip_address:
        lines.append(f"📍 <b>IP-адреса:</b> <code>{ip_address}</code>")

    if is_status_change and old_score is not None:
        lines.append(f"📈 <b>Динаміка балу:</b> {old_score} ➔ {risk_score}")

    lines.append("\n⚠️ <b>Виявлені фактори ризику:</b>")
    for trig in triggers:
        lines.append(f" • {trig}")

    if risk_score >= 80:
        lines.append("\n⚡ <b>Рекомендація:</b> Негайний Abuse Takedown до хостингу / реєстратора!")

    message_text = "\n".join(lines)

    # Check if Telegram credentials are set
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message_text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True
        }
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    logger.info(f"Telegram alert successfully sent for {domain_name}")
                    return True
                else:
                    logger.warning(f"Telegram API responded with {resp.status_code}: {resp.text}")
        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")

    # Fallback / Local mock console output
    print("\n" + "="*60)
    print(f"📡 [MOCK TELEGRAM ALERT - Bot Token not set or sent]")
    print(message_text.replace("<b>", "").replace("</b>", "").replace("<code>", "").replace("</code>", ""))
    print("="*60 + "\n")
    return True

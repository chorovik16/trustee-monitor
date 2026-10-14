import asyncio
import json
import logging
import re
import time
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Tuple
import httpx
from trustee_monitor.config import TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_IDS, MIN_ALERT_SCORE, AUTO_RECHECK_INTERVAL_HOURS
from trustee_monitor.database.connection import get_db_session
from trustee_monitor.database.models import Domain, DomainCheck
from trustee_monitor.services import state
logger = logging.getLogger(__name__)
_recent_alerts_cache: Dict[str, Tuple[float, int]] = {}
_alert_lock = asyncio.Lock()
_ALERT_COOLDOWN_SECONDS = 1800

def build_alert_keyboard(domain_name: str, is_whitelisted_status: bool=False) -> Dict[str, Any]:
    if is_whitelisted_status:
        return {'inline_keyboard': [[{'text': '🔄 Re-check', 'callback_data': f'recheck:{domain_name}'}, {'text': '📋 Деталі (DNS/SSL)', 'callback_data': f'details:{domain_name}'}]]}
    return {'inline_keyboard': [[{'text': '🔄 Re-check', 'callback_data': f'recheck:{domain_name}'}, {'text': '⚪ У Whitelist', 'callback_data': f'whitelist:{domain_name}'}], [{'text': '📋 Деталі (DNS/SSL)', 'callback_data': f'details:{domain_name}'}]]}

def get_main_reply_keyboard() -> Dict[str, Any]:
    return {'keyboard': [[{'text': '📊 Статус системи'}, {'text': '🚨 Останні загрози'}], [{'text': '⚡ Сканувати мутації'}, {'text': '⚪ Білий список'}], [{'text': f'🔄 Recheck всієї бази (авто {AUTO_RECHECK_INTERVAL_HOURS}г)'}]], 'resize_keyboard': True, 'is_persistent': True}

async def send_telegram_alert(domain_name: str, risk_score: int, status: str, ip_address: Optional[str], triggers: List[str], source: str='scanner', is_status_change: bool=False, old_score: Optional[int]=None) -> bool:
    if status in ['legitimate', 'whitelisted']:
        return False
    if risk_score < MIN_ALERT_SCORE and (not is_status_change):
        return False
    clean_domain = domain_name.lower().strip()
    async with _alert_lock:
        now_ts = time.time()
        if len(_recent_alerts_cache) > 2000:
            expired = [d for d, (t, s) in _recent_alerts_cache.items() if now_ts - t > _ALERT_COOLDOWN_SECONDS]
            for d in expired:
                _recent_alerts_cache.pop(d, None)
        if clean_domain in _recent_alerts_cache:
            last_ts, last_score = _recent_alerts_cache[clean_domain]
            if now_ts - last_ts < _ALERT_COOLDOWN_SECONDS and (not is_status_change) and (risk_score <= last_score + 10):
                logger.info(f'Duplicate Telegram alert suppressed for {clean_domain} (sent {int(now_ts - last_ts)}s ago)')
                return False
        _recent_alerts_cache[clean_domain] = (now_ts, risk_score)
    severity_icon = '🚨 [CRITICAL ALERT]' if risk_score >= 80 else '⚠️ [HIGH ALERT]'
    if is_status_change:
        severity_icon = '🔄 [STATUS CHANGE ALERT]'
    lines = [f'{severity_icon} <b>Виявлено загрозу бренду TRUSTEE</b>', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━', f'🌐 <b>Домен:</b> <code>{domain_name}</code>', f'🎯 <b>Risk Score:</b> <b>{risk_score}/100</b> [{status.upper()}]', f'📡 <b>Джерело:</b> {source}']
    if ip_address:
        lines.append(f'📍 <b>IP-адреса:</b> <code>{ip_address}</code>')
    if is_status_change and old_score is not None:
        lines.append(f'📈 <b>Динаміка балу:</b> {old_score} ➔ {risk_score}')
    lines.append('\n⚠️ <b>Виявлені фактори ризику:</b>')
    for trig in triggers:
        lines.append(f' • {trig}')
    if risk_score >= 80:
        lines.append('\n⚡ <b>Рекомендація:</b> Негайний Abuse Takedown до хостингу / реєстратора!')
    message_text = '\n'.join(lines)
    keyboard = build_alert_keyboard(domain_name)
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_IDS:
        url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
        success = False
        async with httpx.AsyncClient(timeout=8.0) as client:
            for chat_id in TELEGRAM_CHAT_IDS:
                payload = {'chat_id': chat_id, 'text': message_text, 'parse_mode': 'HTML', 'disable_web_page_preview': True, 'reply_markup': keyboard}
                try:
                    resp = await client.post(url, json=payload)
                    if resp.status_code == 200:
                        logger.info(f'Telegram alert sent to {chat_id} for {domain_name}')
                        success = True
                    else:
                        logger.warning(f'Telegram API {resp.status_code} for {chat_id}: {resp.text}')
                except Exception as e:
                    logger.error(f'Failed to send alert to {chat_id}: {e}')
        if success:
            return True
    print('\n' + '=' * 60)
    print('📡 [MOCK TELEGRAM ALERT]')
    print(message_text.replace('<b>', '').replace('</b>', '').replace('<code>', '').replace('</code>', ''))
    print('=' * 60 + '\n')
    return True

class TelegramBotService:

    def __init__(self, token: str):
        self.token = token
        self.api_url = f'https://api.telegram.org/bot{token}'
        self.is_running = False
        self._processed_updates = set()
        self._action_cooldown: Dict[str, float] = {}

    async def send_message(self, chat_id: int | str, text: str, reply_markup: Optional[Dict[str, Any]]=None, parse_mode: str='HTML') -> Optional[Dict[str, Any]]:
        url = f'{self.api_url}/sendMessage'
        payload: Dict[str, Any] = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode, 'disable_web_page_preview': True}
        if reply_markup:
            payload['reply_markup'] = reply_markup
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    return resp.json().get('result')
                else:
                    logger.warning(f'sendMessage error {resp.status_code}: {resp.text}')
            except Exception as e:
                logger.error(f'Error sending message to {chat_id}: {e}')
        return None

    async def edit_message_text(self, chat_id: int | str, message_id: int, text: str, reply_markup: Optional[Dict[str, Any]]=None, parse_mode: str='HTML') -> bool:
        safe_reply_markup = reply_markup
        if safe_reply_markup and 'keyboard' in safe_reply_markup:
            safe_reply_markup = None
        url = f'{self.api_url}/editMessageText'
        payload: Dict[str, Any] = {'chat_id': chat_id, 'message_id': message_id, 'text': text, 'parse_mode': parse_mode, 'disable_web_page_preview': True}
        if safe_reply_markup is not None:
            payload['reply_markup'] = safe_reply_markup
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                resp = await client.post(url, json=payload)
                if resp.status_code == 200:
                    return True
                logger.warning(f'editMessageText warning {resp.status_code}: {resp.text}. Falling back to sendMessage.')
            except Exception as e:
                logger.error(f'Error editing message {message_id}: {e}. Falling back to sendMessage.')
        try:
            await self.send_message(chat_id, text, reply_markup=reply_markup, parse_mode=parse_mode)
            return True
        except Exception as e:
            logger.error(f'Fallback send_message failed: {e}')
            return False

    async def answer_callback_query(self, callback_query_id: str, text: str='', show_alert: bool=False):
        url = f'{self.api_url}/answerCallbackQuery'
        payload = {'callback_query_id': callback_query_id, 'text': text, 'show_alert': show_alert}
        async with httpx.AsyncClient(timeout=8.0) as client:
            try:
                await client.post(url, json=payload)
            except Exception as e:
                logger.debug(f'Failed to answer callback query: {e}')

    async def handle_start(self, chat_id: int | str):
        welcome_text = f'🛡 <b>Trustee Anti-Phishing SecOps Bot</b>\n\nСистема проактивного моніторингу бренду <b>TRUSTEE</b> активна 24/7.\nУсі нові світові SSL-сертифікати аналізуються в реальному часі.\n\n📌 <b>Швидкі команди та функції:</b>\n • <b>/status</b> — стан системи, аптайм, статистика бази та CertStream\n • <b>/recent</b> — останні виявлені загрози у базі\n • <b>/scan [кількість] [потоки]</b> — сканування мутацій бренду (або через меню пресетів)\n • <b>/check &lt;домен&gt;</b> — миттєва повна перевірка будь-якого сайту\n • <b>/whitelist</b> — перегляд білого списку (виключень)\n • <b>/recheck</b> — повторна перевірка ВСІЄЇ бази сплячих доменів (фоново авто кожні {AUTO_RECHECK_INTERVAL_HOURS}г)\n\n💡 <i>Ви також можете просто скинути назву будь-якого домену в чат, і бот одразу просканує його!</i>'
        await self.send_message(chat_id, welcome_text, reply_markup=get_main_reply_keyboard())

    async def handle_status(self, chat_id: int | str):
        from sqlalchemy import select, func
        now = datetime.now(timezone.utc)
        uptime_seconds = int((now - state.start_time).total_seconds())
        days, rem = divmod(uptime_seconds, 86400)
        hours, rem = divmod(rem, 3600)
        minutes, _ = divmod(rem, 60)
        uptime_str = f'{days}д {hours}г {minutes}хв' if days > 0 else f'{hours}г {minutes}хв'
        total_domains = 0
        active_phishing = 0
        suspicious = 0
        dormant = 0
        whitelisted = 0
        try:
            async with get_db_session() as session:
                total_domains = (await session.execute(select(func.count(Domain.id)))).scalar() or 0
                active_phishing = (await session.execute(select(func.count(Domain.id)).where(Domain.current_status == 'active_phishing'))).scalar() or 0
                suspicious = (await session.execute(select(func.count(Domain.id)).where(Domain.current_status == 'suspicious'))).scalar() or 0
                dormant = (await session.execute(select(func.count(Domain.id)).where(Domain.current_status.in_(['dormant', 'parked'])))).scalar() or 0
            from trustee_monitor.services.whitelist_service import get_all_whitelisted
            wl = await get_all_whitelisted()
            combined_wl = set([d.lower().strip() for d in wl.get('official', [])] + [item['domain'].lower().strip() for item in wl.get('custom', [])])
            whitelisted = len(combined_wl)
        except Exception as e:
            logger.error(f'Error querying database stats for /status: {e}')
        cs_icon = '🟢 ONLINE (активний)' if state.certstream_connected else '🟡 STANDBY / CONNECTING'
        if state.last_cert_time:
            diff = int((now - state.last_cert_time).total_seconds())
            last_cert_str = f'{diff} сек тому' if diff < 60 else f'{diff // 60} хв тому'
        else:
            last_cert_str = 'очікування пакетів'
        certs_num = state.total_certs_observed
        if certs_num >= 1000000000:
            certs_display = f'{certs_num / 1000000000:.2f} млрд ({certs_num:,})'
        elif certs_num >= 1000000:
            certs_display = f'{certs_num / 1000000:.2f} млн ({certs_num:,})'
        elif certs_num >= 10000:
            certs_display = f'{certs_num / 1000:.1f} тис. ({certs_num:,})'
        else:
            certs_display = f'{certs_num:,}'
        status_text = f'📊 <b>Стан системи моніторингу TRUSTEE</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n📡 <b>CertStream (Світовий потік SSL):</b> {cs_icon}\n🗄 <b>База даних:</b> 🟢 PostgreSQL (Healthy)\n⏱ <b>Аптайм сервісу:</b> {uptime_str}\n🔄 <b>Авто-речек всієї бази:</b> кожні {AUTO_RECHECK_INTERVAL_HOURS} годин\n\n📈 <b>Цільова база брендів TRUSTEE ({total_domains:,} доменів):</b>\n • 🔴 <b>Активний фішинг [!!!]:</b> {active_phishing}\n • 🟡 <b>Підозрілі домени [ ! ]:</b> {suspicious}\n • ⚪ <b>У білому списку [ V ]:</b> {whitelisted}\n • 💤 <b>Сплячі / Парковані:</b> {dormant}\n\n⚡ <b>CertStream у реальному часі:</b>\n • Останній SSL-сертифікат: {last_cert_str}\n • Всього оброблено пакетів: {certs_display}'
        await self.send_message(chat_id, status_text, reply_markup=get_main_reply_keyboard())

    async def handle_recent(self, chat_id: int | str):
        from sqlalchemy import select
        lines = ['🚨 <b>Останні виявлені загрози у базі:</b>', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━']
        try:
            async with get_db_session() as session:
                stmt = select(Domain).where(Domain.current_status.in_(['active_phishing', 'suspicious'])).order_by(Domain.current_risk_score.desc(), Domain.last_checked_at.desc()).limit(5)
                res = await session.execute(stmt)
                threats = res.scalars().all()
                if not threats:
                    lines.append('<i>Активних загроз у базі зараз немає.</i>')
                else:
                    for i, t in enumerate(threats, start=1):
                        icon = '🔴' if t.current_status == 'active_phishing' else '🟡'
                        dt = t.last_checked_at.strftime('%d.%m %H:%M') if t.last_checked_at else '—'
                        lines.append(f'{i}. {icon} <code>{t.domain_name}</code> — <b>{t.current_risk_score}/100</b> [{t.current_status.upper()}]\n   🕒 Перевірено: {dt}')
        except Exception as e:
            logger.error(f'Error fetching recent threats: {e}')
            lines.append('<i>Не вдалося завантажити останні загрози.</i>')
        lines.append('\n💡 <i>Для детального сканування введіть /check &lt;домен&gt;</i>')
        await self.send_message(chat_id, '\n'.join(lines), reply_markup=get_main_reply_keyboard())

    async def get_whitelist_page_content(self, page: int=1, page_size: int=15) -> Tuple[str, Optional[Dict[str, Any]]]:
        import math
        from trustee_monitor.services.whitelist_service import get_all_whitelisted
        wl = await get_all_whitelisted()
        combined = []
        for d in wl['official']:
            clean_d = d.lower().strip()
            if clean_d not in combined:
                combined.append(clean_d)
        for item in wl['custom']:
            clean_d = item['domain'].lower().strip()
            if clean_d not in combined:
                combined.append(clean_d)
        total_count = len(combined)
        total_pages = max(1, math.ceil(total_count / page_size))
        page = max(1, min(page, total_pages))
        start_idx = (page - 1) * page_size
        page_items = combined[start_idx:start_idx + page_size]
        page_info = f' [Стор. {page}/{total_pages}]' if total_pages > 1 else ''
        lines = [f'⚪ <b>Вайтліст:</b>{page_info}', f'<i>Всього в списку: {total_count}</i>', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━']
        if not page_items:
            lines.append('• <i>Список порожній</i>')
        else:
            for d in page_items:
                lines.append(f'• <code>{d}</code>')
        lines.append('\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n➕ <i>Додати:</i> <code>/whitelist_add домен.com</code>\n➖ <i>Видалити:</i> <code>/whitelist_del домен.com</code>')
        keyboard = None
        if total_pages > 1:
            nav_row = []
            if page > 1:
                nav_row.append({'text': '⬅️ Попередня', 'callback_data': f'wl_page:{page - 1}'})
            nav_row.append({'text': f'📄 {page} / {total_pages}', 'callback_data': 'noop'})
            if page < total_pages:
                nav_row.append({'text': 'Наступна ➡️', 'callback_data': f'wl_page:{page + 1}'})
            keyboard = {'inline_keyboard': [nav_row]}
        return ('\n'.join(lines), keyboard)

    async def handle_whitelist_view(self, chat_id: int | str, page: int=1):
        text, keyboard = await self.get_whitelist_page_content(page=page)
        await self.send_message(chat_id, text, reply_markup=keyboard)

    async def handle_whitelist_add(self, chat_id: int | str, text: str, user_name: str='admin'):
        from trustee_monitor.services.whitelist_service import add_to_whitelist
        parts = text.strip().split()
        if len(parts) < 2:
            await self.send_message(chat_id, '⚠️ <b>Формат:</b> <code>/whitelist_add &lt;домен&gt;</code>')
            return
        domain = parts[1].lower().replace('https://', '').replace('http://', '').split('/')[0].strip()
        success = await add_to_whitelist(domain, added_by=f'@{user_name}' if user_name else 'admin')
        if success:
            await self.send_message(chat_id, f'✅ Домен <code>{domain}</code> успішно додано до <b>Whitelist</b>!\nСистема ігноруватиме його при наступних перевірках та не надсилатиме алерти.')
        else:
            await self.send_message(chat_id, f'❌ Помилка при додаванні <code>{domain}</code> до вайтлісту.')

    async def handle_whitelist_del(self, chat_id: int | str, text: str):
        from trustee_monitor.services.whitelist_service import remove_from_whitelist
        parts = text.strip().split()
        if len(parts) < 2:
            await self.send_message(chat_id, '⚠️ <b>Формат:</b> <code>/whitelist_del &lt;домен&gt;</code>')
            return
        domain = parts[1].lower().replace('https://', '').replace('http://', '').split('/')[0].strip()
        success = await remove_from_whitelist(domain)
        if success:
            await self.send_message(chat_id, f'🗑 Домен <code>{domain}</code> видалено з <b>Whitelist</b>.')
        else:
            await self.send_message(chat_id, f'❌ Помилка при видаленні <code>{domain}</code> з вайтлісту.')

    async def handle_check_domain(self, chat_id: int | str, domain_input: str):
        clean_domain = domain_input.strip().lower().replace('https://', '').replace('http://', '').split('/')[0].strip()
        if not clean_domain or '.' not in clean_domain:
            await self.send_message(chat_id, '⚠️ Будь ласка, вкажіть коректний домен (наприклад: <code>trusteecard.com</code>).')
            return
        temp_msg = await self.send_message(chat_id, f'⏳ <b>Сканую домен <code>{clean_domain}</code>...</b>\n<i>Перевірка DNS, SSL та аналіз контенту сторінки...</i>')
        try:
            from trustee_monitor.services.scanner_service import analyze_domain
            res = await analyze_domain(clean_domain, source='telegram_manual')
            score = res.get('risk_score', 0)
            status = res.get('status', 'unknown').upper()
            ip = res.get('ip_address') or 'Не резолвиться (NXDOMAIN)'
            http_code = res.get('http_status') or '—'
            triggers = res.get('triggers', [])
            status_icon = '🔴' if score >= 80 else '🟡' if score >= 60 else '🟢'
            if status in ['LEGITIMATE', 'WHITELISTED']:
                status_icon = '⚪'
            card_lines = [f'🎯 <b>Результат перевірки:</b> <code>{clean_domain}</code>', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━', f'📊 <b>Risk Score:</b> <b>{score}/100</b> {status_icon} [{status}]', f'📍 <b>IP-адреса:</b> <code>{ip}</code>', f'🌐 <b>HTTP Код:</b> {http_code}']
            if triggers:
                card_lines.append('\n⚠️ <b>Фактори оцінки:</b>')
                for t in triggers:
                    card_lines.append(f' • {t}')
            else:
                card_lines.append('\n✅ <i>Жодних фішингових тригерів не виявлено.</i>')
            keyboard = build_alert_keyboard(clean_domain, is_whitelisted_status=status in ['LEGITIMATE', 'WHITELISTED'])
            card_text = '\n'.join(card_lines)
            if temp_msg and 'message_id' in temp_msg:
                await self.edit_message_text(chat_id, temp_msg['message_id'], card_text, reply_markup=keyboard)
            else:
                await self.send_message(chat_id, card_text, reply_markup=keyboard)
        except Exception as e:
            logger.error(f'Error checking domain {clean_domain}: {e}')
            err_text = f'❌ Помилка під час аналізу <code>{clean_domain}</code>: {e}'
            if temp_msg and 'message_id' in temp_msg:
                await self.edit_message_text(chat_id, temp_msg['message_id'], err_text)
            else:
                await self.send_message(chat_id, err_text)

    def build_scan_presets_keyboard(self) -> Dict[str, Any]:
        return {'inline_keyboard': [[{'text': '⚡ 50 мутацій (10 потоків)', 'callback_data': 'scan_run:50:10'}, {'text': '🚀 250 мутацій (20 потоків)', 'callback_data': 'scan_run:250:20'}], [{'text': '🔥 500 мутацій (25 потоків)', 'callback_data': 'scan_run:500:25'}, {'text': '💥 1000 мутацій (30 потоків)', 'callback_data': 'scan_run:1000:30'}], [{'text': '⚙️ Власний ліміт (/scan N потоки)', 'callback_data': 'scan_manual_help'}]]}

    async def handle_scan_mutations(self, chat_id: int | str, text: str):
        parts = text.strip().split()
        if len(parts) >= 2 and parts[1].isdigit():
            count = min(max(5, int(parts[1])), 5000)
            concurrency = 15
            if len(parts) >= 3 and parts[2].isdigit():
                concurrency = min(max(1, int(parts[2])), 50)
            asyncio.create_task(self.execute_mutation_scan(chat_id, count=count, concurrency=concurrency))
        else:
            msg = '⚡ <b>Сканування мутацій бренду TRUSTEE</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\nОберіть бажану кількість доменів та швидкість (потоки):\n\n💡 <i>Або вкажіть вручну:</i> <code>/scan &lt;к-ть&gt; &lt;потоки&gt;</code>\n<i>(наприклад: <code>/scan 1000 30</code>)</i>'
            await self.send_message(chat_id, msg, reply_markup=self.build_scan_presets_keyboard())

    async def execute_mutation_scan(self, chat_id: int | str, count: int=50, concurrency: int=10, message_id: Optional[int]=None):
        status_text = f'⚡ <b>Запуск генерації мутацій та сканування...</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n🎯 <b>Кількість доменів:</b> {count}\n⚡ <b>Паралельних потоків:</b> {concurrency}\n\n⏳ <i>Йде перевірка DNS, HTTP, SSL та аналіз контенту сторінок...</i>'
        if message_id:
            await self.edit_message_text(chat_id, message_id, status_text)
            init_msg = {'message_id': message_id}
        else:
            init_msg = await self.send_message(chat_id, status_text)
        try:
            from trustee_monitor.modules.mutation_generator import generate_domain_permutations
            from trustee_monitor.services.scanner_service import analyze_domain
            domains = generate_domain_permutations(max_count=count)
            total = len(domains)
            sem = asyncio.Semaphore(concurrency)
            scanned = 0
            active_threats = []
            suspicious = []
            dormant = []
            clean = []
            loop = asyncio.get_running_loop()
            last_edit_time = loop.time()

            async def sem_check(d):
                nonlocal scanned, last_edit_time
                async with sem:
                    try:
                        res = await analyze_domain(d, source='telegram_mutation_scan')
                        scanned += 1
                        status = res.get('status')
                        if status == 'active_phishing':
                            active_threats.append(res)
                        elif status == 'suspicious':
                            suspicious.append(res)
                        elif status in ['dormant', 'parked']:
                            dormant.append(res)
                        else:
                            clean.append(res)
                        now_t = loop.time()
                        if init_msg and 'message_id' in init_msg and (now_t - last_edit_time > 2.5 or scanned == total):
                            last_edit_time = now_t
                            prog_lines = f'⚡ <b>Сканування мутацій у процесі...</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n📊 <b>Прогрес:</b> {scanned}/{total} ({scanned / total * 100:.0f}%)\n⚡ <b>Потоків:</b> {concurrency}\n\n • 🔴 Активний фішинг: {len(active_threats)}\n • 🟡 Підозрілі: {len(suspicious)}\n • 💤 Сплячі: {len(dormant)}\n • 🟢 Чисті: {len(clean)}'
                            await self.edit_message_text(chat_id, init_msg['message_id'], prog_lines)
                    except Exception as e:
                        logger.error(f'Error scanning mutation {d}: {e}')
            tasks = [sem_check(d) for d in domains]
            await asyncio.gather(*tasks, return_exceptions=True)
            lines = ['✅ <b>Сканування мутацій завершено!</b>', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━', f'🌐 <b>Перевірено згенерованих доменів:</b> {scanned} (у {concurrency} потоків)', f' • 🔴 <b>Активний фішинг [!!!]:</b> {len(active_threats)}', f' • 🟡 <b>Підозрілі домени [ ! ]:</b> {len(suspicious)}', f' • 💤 <b>Сплячі / Парковані:</b> {len(dormant)}', f' • 🟢 <b>Чисті / NXDOMAIN:</b> {len(clean)}']
            all_threats = active_threats + suspicious
            if all_threats:
                lines.append('\n🚨 <b>Виявлені підозрілі домени:</b>')
                all_threats.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
                for t in all_threats[:8]:
                    dom = t.get('domain', '')
                    sc = t.get('risk_score', 0)
                    st = t.get('status', '').upper()
                    lines.append(f' • <code>{dom}</code> — <b>{sc}/100</b> [{st}]')
            else:
                lines.append('\n🛡 <i>Жодних активних фішингових загроз серед перевірених не знайдено!</i>')
            report_text = '\n'.join(lines)
            if init_msg and 'message_id' in init_msg:
                await self.edit_message_text(chat_id, init_msg['message_id'], report_text)
            else:
                await self.send_message(chat_id, report_text)
        except Exception as e:
            logger.error(f'Error in telegram scan mutations: {e}')
            err = f'❌ Помилка під час сканування мутацій: {e}'
            if init_msg and 'message_id' in init_msg:
                await self.edit_message_text(chat_id, init_msg['message_id'], err)
            else:
                await self.send_message(chat_id, err)

    async def handle_recheck_dormant(self, chat_id: int | str, text: str=''):
        asyncio.create_task(self.execute_recheck_dormant(chat_id, limit=0, concurrency=50))

    async def execute_recheck_dormant(self, chat_id: int | str, limit: int=0, concurrency: int=50, message_id: Optional[int]=None):
        status_text = f'🔄 <b>Запущено повторну перевірку ВСІЄЇ бази сплячих доменів...</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n🎯 <b>Обсяг перевірки:</b> ВСЯ БАЗА (усі сплячі домени)\n⚡ <b>Паралельних потоків:</b> {concurrency}\n🕒 <b>Автоматичний розклад:</b> кожні {AUTO_RECHECK_INTERVAL_HOURS} годин\n\n⏳ <i>Опитую базу PostgreSQL та сканую сайти на предмет раптової активації фішингу...</i>'
        if message_id:
            await self.edit_message_text(chat_id, message_id, status_text)
            init_msg = {'message_id': message_id}
        else:
            init_msg = await self.send_message(chat_id, status_text)
        try:
            from trustee_monitor.services.recheck_service import recheck_dormant_domains
            loop = asyncio.get_running_loop()
            last_edit_time = loop.time()

            async def progress_callback(completed: int, total_count: int):
                nonlocal last_edit_time
                now_t = loop.time()
                if init_msg and 'message_id' in init_msg and (now_t - last_edit_time > 2.5 or completed == total_count):
                    last_edit_time = now_t
                    pct = f'({completed / total_count * 100:.0f}%)' if total_count > 0 else ''
                    prog = f'🔄 <b>Повторна перевірка сплячих у процесі...</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n📊 <b>Прогрес:</b> {completed}/{total_count} {pct}\n⚡ <b>Потоків:</b> {concurrency}\n\n⏳ <i>Перевірка статусів DNS/HTTP/SSL...</i>'
                    await self.edit_message_text(chat_id, init_msg['message_id'], prog)
            results = await recheck_dormant_domains(limit=limit, concurrency=concurrency, on_progress=progress_callback)
            total = len(results)
            if total == 0:
                report = '✅ <b>Повторна перевірка сплячих завершена!</b>\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━\nℹ️ <i>У базі наразі немає сплячих доменів для перевірки.</i>'
            else:
                activated = [r for r in results if r.get('status') in ['active_phishing', 'suspicious']]
                dormant = [r for r in results if r.get('status') in ['dormant', 'parked']]
                clean = [r for r in results if r.get('status') not in ['active_phishing', 'suspicious', 'dormant', 'parked']]
                lines = ['✅ <b>Повторна перевірка сплячих завершена!</b>', '━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n', f'📊 <b>Всього перевірено доменів:</b> {total} (у {concurrency} потоків)', f' • 🔴 <b>Активовано загроз:</b> {len(activated)}', f' • 💤 <b>Залишились сплячими:</b> {len(dormant)}', f' • 🟢 <b>Недоступні / чисті:</b> {len(clean)}']
                if activated:
                    lines.append('\n⚠️ <b>Увага! Домени, які раптово активувалися:</b>')
                    for a in activated[:6]:
                        dom = a.get('domain', '')
                        sc = a.get('risk_score', 0)
                        st = a.get('status', '').upper()
                        lines.append(f' • <code>{dom}</code> — <b>{sc}/100</b> [{st}]')
                else:
                    lines.append('\n🛡 <i>Усі перевірені домени безпечні або залишаються неактивними.</i>')
                report = '\n'.join(lines)
            if init_msg and 'message_id' in init_msg:
                await self.edit_message_text(chat_id, init_msg['message_id'], report)
            else:
                await self.send_message(chat_id, report)
        except Exception as e:
            logger.error(f'Error in handle_recheck_dormant: {e}')
            err = f'❌ Помилка під час recheck сплячих: {e}'
            if init_msg and 'message_id' in init_msg:
                await self.edit_message_text(chat_id, init_msg['message_id'], err)
            else:
                await self.send_message(chat_id, err)

    async def handle_callback_query(self, cb: Dict[str, Any]):
        cb_id = cb.get('id')
        data = cb.get('data', '')
        message = cb.get('message', {})
        chat_id = message.get('chat', {}).get('id')
        message_id = message.get('message_id')
        from_user = cb.get('from', {})
        username = from_user.get('username') or from_user.get('first_name', 'admin')
        if not cb_id or not chat_id:
            return
        user_id = from_user.get('id') or chat_id
        now_ts = time.time()
        cb_key = f'{user_id}:{data}'
        if cb_key in self._action_cooldown and now_ts - self._action_cooldown[cb_key] < 1.5:
            await self.answer_callback_query(cb_id, text='⏳ Запит уже виконується...')
            return
        self._action_cooldown[cb_key] = now_ts
        if len(self._action_cooldown) > 1000:
            self._action_cooldown = {k: v for k, v in self._action_cooldown.items() if now_ts - v < 10.0}
        if data.startswith('recheck:'):
            domain = data.split(':', 1)[1]
            await self.answer_callback_query(cb_id, text=f'🔄 Запущено Re-check для {domain}...')
            from trustee_monitor.services.scanner_service import analyze_domain
            res = await analyze_domain(domain, source='telegram_recheck')
            score = res.get('risk_score', 0)
            status = res.get('status', 'unknown').upper()
            now_str = datetime.now(timezone.utc).strftime('%H:%M:%S')
            original_text = message.get('text', '')
            update_note = f'\n\n🔄 <i>Re-check оновлено о {now_str} UTC: Score {score}/100 [{status}]</i>'
            clean_text = re.sub('\\n\\n🔄 <i>Re-check оновлено.*?</i>', '', original_text, flags=re.DOTALL)
            new_text = clean_text + update_note
            keyboard = build_alert_keyboard(domain, is_whitelisted_status=status in ['LEGITIMATE', 'WHITELISTED'])
            await self.edit_message_text(chat_id, message_id, new_text, reply_markup=keyboard)
        elif data.startswith('whitelist:'):
            from trustee_monitor.services.whitelist_service import add_to_whitelist
            domain = data.split(':', 1)[1]
            await add_to_whitelist(domain, added_by=f'@{username}')
            await self.answer_callback_query(cb_id, text=f'✅ {domain} додано до Whitelist!', show_alert=True)
            original_text = message.get('text', '')
            whitelist_note = f'\n\n✅ <b>Додано до WhiteList користувачем @{username}</b>. Сповіщення вимкнено.'
            new_text = original_text + whitelist_note
            keyboard = build_alert_keyboard(domain, is_whitelisted_status=True)
            await self.edit_message_text(chat_id, message_id, new_text, reply_markup=keyboard)
        elif data.startswith('details:'):
            domain = data.split(':', 1)[1]
            await self.answer_callback_query(cb_id, text='📋 Отримання технічних деталей...')
            from sqlalchemy import select
            details_text = f'📋 <b>Технічний звіт для <code>{domain}</code>:</b>\n'
            try:
                async with get_db_session() as session:
                    stmt = select(Domain).where(Domain.domain_name == domain)
                    res = await session.execute(stmt)
                    dom = res.scalar_one_or_none()
                    if dom and dom.checks:
                        latest_chk = dom.checks[0]
                        raw = {}
                        if latest_chk.raw_details:
                            try:
                                raw = json.loads(latest_chk.raw_details)
                            except Exception:
                                pass
                        dns_info = raw.get('dns', {})
                        details_text += f" • <b>IP-адреса:</b> <code>{latest_chk.ip_address or '—'}</code>\n • <b>MX-записи:</b> <code>{latest_chk.mx_records or 'відсутні'}</code>\n • <b>NS-сервери:</b> <code>{', '.join(dns_info.get('ns_records', [])) or '—'}</code>\n • <b>SSL Issuer:</b> {latest_chk.ssl_issuer or 'Немає / Self-signed'}\n • <b>Вік SSL:</b> {latest_chk.ssl_age_days or 0} днів\n • <b>HTTP Заголовок:</b> <i>{raw.get('title') or '—'}</i>\n • <b>Збіги слів:</b> <code>{', '.join(latest_chk.keywords_list) or '—'}</code>"
                    else:
                        details_text += '<i>Історія перевірок для цього домену ще порожня.</i>'
            except Exception as e:
                details_text += f'<i>Помилка завантаження: {e}</i>'
            await self.send_message(chat_id, details_text)
        elif data.startswith('wl_page:'):
            try:
                page_num = int(data.split(':', 1)[1])
            except ValueError:
                page_num = 1
            await self.answer_callback_query(cb_id)
            text, keyboard = await self.get_whitelist_page_content(page=page_num)
            await self.edit_message_text(chat_id, message_id, text, reply_markup=keyboard)
        elif data.startswith('scan_run:'):
            parts = data.split(':')
            count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 50
            concurrency = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 10
            await self.answer_callback_query(cb_id, text=f'🚀 Запуск: {count} мутацій ({concurrency} потоків)...')
            asyncio.create_task(self.execute_mutation_scan(chat_id, count=count, concurrency=concurrency, message_id=message_id))
        elif data == 'scan_manual_help':
            await self.answer_callback_query(cb_id, text='Вкажіть у чат команду:\n/scan <кількість> <потоки>\nНаприклад: /scan 100 20', show_alert=True)
        elif data == 'noop':
            await self.answer_callback_query(cb_id)

    async def poll_updates(self):
        offset = 0
        logger.info('Telegram Bot interactive polling started...')
        while self.is_running:
            try:
                url = f'{self.api_url}/getUpdates'
                params = {'offset': offset, 'timeout': 25}
                async with httpx.AsyncClient(timeout=35.0) as client:
                    resp = await client.get(url, params=params)
                if resp.status_code != 200:
                    logger.warning(f'Telegram polling status {resp.status_code}: {resp.text}')
                    await asyncio.sleep(5)
                    continue
                data = resp.json()
                updates = data.get('result', [])
                for update in updates:
                    update_id = update.get('update_id', 0)
                    offset = max(offset, update_id + 1)
                    if update_id in self._processed_updates:
                        continue
                    self._processed_updates.add(update_id)
                    if len(self._processed_updates) > 3000:
                        self._processed_updates = set(list(self._processed_updates)[-1000:])
                    if 'callback_query' in update:
                        asyncio.create_task(self.handle_callback_query(update['callback_query']))
                        continue
                    message = update.get('message')
                    if not message or 'text' not in message:
                        continue
                    chat_id = message['chat']['id']
                    text = message['text'].strip()
                    user = message.get('from', {}).get('username', '')
                    if text.startswith('/start') or text.startswith('/help'):
                        asyncio.create_task(self.handle_start(chat_id))
                    elif text.startswith('/status') or text == '📊 Статус системи' or text == '📊 Статус':
                        asyncio.create_task(self.handle_status(chat_id))
                    elif text.startswith('/recent') or text.startswith('/alerts') or text == '🚨 Останні загрози':
                        asyncio.create_task(self.handle_recent(chat_id))
                    elif text.startswith('/scan') or text == '⚡ Сканувати мутації':
                        asyncio.create_task(self.handle_scan_mutations(chat_id, text))
                    elif text.startswith('/whitelist_add'):
                        asyncio.create_task(self.handle_whitelist_add(chat_id, text, user))
                    elif text.startswith('/whitelist_del'):
                        asyncio.create_task(self.handle_whitelist_del(chat_id, text))
                    elif text.startswith('/whitelist') or text == '⚪ Білий список':
                        asyncio.create_task(self.handle_whitelist_view(chat_id))
                    elif text.startswith('/recheck') or 'recheck' in text.lower():
                        asyncio.create_task(self.handle_recheck_dormant(chat_id, text=text))
                    elif text.startswith('/check'):
                        parts = text.split(maxsplit=1)
                        if len(parts) > 1:
                            asyncio.create_task(self.handle_check_domain(chat_id, parts[1]))
                        else:
                            await self.send_message(chat_id, '⚠️ Будь ласка, вкажіть домен: <code>/check trusteecard.com</code>')
                    elif '.' in text and (not text.startswith('/')) and (len(text.split()) == 1):
                        asyncio.create_task(self.handle_check_domain(chat_id, text))
            except asyncio.CancelledError:
                logger.info('Telegram Bot polling loop cancelled.')
                break
            except (httpx.ReadTimeout, httpx.ConnectTimeout):
                continue
            except Exception as e:
                logger.error(f'Error in Telegram Bot polling: {e}')
                await asyncio.sleep(5)
_bot_service: Optional[TelegramBotService] = None

async def start_telegram_bot_polling():
    global _bot_service
    if not TELEGRAM_BOT_TOKEN:
        logger.warning('TELEGRAM_BOT_TOKEN is not configured. Interactive Telegram Bot is disabled.')
        return
    _bot_service = TelegramBotService(TELEGRAM_BOT_TOKEN)
    _bot_service.is_running = True
    await _bot_service.poll_updates()

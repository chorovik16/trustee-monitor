import sys
import asyncio
import argparse
import logging
from pathlib import Path

# Fix Windows console UTF-8 encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding='utf-8')
        sys.stderr.reconfigure(encoding='utf-8')
    except Exception:
        pass

# Add project root and parent to sys.path so trustee_monitor imports cleanly everywhere
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(ROOT_DIR.parent) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR.parent))

from trustee_monitor.database.connection import init_db
from trustee_monitor.modules.mutation_generator import generate_domain_permutations
from trustee_monitor.modules.certstream_listener import start_certstream_listener
from trustee_monitor.services.scanner_service import analyze_domain
from trustee_monitor.services.recheck_service import recheck_domain, recheck_dormant_domains

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("trustee_monitor")

BANNER = r"""
========================================================================
   ______ ____   __  __ _____ ______ ______ ______    ___   _   _ _____ _____
  |_   _||  _ \ |  ||  |/ ____||_   _||  ____||  ____|  / _ \ | \ | |_   _|  ___|
    | |  | |_) ||  ||  | (___    | |  | |__   | |__    / /_\ \|  \| | | | | |__  
    | |  |  _ < |  ||  |\___ \   | |  |  __|  |  __|   |  _  || . ` | | | |  __| 
    | |  | | \ \|  ||  |____) |  | |  | |____ | |____  | | | || |\  |_| |_| |    
    \_/  |_|  \_\\____/|_____/   \_/  |______||______| \_| |_/\_| \_/_____/\_|    
           PROACTIVE PHISHING DETECTION & RE-CHECK SYSTEM FOR TRUSTEE
========================================================================
"""

async def run_check_command(domain: str):
    """Executes single domain check and prints full history timeline."""
    print(BANNER)
    print(f"[*] Перевірка домену: {domain}...")
    try:
        await init_db()
    except Exception as e:
        logger.error(f"Помилка підключення до БД: {e}")
        return

    result = await recheck_domain(domain)
    print("\n" + result["formatted_timeline"])
    curr = result["current_result"]
    print(f"[>] ПІДСУМОК: Стан: {curr['status'].upper()} | Ризик-бал: {curr['risk_score']}/100")
    if curr['triggers']:
        print("[>] Знайдені фактори:")
        for t in curr['triggers']:
            print(f"   - {t}")


async def run_scan_mutations_command(count: int = 50, concurrency: int = 10):
    """Generates permutations and scans them concurrently."""
    print(BANNER)
    try:
        await init_db()
    except Exception as e:
        logger.error(f"Помилка підключення до БД: {e}")
        return

    print(f"[*] Генерація мутацій навколо брендів TRUSTEE (ліміт: {count})...")
    domains = generate_domain_permutations(max_count=count)
    print(f"[+] Згенеровано {len(domains)} унікальних доменів для перевірки.")
    print(f"[*] Початок паралельного сканування (потоків: {concurrency})...\n")

    semaphore = asyncio.Semaphore(concurrency)
    scanned_count = 0
    suspicious_found = 0

    async def sem_analyze(d):
        nonlocal scanned_count, suspicious_found
        async with semaphore:
            res = await analyze_domain(d, source="mutation_generator")
            scanned_count += 1
            if res["status"] in ["suspicious", "active_phishing"]:
                suspicious_found += 1
                print(f"[!] [{res['status'].upper()}] {d} -> Score: {res['risk_score']} | IP: {res.get('ip_address')}")
            else:
                if scanned_count % 10 == 0 or scanned_count == len(domains):
                    print(f"[{scanned_count}/{len(domains)}] Оброблено доменів... (Знайдено підозрілих: {suspicious_found})")
            return res

    tasks = [sem_analyze(d) for d in domains]
    await asyncio.gather(*tasks, return_exceptions=True)

    print("\n" + "="*60)
    print(f"[OK] Сканування завершено! Перевірено: {scanned_count}, Виявлено підозрілих: {suspicious_found}")
    print("="*60)


async def run_daemon_command():
    """Runs continuous real-time CertStream listener and periodic re-check."""
    print(BANNER)
    try:
        await init_db()
    except Exception as e:
        logger.error(f"Помилка підключення до БД: {e}")
        return

    print("[*] Запуск режиму 24/7 моніторингу...")
    print("[*] 1. Слухач CertStream (нові SSL-сертифікати в реальному часі)")
    print("[*] 2. Фонові повторні перевірки сплячих доменів кожні 6 годин\n")

    async def on_certstream_match(domain_name: str):
        logger.info(f"[*] Аналіз виявленого з CertStream домену: {domain_name}")
        res = await analyze_domain(domain_name, source="certstream")
        if res["status"] in ["suspicious", "active_phishing"]:
            logger.warning(f"[!] [ЗАГРОЗА] {domain_name} -> Score: {res['risk_score']}")

    async def periodic_recheck_loop():
        while True:
            try:
                # Sleep for 6 hours between dormant re-checks
                await asyncio.sleep(6 * 3600)
                logger.info("[*] Запуск планової повторної перевірки сплячих доменів...")
                await recheck_dormant_domains(limit=50)
            except Exception as e:
                logger.error(f"Помилка у фоновому recheck: {e}")

    # Run both concurrently
    await asyncio.gather(
        start_certstream_listener(on_certstream_match),
        periodic_recheck_loop()
    )


async def run_list_command(status_filter: str = None, limit: int = 50):
    """Lists domains from the database in a formatted table with optional limit and filtering."""
    print(BANNER)
    try:
        await init_db()
    except Exception as e:
        logger.error(f"Помилка підключення до БД: {e}")
        return

    from sqlalchemy import select, func
    from trustee_monitor.database.connection import get_db_session
    from trustee_monitor.database.models import Domain, DomainCheck

    async with get_db_session() as session:
        total_count_stmt = select(func.count(Domain.id))
        if status_filter:
            total_count_stmt = total_count_stmt.where(Domain.current_status == status_filter.lower())
        total_domains = (await session.execute(total_count_stmt)).scalar() or 0

        stmt = select(Domain).order_by(Domain.current_risk_score.desc())
        if status_filter:
            stmt = stmt.where(Domain.current_status == status_filter.lower())
        if limit and limit > 0:
            stmt = stmt.limit(limit)

        result = await session.execute(stmt)
        domains = result.scalars().all()

        count_stmt = select(func.count(DomainCheck.id))
        count_res = await session.execute(count_stmt)
        total_checks = count_res.scalar() or 0

    if not domains:
        print("[i] Доменів не знайдено за заданими фільтрами.")
        return

    status_icons = {
        "active_phishing": "!!!",
        "suspicious": " ! ",
        "dormant": " ~ ",
        "parked": " P ",
        "clean": " . ",
        "legitimate": " V ",
    }

    shown = len(domains)
    print(f"[*] Всього доменів у базі: {total_domains} | Показано: {shown} | Всього перевірок: {total_checks}")
    if status_filter:
        print(f"[*] Фільтр статусу: {status_filter.upper()}")
    if limit and limit > 0 and shown < total_domains:
        print(f"[*] Відображено ТОП-{limit} найризикованіших. (Вкажіть --limit 100 або --limit 0 для всіх)")
    print()
    print(f"{'#':<4} {'Ст':>3}  {'Score':>5}  {'Домен':<35} {'Статус':<18} {'Останній чек':<20}")
    print("-" * 90)

    for idx, d in enumerate(domains, 1):
        icon = status_icons.get(d.current_status, " ? ")
        last_check = d.last_checked_at.strftime("%d.%m.%Y %H:%M") if d.last_checked_at else "---"
        print(f"{idx:<4} [{icon}] {d.current_risk_score:>3}/100  {d.domain_name:<35} {d.current_status:<18} {last_check:<20}")

    print("-" * 90)
    print()
    print("Легенда: [!!!] Active Phishing | [ ! ] Suspicious | [ ~ ] Dormant | [ P ] Parked | [ . ] Clean | [ V ] Legitimate")


def main():
    parser = argparse.ArgumentParser(
        description="TRUSTEE Anti-Phishing Monitoring & Re-Check System",
        formatter_class=argparse.RawTextHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", type=str, metavar="DOMAIN", help="Перевірити конкретний домен та вивести хронологію змін")
    group.add_argument("--scan-mutations", action="store_true", help="Згенерувати мутації бренду та запустити сканування")
    group.add_argument("--daemon", action="store_true", help="Запустити безперервний фоновий моніторинг (CertStream)")
    group.add_argument("--init-db", action="store_true", help="Ініціалізувати таблиці в базі даних")
    group.add_argument("--recheck-dormant", action="store_true", help="Запустити повторну перевірку сплячих доменів із БД")
    group.add_argument("--list", action="store_true", help="Вивести домени з бази даних (з лімітом ТОП за замовчуванням)")

    parser.add_argument("--count", type=int, default=50, help="Кількість мутацій для сканування (за замовчуванням: 50)")
    parser.add_argument("--concurrency", type=int, default=10, help="Кількість паралельних потоків (за замовчуванням: 10)")
    parser.add_argument("--status", type=str, default=None, help="Фільтр статусу для --list (suspicious, active_phishing, dormant, parked, clean)")
    parser.add_argument("--limit", type=int, default=50, help="Кількість доменів для виводу у --list (за замовчуванням: 50, 0 = без ліміту)")

    args = parser.parse_args()

    if args.init_db:
        asyncio.run(init_db())
        print("[OK] Таблиці бази даних успішно створено.")
    elif args.check:
        asyncio.run(run_check_command(args.check))
    elif args.scan_mutations:
        asyncio.run(run_scan_mutations_command(count=args.count, concurrency=args.concurrency))
    elif args.daemon:
        try:
            asyncio.run(run_daemon_command())
        except (KeyboardInterrupt, SystemExit):
            print("\n[OK] Фоновий моніторинг зупинено користувачем (Ctrl+C).")
    elif args.recheck_dormant:
        asyncio.run(recheck_dormant_domains())
        print("[OK] Повторну перевірку сплячих доменів завершено.")
    elif args.list:
        asyncio.run(run_list_command(status_filter=args.status, limit=args.limit))

if __name__ == "__main__":
    main()


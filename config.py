import os
from pathlib import Path
from dotenv import load_dotenv
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / '.env', override=False)
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql+asyncpg://postgres:postgres@localhost:5432/trustee_antifish')
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '').strip()
_raw_chat_ids = os.getenv('TELEGRAM_CHAT_ID', '').strip()
TELEGRAM_CHAT_IDS = list(dict.fromkeys((cid.strip() for cid in _raw_chat_ids.split(',') if cid.strip())))
TELEGRAM_CHAT_ID = TELEGRAM_CHAT_IDS[0] if TELEGRAM_CHAT_IDS else ''
MIN_ALERT_SCORE = int(os.getenv('MIN_ALERT_SCORE', '60'))
DEFAULT_TIMEOUT = int(os.getenv('DEFAULT_TIMEOUT', '8'))
CERTSTREAM_URL = os.getenv('CERTSTREAM_URL', 'wss://certstream.calidog.io/')
AUTO_RECHECK_INTERVAL_HOURS = int(os.getenv('AUTO_RECHECK_INTERVAL_HOURS', '6'))
LEGITIMATE_DOMAINS = ['trustee.io', 'trusteeglobal.com']
BRAND_TARGETS = ['trustee', 'trusteeplus', 'trusteewallet', 'trustee-plus', 'trustee-wallet']
SUSPICIOUS_KEYWORDS = ['seed', 'seed phrase', '12 words', '24 words', 'mnemonic', 'private key', 'recovery', 'restore', 'restore wallet', 'connect wallet', 'web3', 'crypto', 'card', 'mastercard', 'virtual card', 'download', 'apk', 'install', 'airdrop', 'bonus', 'reward', 'promo', 'claim', 'support', 'helpdesk', 'verify', 'auth', 'login', 'security', 'security update', 'kyc']

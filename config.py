import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://postgres:postgres@localhost:5432/trustee_antifish")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
MIN_ALERT_SCORE = int(os.getenv("MIN_ALERT_SCORE", "60"))
DEFAULT_TIMEOUT = int(os.getenv("DEFAULT_TIMEOUT", "8"))

# Legitimate official brand domains (Never alert on these & their subdomains)
LEGITIMATE_DOMAINS = [
    "trustee.io",
    "trusteeglobal.com"
]

# Target brands and keywords for Trustee
BRAND_TARGETS = ["trustee", "trusteeplus", "trusteewallet", "trustee-plus", "trustee-wallet"]

# Phishing / high-risk words often squatted with Trustee
SUSPICIOUS_KEYWORDS = [
    "seed", "seed phrase", "12 words", "24 words", "mnemonic", "private key",
    "recovery", "restore", "restore wallet", "connect wallet", "web3", "crypto",
    "card", "mastercard", "virtual card", "download", "apk", "install",
    "airdrop", "bonus", "reward", "promo", "claim", "support", "helpdesk",
    "verify", "auth", "login", "security", "security update", "kyc"
]

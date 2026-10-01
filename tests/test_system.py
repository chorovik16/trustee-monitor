import pytest
import asyncio
import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from trustee_monitor.modules.mutation_generator import (
    generate_domain_permutations,
    generate_homoglyphs,
    generate_typos,
    generate_combos,
    is_trustee_candidate
)
from trustee_monitor.modules.risk_scorer import calculate_risk_score
from trustee_monitor.services.recheck_service import recheck_domain
from trustee_monitor.database.connection import init_db

def test_permutations_generation():
    perms = generate_domain_permutations(["trustee"], ["com", "io"], max_count=50)
    assert len(perms) > 0
    # Must not contain whitelisted trustee.io
    assert "trustee.io" not in perms
    # Check typo / combo existence
    assert any("wallet" in p or "plus" in p or "card" in p or "truste" in p for p in perms)

def test_homoglyphs():
    homos = generate_homoglyphs("trustee")
    # Must produce Punycode xn--
    assert any("xn--" in h for h in homos)

def test_candidate_detection():
    assert is_trustee_candidate("trustee-wallet.com") is True
    assert is_trustee_candidate("truste-card.xyz") is True
    assert is_trustee_candidate("google.com") is False
    assert is_trustee_candidate("binance.com") is False

def test_risk_scorer_heuristics():
    # 1. Official domain whitelist
    score, status, _ = calculate_risk_score({}, {}, "trustee.io")
    assert score == 0
    assert status == "legitimate"

    # 2. Phishing with seed phrase
    dns_active = {"is_resolvable": True, "ip": "1.2.3.4", "has_mx": False}
    content_phish = {
        "http_status": 200,
        "is_parked": False,
        "triggered_categories": ["seed_phrase", "brand_spoofing"],
        "trigger_details": ["seed phrase", "trustee wallet"],
        "matched_keywords": ["seed", "wallet", "crypto"],
        "ssl_info": {"has_ssl": True, "issuer": "Let's Encrypt", "issued_days_ago": 1}
    }
    score, status, triggers = calculate_risk_score(dns_active, content_phish, "trustee-fake.com")
    assert score >= 80
    assert status == "active_phishing"
    assert any("сід-фраз" in t for t in triggers)

    # 3. Parked domain penalty
    content_parked = {
        "http_status": 200,
        "is_parked": True,
        "triggered_categories": [],
        "trigger_details": [],
        "matched_keywords": [],
        "ssl_info": {}
    }
    score, status, _ = calculate_risk_score(dns_active, content_parked, "trustee-parked.xyz")
    assert score <= 25
    assert status == "parked"

@pytest.mark.asyncio
async def test_recheck_and_database_persistence():
    await init_db()
    # Test checking a mock domain
    domain = "test-trustee-mock.net"
    result = await recheck_domain(domain)
    assert result["domain"] == domain
    assert result["total_checks"] >= 1
    assert "ХРОНОЛОГІЯ ПЕРЕВІРОК" in result["formatted_timeline"]

if __name__ == "__main__":
    print("Running unit tests...")
    test_permutations_generation()
    test_homoglyphs()
    test_candidate_detection()
    test_risk_scorer_heuristics()
    asyncio.run(test_recheck_and_database_persistence())
    print("[OK] All tests passed successfully!")

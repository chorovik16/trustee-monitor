import itertools
from typing import Set, List

# Cyrillic / visual homoglyphs for Latin characters
HOMOGLYPH_MAP = {
    'e': ['е', 'ë'],       # Cyrillic 'е' (U+0435)
    'o': ['о'],            # Cyrillic 'о' (U+043E)
    'a': ['а'],            # Cyrillic 'а' (U+0430)
    'c': ['с'],            # Cyrillic 'с' (U+0441)
    'i': ['і', '1', 'l'],  # Cyrillic 'і' or numbers
    's': ['ѕ'],            # Cyrillic 'ѕ' (U+0455)
    't': ['т']             # Cyrillic 'т'
}

COMMON_TLDS = [
    "com", "io", "net", "org", "app", "xyz", "top", "online",
    "cc", "site", "link", "me", "live", "store", "tech"
]

AFFIXES = [
    # Products & features
    "plus", "wallet", "card", "pay", "app", "crypto", "token",
    # Actions & Fraud vectors
    "login", "auth", "connect", "restore", "recovery", "web", "download", "apk",
    "support", "help", "security", "verify", "bonus", "airdrop", "claim", "official"
]

SEPARATORS = ["-", ""]

def generate_typos(base_name: str) -> Set[str]:
    """Generates omission, repetition, and transposition typos."""
    results = set()
    n = len(base_name)

    # 1. Omissions (skip one char)
    for i in range(n):
        typo = base_name[:i] + base_name[i+1:]
        if len(typo) >= 4:
            results.add(typo)

    # 2. Character repetition
    for i in range(n):
        typo = base_name[:i] + base_name[i] + base_name[i:]
        results.add(typo)

    # 3. Transposition (swap adjacent characters)
    for i in range(n - 1):
        typo = base_name[:i] + base_name[i+1] + base_name[i] + base_name[i+2:]
        results.add(typo)

    return results

def generate_homoglyphs(base_name: str) -> Set[str]:
    """Generates IDN homoglyphs and encodes to Punycode."""
    results = set()

    for idx, char in enumerate(base_name):
        if char in HOMOGLYPH_MAP:
            for replacement in HOMOGLYPH_MAP[char]:
                substituted = base_name[:idx] + replacement + base_name[idx+1:]
                try:
                    # Convert to Punycode format (e.g. xn--...)
                    puny = substituted.encode('idna').decode('ascii')
                    results.add(puny)
                    results.add(substituted)
                except Exception:
                    pass

    return results

def generate_combos(base_name: str) -> Set[str]:
    """Generates combinations with keywords, prefixes, and suffixes."""
    results = set()
    for affix in AFFIXES:
        for sep in SEPARATORS:
            # Suffix: trustee-card, trusteeplus, etc.
            results.add(f"{base_name}{sep}{affix}")
            # Prefix: card-trustee, get-trustee, etc.
            results.add(f"{affix}{sep}{base_name}")
    return results

def generate_domain_permutations(
    bases: List[str] = None,
    tlds: List[str] = None,
    max_count: int = 500
) -> List[str]:
    """
    Generates a prioritized list of potential phishing domain permutations for TRUSTEE.
    """
    if bases is None:
        bases = ["trustee", "trusteeplus", "trusteewallet"]
    if tlds is None:
        tlds = COMMON_TLDS

    generated_names = set()

    for base in bases:
        # Base names with different TLDs
        generated_names.add(base)
        # Typos
        generated_names.update(generate_typos(base))
        # Homoglyphs
        generated_names.update(generate_homoglyphs(base))
        # Combos
        generated_names.update(generate_combos(base))

    full_domains = []
    # Primary TLDs first
    for name in generated_names:
        for tld in tlds:
            domain = f"{name}.{tld}"
            # Exclude legitimate trustee.io
            if domain.lower() in ["trustee.io", "www.trustee.io"]:
                continue
            full_domains.append(domain)
            if len(full_domains) >= max_count:
                return full_domains

    return full_domains

def is_trustee_candidate(domain_name: str) -> bool:
    """
    Quickly checks if an arbitrary domain (e.g. from CertStream) matches Trustee brand patterns.
    """
    clean_domain = domain_name.lower().strip().rstrip(".")
    # Remove port or subdomains if any for basic check
    parts = clean_domain.split(".")
    for part in parts:
        if "trustee" in part or "truste" in part or "trutsee" in part:
            return True
        # Check decoded punycode
        if part.startswith("xn--"):
            try:
                decoded = part.encode('ascii').decode('idna')
                if "trustee" in decoded:
                    return True
            except Exception:
                pass
    return False

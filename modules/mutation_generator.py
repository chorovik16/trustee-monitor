import re
from typing import Set, List
HOMOGLYPH_MAP = {'e': ['е', 'ë'], 'o': ['о'], 'a': ['а'], 'c': ['с'], 'i': ['і', '1', 'l'], 's': ['ѕ'], 't': ['т']}
COMMON_TLDS = ['com', 'io', 'net', 'org', 'app', 'xyz', 'top', 'online', 'cc', 'site', 'link', 'me', 'live', 'store', 'tech']
AFFIXES = ['plus', 'wallet', 'card', 'pay', 'app', 'crypto', 'token', 'login', 'auth', 'connect', 'restore', 'recovery', 'web', 'download', 'apk', 'support', 'help', 'security', 'verify', 'bonus', 'airdrop', 'claim', 'official']
SEPARATORS = ['-', '']

def generate_typos(base_name: str) -> Set[str]:
    results = set()
    n = len(base_name)
    for i in range(n):
        typo = base_name[:i] + base_name[i + 1:]
        if len(typo) >= 4:
            results.add(typo)
    for i in range(n):
        typo = base_name[:i] + base_name[i] + base_name[i:]
        results.add(typo)
    for i in range(n - 1):
        typo = base_name[:i] + base_name[i + 1] + base_name[i] + base_name[i + 2:]
        results.add(typo)
    return results

def generate_homoglyphs(base_name: str) -> Set[str]:
    results = set()
    for idx, char in enumerate(base_name):
        if char in HOMOGLYPH_MAP:
            for replacement in HOMOGLYPH_MAP[char]:
                substituted = base_name[:idx] + replacement + base_name[idx + 1:]
                try:
                    puny = substituted.encode('idna').decode('ascii')
                    results.add(puny)
                    results.add(substituted)
                except Exception:
                    pass
    return results

def generate_combos(base_name: str) -> Set[str]:
    results = set()
    for affix in AFFIXES:
        for sep in SEPARATORS:
            results.add(f'{base_name}{sep}{affix}')
            results.add(f'{affix}{sep}{base_name}')
    return results

def generate_domain_permutations(bases: List[str]=None, tlds: List[str]=None, max_count: int=500) -> List[str]:
    if bases is None:
        bases = ['trustee', 'trusteeplus', 'trusteewallet']
    if tlds is None:
        tlds = COMMON_TLDS
    generated_names = set()
    for base in bases:
        generated_names.add(base)
        generated_names.update(generate_typos(base))
        generated_names.update(generate_homoglyphs(base))
        generated_names.update(generate_combos(base))
    full_domains = []
    for name in generated_names:
        for tld in tlds:
            domain = f'{name}.{tld}'
            if domain.lower() in ['trustee.io', 'www.trustee.io']:
                continue
            full_domains.append(domain)
            if len(full_domains) >= max_count:
                return full_domains
    return full_domains

def is_trustee_candidate(domain_name: str) -> bool:
    clean_domain = domain_name.lower().strip().rstrip('.')
    parts = clean_domain.split('.')
    non_trustee_regex = '(?:untrusted|distrusted|entrusted|trusted|trustworthy|trustpilot|trustmark|trusting|trusteeship)'
    crypto_affixes = ['wallet', 'plus', 'card', 'crypto', 'pay', 'coin', 'token', 'btc', 'seed', 'trustee']
    for part in parts:
        if part.startswith('xn--'):
            try:
                decoded = part.encode('ascii').decode('idna')
                if 'trustee' in decoded:
                    return True
            except Exception:
                pass
        if 'trustee' in part:
            if 'trusteeship' in part and (not any((aff in clean_domain for aff in crypto_affixes))):
                continue
            return True
        if any((typo in part for typo in ['trutsee', 'turstee', 'trusetee', 'trustie', 'trusteee'])):
            return True
        if 'truste' in part:
            if re.search(non_trustee_regex, part):
                if any((aff in clean_domain for aff in crypto_affixes)):
                    return True
                continue
            return True
    return False

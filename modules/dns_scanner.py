import asyncio
import logging
from typing import Dict, Any, List
import dns.asyncresolver
import dns.resolver

logger = logging.getLogger(__name__)

async def scan_dns(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Performs asynchronous DNS resolution for A, AAAA, and MX records.
    Returns:
        dict: {
            "is_resolvable": bool,
            "ip": str or None,
            "all_ips": List[str],
            "mx_records": List[str],
            "has_mx": bool,
            "error": str or None
        }
    """
    clean_domain = domain.lower().strip().rstrip(".")
    result = {
        "is_resolvable": False,
        "ip": None,
        "all_ips": [],
        "mx_records": [],
        "has_mx": False,
        "error": None
    }

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    # Use dependable public DNS
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']

    # 1. Resolve A records
    try:
        a_records = await resolver.resolve(clean_domain, 'A')
        ips = [str(rdata) for rdata in a_records]
        if ips:
            result["is_resolvable"] = True
            result["ip"] = ips[0]
            result["all_ips"] = ips
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        pass
    except dns.resolver.Timeout:
        result["error"] = "DNS Timeout"
    except Exception as e:
        result["error"] = str(e)

    # 2. Resolve MX records (indicates email spoofing capability)
    try:
        mx_records = await resolver.resolve(clean_domain, 'MX')
        mx_hosts = [str(rdata.exchange).rstrip(".") for rdata in mx_records]
        if mx_hosts:
            result["mx_records"] = mx_hosts
            result["has_mx"] = True
            result["is_resolvable"] = True
    except Exception:
        pass

    return result

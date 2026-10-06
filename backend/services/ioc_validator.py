"""
IOC Validation Engine
Syntactic and structural validation for:
- IPv4 (RFC 5737 aware)
- IPv6
- Domain
- URL
- MD5, SHA-1, SHA-256 Hashes
- CVE ID

CRITICAL DEFENSIVE PRINCIPLE:
Validation means: "Is this syntactically valid data format?"
NOT: "Is this confirmed malicious?"
"""

import re
import ipaddress
from urllib.parse import urlparse

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
    re.IGNORECASE
)
EMAIL_PATTERN = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)

def validate_indicator(indicator_input: str) -> dict:
    """
    Validates any given indicator input string.
    Returns:
    {
        "valid": bool,
        "indicator_type": str,
        "normalized_value": str,
        "validation_notes": str
    }
    """
    if not indicator_input or not isinstance(indicator_input, str):
        return {
            "valid": False,
            "indicator_type": "UNKNOWN",
            "normalized_value": "",
            "validation_notes": "Empty or non-string indicator provided."
        }

    val = indicator_input.strip()

    # 1. Check CVE Format
    if CVE_PATTERN.match(val):
        normalized = val.upper()
        return {
            "valid": True,
            "indicator_type": "CVE ID",
            "normalized_value": normalized,
            "validation_notes": "Valid Common Vulnerabilities and Exposures (CVE) format."
        }

    # 2. Check Hashes
    if SHA256_PATTERN.match(val):
        return {
            "valid": True,
            "indicator_type": "FILE HASH (SHA-256)",
            "normalized_value": val.lower(),
            "validation_notes": "Valid 64-character hexadecimal SHA-256 hash syntax."
        }
    if SHA1_PATTERN.match(val):
        return {
            "valid": True,
            "indicator_type": "FILE HASH (SHA-1)",
            "normalized_value": val.lower(),
            "validation_notes": "Valid 40-character hexadecimal SHA-1 hash syntax."
        }
    if MD5_PATTERN.match(val):
        return {
            "valid": True,
            "indicator_type": "FILE HASH (MD5)",
            "normalized_value": val.lower(),
            "validation_notes": "Valid 32-character hexadecimal MD5 hash syntax."
        }

    # 3. Check IPv4 / IPv6
    try:
        ip_obj = ipaddress.ip_address(val)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            is_doc = ip_obj in ipaddress.ip_network("192.0.2.0/24") or \
                     ip_obj in ipaddress.ip_network("198.51.100.0/24") or \
                     ip_obj in ipaddress.ip_network("203.0.113.0/24")
            notes = "Valid IPv4 address (RFC 5737 Documentation block)" if is_doc else "Valid IPv4 address syntax."
            return {
                "valid": True,
                "indicator_type": "IP ADDRESS",
                "normalized_value": str(ip_obj),
                "validation_notes": notes
            }
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            return {
                "valid": True,
                "indicator_type": "IP ADDRESS (IPv6)",
                "normalized_value": str(ip_obj),
                "validation_notes": "Valid IPv6 address syntax."
            }
    except ValueError:
        pass

    # 4. Check Email address
    if EMAIL_PATTERN.match(val):
        return {
            "valid": True,
            "indicator_type": "EMAIL/SENDER DOMAIN",
            "normalized_value": val.lower(),
            "validation_notes": "Valid email/sender indicator syntax."
        }

    # 5. Check URL
    if val.startswith("http://") or val.startswith("https://"):
        try:
            parsed = urlparse(val)
            if parsed.netloc:
                return {
                    "valid": True,
                    "indicator_type": "URL",
                    "normalized_value": val,
                    "validation_notes": f"Valid URL structure targeting scheme '{parsed.scheme}' on host '{parsed.netloc}'."
                }
        except Exception:
            pass

    # 6. Check Domain
    if DOMAIN_PATTERN.match(val) and not val.endswith("."):
        return {
            "valid": True,
            "indicator_type": "DOMAIN",
            "normalized_value": val.lower(),
            "validation_notes": "Valid Fully Qualified Domain Name (FQDN) syntax."
        }

    # Invalid / Unsupported
    return {
        "valid": False,
        "indicator_type": "INVALID / UNKNOWN",
        "normalized_value": val,
        "validation_notes": "Indicator did not match any standard network/host/hash format."
    }

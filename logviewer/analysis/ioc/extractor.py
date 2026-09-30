import re
from typing import Dict, List


IOC_PATTERNS = {
    "ipv4": re.compile(
        r"\b(?:"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\."
        r"){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
    ),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,63}\b"
    ),
    "url": re.compile(
        r"https?://[^\s<>\"]+"
    ),
}


HASH_PATTERN = re.compile(
    r"\b("
    r"[a-fA-F0-9]{64}"
    r"|[a-fA-F0-9]{40}"
    r"|[a-fA-F0-9]{32}"
    r")\b"
)


def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract common indicators of compromise from text.

    Returns:
        Dictionary containing IOC types and unique values.

    The extractor preserves the existing IOC categories and output
    structure while avoiding regex scans that cannot produce a match.
    """

    results = {
        "ipv4": [],
        "domain": [],
        "url": [],
        "sha256": [],
        "sha1": [],
        "md5": [],
    }

    if not text:
        return results

    has_dot = "." in text

    if has_dot:
        results["ipv4"] = list(
            dict.fromkeys(IOC_PATTERNS["ipv4"].findall(text))
        )

        results["domain"] = list(
            dict.fromkeys(IOC_PATTERNS["domain"].findall(text))
        )

    if "http://" in text or "https://" in text:
        results["url"] = list(
            dict.fromkeys(IOC_PATTERNS["url"].findall(text))
        )

    if len(text) >= 32:
        for match in HASH_PATTERN.finditer(text):
            value = match.group(1)
            length = len(value)

            if length == 64:
                results["sha256"].append(value)
            elif length == 40:
                results["sha1"].append(value)
            elif length == 32:
                results["md5"].append(value)

        for ioc_type in ("sha256", "sha1", "md5"):
            results[ioc_type] = list(
                dict.fromkeys(results[ioc_type])
            )

    return results

import re
import os
from typing import Optional


def parse_splunk_webhook(payload: dict) -> Optional[dict]:
    """
    Parse a Splunk alert webhook payload into an alert dict
    the investigation pipeline understands.
    """
    search_name = payload.get("search_name", "Splunk Alert")
    result = payload.get("result", {})
    raw = result.get("_raw", "")
    source = result.get("source", "")
    host = result.get("host", "")

    # Extract IPs from raw event
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
    # Filter out localhost and private boring IPs that are likely infrastructure
    ips = [ip for ip in ips if not ip.startswith("127.") and ip != "0.0.0.0"]

    # Extract usernames
    users = re.findall(r"(?:user|for|by)\s+'?([a-zA-Z0-9_-]+)'?", raw.lower())
    users = [u for u in users if u not in ("root", "the", "a", "an", "invalid", "admin")]

    # Build search terms from what we found
    search_parts = []
    if ips:
        search_parts.append(ips[0])  # most prominent IP
    if users:
        search_parts.append(f'"{users[0]}"')
    if not search_parts and raw:
        # Fall back to first meaningful word sequence from raw
        words = raw.split()[:5]
        search_parts.append(" ".join(words))

    # Determine index from source path
    index = "main"
    if source:
        if "auth" in source.lower():
            index = "main"
        elif "syslog" in source.lower():
            index = "main"

    return {
        "title": search_name,
        "search_terms": " ".join(search_parts) if search_parts else "*",
        "index": index,
        "earliest": "-15m",
        "latest": "now",
        "webhook_source": {
            "sid": payload.get("sid"),
            "host": host,
            "source": source,
            "raw_event": raw[:500],  # truncate for storage
        }
    }
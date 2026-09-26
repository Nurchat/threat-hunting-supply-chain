import json
import re
from datetime import datetime

# Regex patterns for normalization and validation
IPV4_REGEX = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
SHA256_REGEX = r"^[a-fA-F0-9]{64}$"
DOMAIN_REGEX = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

def sanitize_indicator(raw_value: str) -> str:
    """Removes defang brackets and excessive whitespace."""
    cleaned = raw_value.strip().lower()
    cleaned = cleaned.replace("[.]", ".").replace("hxxp", "http")
    return cleaned

def classify_ioc(value: str) -> str:
    """Determines IOC attribute type for MISP mapping."""
    if re.match(SHA256_REGEX, value):
        return "sha256"
    elif re.match(IPV4_REGEX, value):
        return "ip-dst"
    elif re.match(DOMAIN_REGEX, value):
        return "domain"
    return "unknown"

def process_and_normalize(raw_feed: list) -> dict:
    """Filters, deduplicates, and structures IOCs into MISP Event format."""
    print("[*] Processing raw threat feed data...")
    normalized_attributes = []
    seen = set()

    for entry in raw_feed:
        indicator = sanitize_indicator(entry.get("raw_indicator", ""))
        comment = entry.get("context", "Identified in Supply Chain Reconnaissance")
        
        if not indicator or indicator in seen:
            continue
        
        ioc_type = classify_ioc(indicator)
        if ioc_type == "unknown":
            print(f"[!] Warning: Skipping unrecognized or malformed IOC: {indicator}")
            continue

        seen.add(indicator)
        normalized_attributes.append({
            "type": ioc_type,
            "value": indicator,
            "category": "Payload delivery" if ioc_type == "sha256" else "Network activity",
            "to_ids": True,
            "comment": comment
        })

    misp_event = {
        "Event": {
            "info": "Software Supply Chain Compromise: Tampered Packages & C2 Feed",
            "date": datetime.today().strftime('%Y-%m-%d'),
            "threat_level_id": "2",  # Medium/High
            "analysis": "1",        # Ongoing
            "distribution": "1",     # This community only
            "Attribute": normalized_attributes
        }
    }
    return misp_event

if __name__ == "__main__":
    # Simulated un-normalized, messy raw threat feed
    raw_feed_sample = [
        {"raw_indicator": "  83a0429f9e2b1049c5e3d7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0  ", "context": "Poisoned setup.py SHA-256 hash"},
        {"raw_indicator": "83a0429f9e2b1049c5e3d7a8b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0", "context": "Duplicate hash entry"},
        {"raw_indicator": "198.51.100[.]42", "context": "Exfiltration C2 server IP"},
        {"raw_indicator": "malicious-pypi-mirror[.]org", "context": "Typosquatted repository host"},
        {"raw_indicator": "invalid_indicator_value", "context": "Malformed record"}
    ]

    output_event = process_and_normalize(raw_feed_sample)
    output_filename = "normalized_misp_event.json"
    
    with open(output_filename, "w", encoding="utf-8") as f:
        json.dump(output_event, f, indent=4)
        
    print(f"\n[+] Successfully normalized {len(output_event['Event']['Attribute'])} IOCs.")
    print(f"[+] Output ready for MISP ingestion saved to: {output_filename}")

#!/usr/bin/env python3
"""
Threat Feed Simulator
=====================
Generates a fresh dummy_threat_feed.json with randomised IOCs and
optionally POSTs a refresh trigger to the backend API.

Usage:
    python scripts/simulate_threat_feed.py [--output PATH] [--push-url URL]

Options:
    --count      Number of IOCs to generate (default: 30)
    --output     Output JSON path (default: data/dummy_threat_feed.json)
    --push-url   If set, POST /api/threat-intel/refresh after writing file
"""

import argparse
import hashlib
import json
import random
import urllib.request
from datetime import datetime, timedelta
from pathlib import Path

from auth_client import json_headers

THREAT_TYPES  = ["malware","phishing","c2","ransomware","apt","cryptominer","infostealer"]
IOC_TYPES     = ["ip","domain","hash","url","email"]
SEVERITIES    = ["critical","high","medium","low"]
FEED_SOURCES  = ["threat_feed_alpha","threat_feed_beta","misp_feed","isac_feed","threat_feed_gamma"]
TAGS_POOL     = ["apt","c2","botnet","tor","ransomware","phishing","cryptominer",
                 "lateral-movement","exfiltration","supply-chain","zero-day"]

TLD_POOL      = [".ru",".cn",".tk",".xyz",".top",".cc",".pw",".su"]


def random_ip():
    """Generate a non-RFC-1918 IP."""
    while True:
        ip = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
        if not any(ip.startswith(p) for p in ("10.","192.168.","172.","127.")):
            return ip

def random_domain():
    name = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=random.randint(6, 14)))
    return name + random.choice(TLD_POOL)

def random_hash():
    return hashlib.sha256(str(random.random()).encode()).hexdigest()

def random_url():
    domain = random_domain()
    path   = "/" + "/".join(
        "".join(random.choices("abcdefghijklmnop", k=6))
        for _ in range(random.randint(1, 3))
    )
    return f"http://{domain}{path}"

def random_email():
    user   = "".join(random.choices("abcdefghijklmnop", k=6))
    domain = random_domain()
    return f"{user}@{domain}"

GENERATORS = {
    "ip":     random_ip,
    "domain": random_domain,
    "hash":   random_hash,
    "url":    random_url,
    "email":  random_email,
}


def generate_ioc() -> dict:
    ioc_type    = random.choice(IOC_TYPES)
    threat_type = random.choice(THREAT_TYPES)
    severity    = random.choices(SEVERITIES, weights=[10, 30, 40, 20])[0]
    confidence  = round(random.uniform(0.5, 0.99), 2)
    num_tags    = random.randint(1, 3)
    tags        = random.sample(TAGS_POOL, min(num_tags, len(TAGS_POOL)))
    days_ago    = random.randint(0, 90)
    first_seen  = (datetime.utcnow() - timedelta(days=days_ago)).isoformat() + "Z"
    last_seen   = (datetime.utcnow() - timedelta(hours=random.randint(0, 24))).isoformat() + "Z"

    return {
        "ioc_type":    ioc_type,
        "value":       GENERATORS[ioc_type](),
        "threat_type": threat_type,
        "severity":    severity,
        "confidence":  confidence,
        "feed_source": random.choice(FEED_SOURCES),
        "description": f"Simulated {threat_type} indicator of type {ioc_type}",
        "tags":        tags,
        "first_seen":  first_seen,
        "last_seen":   last_seen,
        "is_active":   True,
    }


def main():
    parser = argparse.ArgumentParser(description="Ataraxia threat feed simulator")
    parser.add_argument("--count",    type=int, default=30,
                        help="Number of IOCs to generate")
    parser.add_argument("--output",   default=None,
                        help="Output path (default: data/dummy_threat_feed.json)")
    parser.add_argument("--push-url", default=None,
                        help="Backend URL to trigger feed refresh after writing")
    args = parser.parse_args()

    output_path = Path(args.output) if args.output else (
        Path(__file__).resolve().parent.parent / "data" / "dummy_threat_feed.json"
    )

    # Keep existing static entries, append random ones
    existing = {}
    if output_path.exists():
        with open(output_path) as fh:
            existing = json.load(fh)

    existing_iocs = existing.get("indicators", [])
    new_iocs = [generate_ioc() for _ in range(args.count)]
    all_iocs = existing_iocs + new_iocs

    feed = {
        "feed_name":  "Ataraxia Threat Feed",
        "generated":  datetime.utcnow().isoformat() + "Z",
        "indicators": all_iocs,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump(feed, fh, indent=2)

    print(f"Wrote {len(all_iocs)} indicators ({len(new_iocs)} new) → {output_path}")

    if args.push_url:
        try:
            req = urllib.request.Request(
                f"{args.push_url}/api/threat-intel/refresh",
                method="POST",
                headers=json_headers(args.push_url),
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = json.loads(resp.read())
                print(f"Feed refresh triggered: {result}")
        except Exception as exc:
            print(f"[WARN] Could not push refresh: {exc}")


if __name__ == "__main__":
    main()

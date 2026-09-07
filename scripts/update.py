from __future__ import annotations

import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.yaml"
OUTPUT = ROOT / "output" / "clash.yaml"
STATUS = ROOT / "output" / "source-status.json"
MAX_NODES = int(os.getenv("MAX_NODES", "1000"))
TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))
# Region caps mirror the proxy groups in clash-verge-local.yaml; filters are copied verbatim
REGION_CAP = int(os.getenv("REGION_CAP", "100"))
REGION_FILTERS: list[tuple[str, re.Pattern]] = [
    ("港台", re.compile(r"(?i)港|🇭🇰|香港|HKG|Hong|(?:^|[^a-z])HK(?:[^a-z]|$)|台|🇨🇳|台湾|新北|TPE|TWN|Taiwan|(?:^|[^a-z])TW(?:[^a-z]|$)")),
    ("东南亚", re.compile(r"(?i)坡|🇸🇬|新加坡|狮城|SGP|Singapore|(?:^|[^a-z])SG(?:[^a-z]|$)|菲律|🇵🇭|马尼拉|PHL|Philippine|(?:^|[^a-z])PH(?:[^a-z]|$)|越南|🇻🇳|河内|胡志明|VNM|Vietnam|(?:^|[^a-z])VN(?:[^a-z]|$)|马来|🇲🇾|吉隆坡|MYS|Malaysia|(?:^|[^a-z])MY(?:[^a-z]|$)|泰国|🇹🇭|曼谷|THA|Thailand|(?:^|[^a-z])TH(?:[^a-z]|$)|印尼|印度尼|🇮🇩|雅加达|IDN|Indonesia|(?:^|[^a-z])ID(?:[^a-z]|$)|柬埔寨|🇰🇭|金边|老挝|缅甸|🇲🇲|文莱|🇧🇳")),
    ("日韩", re.compile(r"(?i)🇯🇵|日本|东京|大阪|JPN|Japan|(?:^|[^a-z])JP(?:[^a-z]|$)|韩|🇰🇷|首尔|Korea|KOR|(?:^|[^a-z])KR(?:[^a-z]|$)")),
    ("美加", re.compile(r"(?i)美|🇺🇸|美国|USA|States|American|洛杉矶|圣何塞|西雅图|凤凰城|达拉斯|芝加哥|Los Angeles|San Jose|Seattle|Phoenix|Dallas|Chicago|(?:^|[^a-z])US(?:[^a-z]|$)|加拿大|🇨🇦|枫叶|Canad|蒙特利尔|多伦多|温哥华|Toronto|Montreal|Vancouver|(?:^|[^a-z])CA(?:[^a-z]|$)")),
    ("澳大利亚", re.compile(r"(?i)澳大利亚|澳洲|🇦🇺|AUS|Australia|Aussie|悉尼|Sydney|(?:^|[^a-z])AU(?:[^a-z]|$)")),
    ("法国", re.compile(r"(?i)法|🇫🇷|法国|巴黎|FRA|France|(?:^|[^a-z])FR(?:[^a-z]|$)")),
    ("英国", re.compile(r"(?i)英|🇬🇧|英国|伦敦|GBR|United Kingdom|(?:^|[^a-z])GB(?:[^a-z]|$)|(?:^|[^a-z])UK(?:[^a-z]|$)")),
    ("德国", re.compile(r"(?i)德|🇩🇪|德国|法兰克福|DEU|German|(?:^|[^a-z])DE(?:[^a-z]|$)")),
    ("荷兰", re.compile(r"(?i)荷兰|阿姆斯特丹|🇳🇱|NLD|Netherland|(?:^|[^a-z])NL(?:[^a-z]|$)")),
    ("罗马尼亚", re.compile(r"(?i)罗马尼亚|🇷🇴|ROU|(?:^|[^a-z])RO(?:[^a-z]|$)")),
    ("西班牙", re.compile(r"(?i)西班牙|🇪🇸|马德里|巴塞罗那|Madrid|Barcelona|ESP|Spa(?:in|nish)|(?:^|[^a-z])ES(?:[^a-z]|$)")),
]


def region_of(name: str) -> str:
    return next((region for region, pattern in REGION_FILTERS if pattern.search(name)), "其他")


def fetch(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": "free-vpn-clash-aggregator/1.0"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        body = response.read()
    parsed = yaml.safe_load(body) or {}
    if not isinstance(parsed, dict):
        raise ValueError("top-level YAML value is not a mapping")
    return parsed


def fingerprint(proxy: dict) -> tuple:
    fields = ("type", "server", "port", "uuid", "password", "public-key", "private-key", "token")
    return tuple(str(proxy.get(field, "")) for field in fields)


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    config = yaml.safe_load(SOURCES.read_text(encoding="utf-8"))
    entries = config.get("sources", [])
    collected: list[dict] = []
    status = []
    for source in entries:
        name, url = source["name"], source["url"]
        try:
            document = fetch(url)
            candidates = document.get("proxies", [])
            if not isinstance(candidates, list):
                raise ValueError("proxies is not a list")
            before = len(collected)
            for proxy in candidates:
                if isinstance(proxy, dict) and proxy.get("name") and proxy.get("type"):
                    # if str(proxy["type"]).strip().lower() == "http":
                    #     continue
                    entry = dict(proxy)
                    entry["_source"] = name
                    collected.append(entry)
            status.append({"name": name, "url": url, "ok": True, "received": len(candidates), "added": len(collected) - before})
        except Exception as exc:  # one broken upstream must not block the other sources
            status.append({"name": name, "url": url, "ok": False, "error": str(exc)})

    # Deduplicate by fingerprint, preferring names that contain "|"
    deduped: list[dict] = []
    seen: dict[tuple, int] = {}
    for proxy in collected:
        key = fingerprint(proxy)
        new_name = str(proxy.get("name", "")).strip()[:80]
        if key in seen:
            existing = deduped[seen[key]]
            if "|" in new_name and "|" not in existing["name"]:
                existing["name"] = new_name
            continue
        seen[key] = len(deduped)
        proxy["name"] = new_name
        deduped.append(proxy)

    # Fix duplicate names
    proxies: list[dict] = []
    used_names: set[str] = set()
    for proxy in deduped:
        base_name = proxy["name"]
        candidate_name = base_name
        suffix = 2
        while candidate_name in used_names:
            candidate_name = f"{base_name} #{suffix}"
            suffix += 1
        proxy["name"] = candidate_name
        used_names.add(candidate_name)
        proxies.append(proxy)

    if not proxies:
        raise RuntimeError("all upstream sources failed, or every node failed the availability check")

    # Keep at most REGION_CAP nodes per region (mirrors clash-verge-local.yaml groups),
    # then cap the total at MAX_NODES; uncategorized nodes ("其他") have no region cap.
    with_pipe = [p for p in proxies if "|" in p["name"]]
    without_pipe = [p for p in proxies if "|" not in p["name"]]
    region_counts: dict[str, int] = {}
    selected: list[dict] = []
    for proxy in with_pipe + without_pipe:
        region = region_of(proxy["name"])
        if region != "其他" and region_counts.get(region, 0) >= REGION_CAP:
            continue
        region_counts[region] = region_counts.get(region, 0) + 1
        selected.append(proxy)
        if len(selected) >= MAX_NODES:
            break
    proxies = selected
    region_stats = {name: region_counts.get(name, 0) for name, _ in REGION_FILTERS}
    region_stats["其他"] = region_counts.get("其他", 0)
    for proxy in proxies:
        proxy.pop("_source", None)
    names = [proxy["name"] for proxy in proxies]
    generated = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": names},
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", "DIRECT"] + names},
        ],
        "rules": ["MATCH,PROXY"],
    }
    OUTPUT.write_text("# Generated by scripts/update.py; do not edit.\n" + yaml.safe_dump(generated, allow_unicode=True, sort_keys=False), encoding="utf-8")
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "proxy_count": len(proxies),
        "checked": len(deduped),
        "regions": region_stats,
        "sources": status,
    }
    STATUS.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

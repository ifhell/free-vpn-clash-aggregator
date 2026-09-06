from __future__ import annotations

import json
import os
import socket
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.yaml"
OUTPUT = ROOT / "output" / "clash.yaml"
STATUS = ROOT / "output" / "source-status.json"
UNAVAILABLE = ROOT / "output" / "unavailable-sources.json"
MAX_NODES = int(os.getenv("MAX_NODES", "1000"))
TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))
CHECK_TIMEOUT = int(os.getenv("CHECK_TIMEOUT", "5"))
CHECK_WORKERS = int(os.getenv("CHECK_WORKERS", "100"))


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


def check_proxy(proxy: dict) -> tuple[bool, str]:
    # TCP-level reachability only: proves the port is open, not a full protocol handshake
    server = str(proxy.get("server", "")).strip()
    try:
        port = int(proxy.get("port", 0))
    except (TypeError, ValueError):
        return False, f"invalid port: {proxy.get('port')!r}"
    if not server or not 0 < port < 65536:
        return False, f"invalid server/port: {server!r}:{port!r}"
    try:
        with socket.create_connection((server, port), timeout=CHECK_TIMEOUT):
            return True, ""
    except OSError as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


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
                    if str(proxy["type"]).strip().lower() == "http":
                        continue
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

    # Probe node availability concurrently and drop dead ones
    results: dict[int, tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=CHECK_WORKERS) as pool:
        futures = {pool.submit(check_proxy, proxy): index for index, proxy in enumerate(deduped)}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    available: list[dict] = []
    unavailable_records: list[dict] = []
    for index, proxy in enumerate(deduped):
        ok, reason = results[index]
        if ok:
            available.append(proxy)
            continue
        unavailable_records.append({
            "name": proxy.get("name", ""),
            "type": proxy.get("type", ""),
            "server": proxy.get("server", ""),
            "port": proxy.get("port", ""),
            "source": proxy.get("_source", ""),
            "reason": reason,
        })
    UNAVAILABLE.write_text(json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "checked": len(deduped),
        "available": len(available),
        "unavailable": len(unavailable_records),
        "nodes": unavailable_records,
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # Roll per-source unavailable counts into the fetch status
    dead_by_source: dict[str, int] = {}
    for record in unavailable_records:
        dead_by_source[record["source"]] = dead_by_source.get(record["source"], 0) + 1
    for entry in status:
        entry["unavailable"] = dead_by_source.get(entry["name"], 0)

    # Fix duplicate names
    proxies: list[dict] = []
    used_names: set[str] = set()
    for proxy in available:
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

    if len(proxies) > MAX_NODES:
        with_pipe = [p for p in proxies if "|" in p["name"]]
        without_pipe = [p for p in proxies if "|" not in p["name"]]
        proxies = (with_pipe + without_pipe)[:MAX_NODES]
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
        "unavailable_count": len(unavailable_records),
        "sources": status,
    }
    STATUS.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

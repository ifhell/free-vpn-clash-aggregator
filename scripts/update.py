from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources.yaml"
OUTPUT = ROOT / "output" / "clash.yaml"
BEST = ROOT / "output" / "best.yaml"
STATUS = ROOT / "output" / "source-status.json"
MAX_NODES = int(os.getenv("MAX_NODES", "1000"))
TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))
# Region caps mirror the proxy groups in clash-verge-local.yaml; filters are copied verbatim
REGION_CAP = int(os.getenv("REGION_CAP", "100"))
MIHOMO_TAG = os.getenv("MIHOMO_TAG", "v1.19.30")
MIHOMO_MIRROR = os.getenv(
    "MIHOMO_MIRROR",
    "https://github.com/MetaCubeX/mihomo/releases/download",
)
TEST_TARGETS = [t.strip() for t in os.getenv("TEST_TARGETS", "https://www.github.com,https://www.google.com,https://www.youtube.com").split(",") if t.strip()]
MIXED_PORT = int(os.getenv("MIXED_PORT", "7891"))
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "9090"))
TEST_TIMEOUT = int(os.getenv("TEST_TIMEOUT", "15"))
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
    result = subprocess.run(
        ["curl.exe", "-sS", "-L", "--connect-timeout", "10", "--max-time", str(TIMEOUT), url],
        capture_output=True, timeout=TIMEOUT + 10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"curl failed: {result.stderr.decode(errors='replace').strip()}")
    body = result.stdout
    parsed = yaml.safe_load(body) or {}
    if not isinstance(parsed, dict):
        raise ValueError("top-level YAML value is not a mapping")
    return parsed


def fingerprint(proxy: dict) -> tuple:
    fields = ("type", "server", "port", "uuid", "password", "public-key", "private-key", "token")
    return tuple(str(proxy.get(field, "")) for field in fields)


def mihomo_binary() -> Path | None:
    sysname = platform.system().lower()
    machine = platform.machine().lower()
    if sysname == "windows":
        os_name, ext = "windows", "zip"
    elif sysname == "linux":
        os_name, ext = "linux", "gz"
    elif sysname == "darwin":
        os_name, ext = "darwin", "gz"
    else:
        return None
    if machine in ("amd64", "x86_64"):
        arch = "amd64"
    elif machine in ("arm64", "aarch64"):
        arch = "arm64"
    else:
        return None
    if os_name == "windows" and arch == "arm64":
        # mihomo windows releases only ship amd64
        arch = "amd64"
    if os_name == "windows":
        # windows archives use a -compatible suffix on amd64 when available
        asset_base = f"mihomo-{os_name}-{arch}"
    else:
        asset_base = f"mihomo-{os_name}-{arch}"
    # The release assets embed the tag in the filename, e.g. mihomo-windows-amd64-v1.19.30.zip
    asset = f"{asset_base}-{MIHOMO_TAG}"
    tmpdir = ROOT / ".tmp" / f"mihomo-{MIHOMO_TAG}-{os_name}-{arch}"
    tmpdir.mkdir(parents=True, exist_ok=True)
    binary = tmpdir / ("mihomo.exe" if os_name == "windows" else "mihomo")
    if binary.exists():
        return binary
    url = f"{MIHOMO_MIRROR}/{MIHOMO_TAG}/{asset}.{ext}"
    archive = tmpdir / f"{asset}.{ext}"
    result = subprocess.run(
        ["curl.exe", "-sS", "-L", "--connect-timeout", "10", "--max-time", "120", "-o", str(archive), url],
        capture_output=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"failed to download mihomo: {result.stderr.decode(errors='replace').strip()}")
    if ext == "zip":
        with zipfile.ZipFile(archive) as zf:
            member = next(n for n in zf.namelist() if n.endswith(".exe") or n.endswith("mihomo"))
            zf.extract(member, tmpdir)
        extracted = tmpdir / Path(member).name
        shutil.move(str(extracted), str(binary))
    else:
        import gzip

        with gzip.open(archive, "rb") as src, open(binary, "wb") as dst:
            shutil.copyfileobj(src, dst)
        binary.chmod(0o755)
    return binary


def make_mihomo_config(proxies: list[dict], names: list[str]) -> dict:
    return {
        "mixed-port": MIXED_PORT,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "error",
        "external-controller": f"127.0.0.1:{CONTROLLER_PORT}",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "PROXY", "type": "select", "proxies": names},
        ],
        "rules": ["MATCH,PROXY"],
    }


def test_proxy(proxy: dict) -> bool:
    base = f"http://127.0.0.1:{CONTROLLER_PORT}"
    name = proxy["name"]
    req = urllib.request.Request(f"{base}/proxies/PROXY", data=json.dumps({"name": name}).encode(), method="PUT", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TEST_TIMEOUT) as resp:
            if resp.status not in (200, 204):
                return False
    except Exception:
        return False
    proxy_url = f"http://127.0.0.1:{MIXED_PORT}"
    for target in TEST_TARGETS:
        result = subprocess.run(
            ["curl.exe", "-sS", "-o", "NUL", "-w", "%{http_code}", "--proxy", proxy_url, "--connect-timeout", "8", "--max-time", str(TEST_TIMEOUT), target],
            capture_output=True,
        )
        if result.returncode != 0:
            return False
        try:
            code = int(result.stdout.decode(errors="replace").strip())
        except ValueError:
            return False
        if code >= 400:
            return False
    return True


def run_tests(proxies: list[dict], binary: Path) -> list[dict]:
    names = [p["name"] for p in proxies]
    config = make_mihomo_config(proxies, names)
    cfg_path = ROOT / ".tmp" / "mihomo-runtime.yaml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    proc = subprocess.Popen([str(binary), "-f", str(cfg_path), "-d", str(cfg_path.parent)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    passed: list[dict] = []
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{CONTROLLER_PORT}/version", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("mihomo did not start in time")
        # Run sequentially: the PROXY group is shared, so concurrent testers would
        # race to select a node and route their curl through a different proxy.
        for proxy in proxies:
            if test_proxy(proxy):
                passed.append(proxy)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    return passed


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    print("DEBUG: main start", flush=True)
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
            print(f"DEBUG: source ok {name} ({len(candidates)})", flush=True)
        except Exception as exc:  # one broken upstream must not block the other sources
            status.append({"name": name, "url": url, "ok": False, "error": str(exc)})
            print(f"DEBUG: source fail {name}: {exc}", flush=True)
    print("DEBUG: sources done, collected =", len(collected), flush=True)

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

    for proxy in proxies:
        proxy.pop("_source", None)

    # --- Step 1: clash.yaml contains the full aggregated set, no caps ---
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

    # --- Step 2: connectivity test through a local mihomo instance ---
    binary = mihomo_binary()
    print("DEBUG: mihomo binary =", binary, flush=True)
    test_status = {"tested": 0, "passed": 0}
    passing: list[dict] = []
    if binary is not None and proxies:
        print("DEBUG: starting tests on", len(proxies), "proxies", flush=True)
        passing = run_tests(proxies, binary)
        test_status["tested"] = len(proxies)
        test_status["passed"] = len(passing)
        print("DEBUG: tests done, passed =", len(passing), flush=True)

    # --- Step 3: merge passing nodes with existing best.yaml hit counts, sort, cap ---
    best_proxies: list[dict] = []
    if BEST.exists():
        try:
            existing_best = yaml.safe_load(BEST.read_text(encoding="utf-8")) or {}
            best_proxies = existing_best.get("proxies", [])
        except Exception:
            best_proxies = []

    hit_counts: dict[tuple, int] = {}
    for bp in best_proxies:
        if isinstance(bp, dict):
            key = fingerprint(bp)
            hit_counts[key] = int(bp.get("hit_count", 0))

    for proxy in passing:
        key = fingerprint(proxy)
        hit_counts[key] = hit_counts.get(key, 0) + 1

    ranked = sorted(passing, key=lambda p: hit_counts[fingerprint(p)], reverse=True)

    region_counts: dict[str, int] = {}
    selected: list[dict] = []
    for proxy in ranked:
        region = region_of(proxy["name"])
        if region != "其他" and region_counts.get(region, 0) >= REGION_CAP:
            continue
        region_counts[region] = region_counts.get(region, 0) + 1
        selected.append(proxy)
        if len(selected) >= MAX_NODES:
            break

    region_stats = {name: region_counts.get(name, 0) for name, _ in REGION_FILTERS}
    region_stats["其他"] = region_counts.get("其他", 0)
    for proxy in selected:
        proxy["hit_count"] = hit_counts[fingerprint(proxy)]

    best_names = [proxy["name"] for proxy in selected]
    best_config = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": selected,
        "proxy-groups": [
            {"name": "AUTO", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "tolerance": 50, "proxies": best_names},
            {"name": "PROXY", "type": "select", "proxies": ["AUTO", "DIRECT"] + best_names},
        ],
        "rules": ["MATCH,PROXY"],
    }
    BEST.write_text("# Generated by scripts/update.py; do not edit.\n" + yaml.safe_dump(best_config, allow_unicode=True, sort_keys=False), encoding="utf-8")

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "clash_count": len(proxies),
        "checked": len(deduped),
        "regions": region_stats,
        "test": test_status,
        "best_count": len(selected),
        "sources": status,
    }
    STATUS.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())

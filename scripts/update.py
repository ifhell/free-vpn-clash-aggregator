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
ERROR_PROXIES = ROOT / "output" / "error-proxies.json"
# Keep failed-proxy records at most this many days; older ones are purged on load.
ERROR_MAX_AGE_DAYS = int(os.getenv("ERROR_MAX_AGE_DAYS", "7"))
# Only hard/network failures get blacklisted. Ambiguous failures (unknown/auth/
# http/controller) are NOT cached, so potentially-working nodes are retested each
# run instead of being skipped forever.
ERROR_HARD_REASONS = frozenset({"dns", "connect", "timeout"})
# Field order used to fingerprint a proxy; kept stable for the error-proxies cache.
FINGERPRINT_FIELDS = ("type", "server", "port", "uuid", "password", "public-key", "private-key", "token")
# curl executable and null-device path differ between Windows and POSIX runners
CURL = "curl.exe" if platform.system().lower() == "windows" else "curl"
NULL_DEV = "NUL" if platform.system().lower() == "windows" else "/dev/null"
MAX_NODES = int(os.getenv("MAX_NODES", "1000"))
TIMEOUT = int(os.getenv("FETCH_TIMEOUT", "20"))
# Region caps mirror the proxy groups in clash-verge-local.yaml; filters are copied verbatim
REGION_CAP = int(os.getenv("REGION_CAP", "100"))
MIHOMO_TAG = os.getenv("MIHOMO_TAG", "v1.19.30")
MIHOMO_MIRROR = os.getenv(
    "MIHOMO_MIRROR",
    "https://github.com/MetaCubeX/mihomo/releases/download",
)
TEST_TARGETS = [t.strip() for t in os.getenv("TEST_TARGETS", "https://www.google.com,https://www.youtube.com").split(",") if t.strip()]
MIXED_PORT = int(os.getenv("MIXED_PORT", "7891"))
CONTROLLER_PORT = int(os.getenv("CONTROLLER_PORT", "9090"))
TEST_TIMEOUT = int(os.getenv("TEST_TIMEOUT", "10"))
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
        [CURL, "-sS", "-L", "--connect-timeout", "10", "--max-time", str(TIMEOUT), url],
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
    return tuple(str(proxy.get(field, "")) for field in FINGERPRINT_FIELDS)


def fingerprint_to_dict(key: tuple) -> dict:
    return {field: value for field, value in zip(FINGERPRINT_FIELDS, key)}


# curl exit codes / stderr hints that map to a stable failure category
def classify_curl_failure(returncode: int, stderr: str) -> str:
    if returncode == 6 or "could not resolve host" in stderr or "couldn't resolve" in stderr:
        return "dns"
    if returncode in (7, 55, 56) or "failed to connect" in stderr or "connection refused" in stderr:
        return "connect"
    if returncode == 28 or "operation timed out" in stderr or "timed out" in stderr:
        return "timeout"
    if "407" in stderr or "proxy authentication required" in stderr or returncode == 67:
        return "auth"
    return "unknown"


def load_error_proxies() -> dict[tuple, dict]:
    """Load the failed-proxy cache, purging entries older than ERROR_MAX_AGE_DAYS.

    Only hard/network failures (dns/connect/timeout) are ever cached, so entries
    here are deterministic blacklists; soft failures are retested each run.
    """
    cache: dict[tuple, dict] = {}
    if not ERROR_PROXIES.exists():
        return cache
    try:
        raw = json.loads(ERROR_PROXIES.read_text(encoding="utf-8"))
        records = raw if isinstance(raw, list) else raw.get("records", [])
    except Exception:
        return cache
    now = datetime.now(timezone.utc)
    for rec in records:
        try:
            at = datetime.fromisoformat(rec["at"])
            if at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            reason = rec.get("reason", "unknown")
            if reason not in ERROR_HARD_REASONS:
                continue  # soft failure was cached by an older version; retest it
            if (now - at).days > ERROR_MAX_AGE_DAYS:
                continue  # stale record
            fields = rec.get("fingerprint", {})
            key = tuple(str(fields.get(f, "")) for f in FINGERPRINT_FIELDS)
            if not any(key):  # all-empty fingerprint is unusable
                continue
            cache[key] = {"reason": reason, "at": rec["at"]}
        except Exception:
            continue
    return cache


def save_error_proxies(cache: dict[tuple, dict]) -> None:
    records = [
        {"fingerprint": fingerprint_to_dict(key), "reason": info["reason"], "at": info["at"]}
        for key, info in cache.items()
    ]
    payload = {"records": records}
    ERROR_PROXIES.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


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
        [CURL, "-sS", "-L", "--connect-timeout", "10", "--max-time", "120", "-o", str(archive), url],
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


def make_mihomo_config(proxies: list[dict]) -> dict:
    names = [p["name"] for p in proxies]
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


def test_proxy(proxy: dict) -> str | None:
    """Test connectivity to TEST_TARGETS. Return None only if every target is
    reachable (HTTP < 400); otherwise a failure category (from the first failing
    target)."""
    base = f"http://127.0.0.1:{CONTROLLER_PORT}"
    name = proxy["name"]
    req = urllib.request.Request(f"{base}/proxies/PROXY", data=json.dumps({"name": name}).encode(), method="PUT", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TEST_TIMEOUT) as resp:
            if resp.status not in (200, 204):
                return "controller"
    except Exception:
        return "controller"
    proxy_url = f"http://127.0.0.1:{MIXED_PORT}"
    first_failure: str | None = None
    for target in TEST_TARGETS:
        result = subprocess.run(
            [CURL, "-sS", "-o", NULL_DEV, "-w", "%{http_code}", "--proxy", proxy_url, "--connect-timeout", "5", "--max-time", str(TEST_TIMEOUT), target],
            capture_output=True,
        )
        stderr = result.stderr.decode(errors="replace")
        # Prefer the parsed HTTP status: a 2xx/3xx body is a reachable target even
        # when curl exits non-zero (e.g. Windows schannel "missing close_notify"
        # warnings are benign but set returncode != 0). Only fall back to classifying
        # the exit code when no usable HTTP status came back.
        code: int | None = None
        try:
            code = int(result.stdout.decode(errors="replace").strip())
        except ValueError:
            code = None
        if code is not None and code < 400:
            continue  # this target reached us -> passes
        if first_failure is not None:
            continue  # already failed; keep the first category
        if code is not None:
            first_failure = "http"
        else:
            first_failure = classify_curl_failure(result.returncode, stderr)
    return first_failure


def run_tests(proxies: list[dict], binary: Path) -> tuple[list[dict], dict]:
    """Test proxies through a local mihomo instance, honoring and updating the error-proxy cache.

    Returns (passed, error_stats) where error_stats counts tests by outcome:
    {tested, skipped, passed, dns, connect, timeout, auth, http, controller, unknown}.
    """
    config = make_mihomo_config(proxies)
    cfg_path = ROOT / ".tmp" / "mihomo-runtime.yaml"
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")
    proc = subprocess.Popen([str(binary), "-f", str(cfg_path), "-d", str(cfg_path.parent)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cache = load_error_proxies()
    stats = {"tested": 0, "skipped": 0, "passed": 0, "dns": 0, "connect": 0, "timeout": 0, "auth": 0, "http": 0, "controller": 0, "unknown": 0}
    passed: list[dict] = []
    now = datetime.now(timezone.utc)
    try:
        for _ in range(60):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{CONTROLLER_PORT}/version", timeout=1)
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("mihomo did not start in time")
        # Sequential is required: the single mixed-port routes every request through
        # the one shared PROXY group, so concurrent testers would race on it and
        # each route their curl through a peer's proxy.
        for proxy in proxies:
            key = fingerprint(proxy)
            if key in cache:
                stats["skipped"] += 1
                continue
            stats["tested"] += 1
            reason = test_proxy(proxy)
            if reason is None:
                stats["passed"] += 1
                passed.append(proxy)
                continue
            stats[reason] = stats.get(reason, 0) + 1
            # Only hard/network failures (dns/connect/timeout) are cached as blacklist.
            # Soft/ambiguous failures (unknown/auth/http/controller) are unreliable and
            # may be working nodes, so do NOT cache them -> they get retested next run.
            if reason in ERROR_HARD_REASONS:
                cache[key] = {"reason": reason, "at": now.isoformat()}
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    save_error_proxies(cache)
    return passed, stats


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
    test_status = {"tested": 0, "skipped": 0, "passed": 0, "dns": 0, "connect": 0, "timeout": 0, "auth": 0, "http": 0, "controller": 0, "unknown": 0}
    passing: list[dict] = []
    if binary is not None and proxies:
        print("DEBUG: starting tests on", len(proxies), "proxies", flush=True)
        passing, test_stats = run_tests(proxies, binary)
        test_status = test_stats
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

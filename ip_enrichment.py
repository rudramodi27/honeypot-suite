"""
ip_enrichment.py — Attacker IP Intelligence
Enriches every attacker IP with:
  - Country, City, Region
  - ISP / Organization / ASN
  - Threat reputation (known malicious, TOR, VPN, datacenter)
  - Abuse confidence score

Uses FREE APIs (no API key needed for basic):
  1. ip-api.com       — geo + ISP (free, 45 req/min)
  2. ipapi.co         — fallback geo
  3. Offline cache    — never re-fetches same IP

Results cached to: cache/ip_cache.json
"""

import json, os, time, socket, threading, urllib.request, urllib.error
from datetime import datetime
from collections import defaultdict

os.makedirs("cache", exist_ok=True)
CACHE_FILE = "cache/ip_cache.json"

# ── Load / Save cache ─────────────────────────────────────────────────────────
_cache: dict = {}
_cache_lock  = threading.Lock()

def _load_cache():
    global _cache
    try:
        with open(CACHE_FILE) as f:
            _cache = json.load(f)
    except Exception:
        _cache = {}

def _save_cache():
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(_cache, f, indent=2)
    except Exception:
        pass

_load_cache()

# ── Known threat IPs / ranges (offline mini-database) ────────────────────────
# Tor exit nodes, known scanners, botnets — updated list
KNOWN_THREATS = {
    # Shodan scanning IPs
    "198.20.69.74":  {"type": "scanner",   "label": "Shodan"},
    "198.20.70.114": {"type": "scanner",   "label": "Shodan"},
    "198.20.99.130": {"type": "scanner",   "label": "Shodan"},
    "198.20.99.132": {"type": "scanner",   "label": "Shodan"},
    # Censys
    "162.142.125.0": {"type": "scanner",   "label": "Censys"},
    "167.94.138.0":  {"type": "scanner",   "label": "Censys"},
    # Common Tor-exit ranges (prefix check)
}

KNOWN_PREFIXES = {
    "185.220": {"type": "tor_exit",    "label": "Tor Exit Node"},
    "185.130": {"type": "tor_exit",    "label": "Tor Exit Node"},
    "199.249": {"type": "tor_exit",    "label": "Tor Exit Node"},
    "162.247": {"type": "tor_exit",    "label": "Tor Exit Node"},
    "23.129":  {"type": "tor_exit",    "label": "Tor Exit Node"},
    "45.142":  {"type": "botnet",      "label": "Known Botnet Range"},
    "91.92":   {"type": "scanner",     "label": "Mass Scanner"},
    "193.32":  {"type": "scanner",     "label": "Stretchoid Scanner"},
}

DATACENTER_ASNS = {
    "AS14061": "DigitalOcean",
    "AS16276": "OVH",
    "AS24940": "Hetzner",
    "AS20473": "Vultr",
    "AS8075":  "Microsoft Azure",
    "AS16509": "Amazon AWS",
    "AS15169": "Google Cloud",
    "AS13335": "Cloudflare",
    "AS9009":  "M247 (VPN/Proxy)",
    "AS208091": "Privado VPN",
}

# ── Private IP check ──────────────────────────────────────────────────────────
def _is_private(ip: str) -> bool:
    priv = ("10.", "192.168.", "127.", "172.16.", "172.17.",
            "172.18.", "172.19.", "172.20.", "0.", "::1", "localhost")
    return any(ip.startswith(p) for p in priv)


# ── Threat classification ─────────────────────────────────────────────────────
def _classify_threat(ip: str, data: dict) -> dict:
    threat = {"is_threat": False, "type": "unknown", "label": "", "score": 0}

    # Check known exact IPs
    if ip in KNOWN_THREATS:
        t = KNOWN_THREATS[ip]
        threat.update({"is_threat": True, "score": 90,
                        "type": t["type"], "label": t["label"]})
        return threat

    # Check prefix ranges
    prefix2 = ".".join(ip.split(".")[:2])
    if prefix2 in KNOWN_PREFIXES:
        t = KNOWN_PREFIXES[prefix2]
        threat.update({"is_threat": True, "score": 80,
                        "type": t["type"], "label": t["label"]})
        return threat

    # Check datacenter ASN
    asn = data.get("asn", "")
    if asn in DATACENTER_ASNS:
        threat.update({"is_threat": False, "score": 40,
                        "type": "datacenter",
                        "label": f"Datacenter: {DATACENTER_ASNS[asn]}"})

    # Heuristic: hosting org keywords
    org = (data.get("org", "") + data.get("isp", "")).lower()
    vps_keywords = ["digitalocean", "linode", "vultr", "ovh", "hetzner",
                    "amazon", "google cloud", "azure", "hosting", "datacenter",
                    "vps", "server", "cloud"]
    if any(k in org for k in vps_keywords):
        if threat["score"] < 40:
            threat.update({"score": 35, "type": "datacenter",
                            "label": "VPS/Cloud Provider"})

    return threat


# ── API fetch ─────────────────────────────────────────────────────────────────
def _fetch_ip_api(ip: str) -> dict | None:
    """ip-api.com — free, no key, 45 req/min"""
    try:
        url = (f"http://ip-api.com/json/{ip}"
               f"?fields=status,country,countryCode,region,regionName,"
               f"city,zip,lat,lon,timezone,isp,org,as,asname,mobile,proxy,hosting,query")
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        if data.get("status") == "success":
            return {
                "ip":          ip,
                "country":     data.get("country", ""),
                "country_code":data.get("countryCode", ""),
                "region":      data.get("regionName", ""),
                "city":        data.get("city", ""),
                "lat":         data.get("lat", 0),
                "lon":         data.get("lon", 0),
                "timezone":    data.get("timezone", ""),
                "isp":         data.get("isp", ""),
                "org":         data.get("org", ""),
                "asn":         data.get("as", "").split()[0] if data.get("as") else "",
                "asn_name":    data.get("asname", ""),
                "is_mobile":   data.get("mobile", False),
                "is_proxy":    data.get("proxy", False),
                "is_hosting":  data.get("hosting", False),
                "source":      "ip-api.com",
                "fetched_at":  datetime.now().isoformat(),
            }
    except Exception:
        pass
    return None


def _fetch_ipapi_co(ip: str) -> dict | None:
    """ipapi.co fallback"""
    try:
        url = f"https://ipapi.co/{ip}/json/"
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "Mozilla/5.0")
        with urllib.request.urlopen(req, timeout=5) as r:
            data = json.loads(r.read())
        if "error" not in data:
            return {
                "ip":           ip,
                "country":      data.get("country_name", ""),
                "country_code": data.get("country_code", ""),
                "region":       data.get("region", ""),
                "city":         data.get("city", ""),
                "lat":          data.get("latitude", 0),
                "lon":          data.get("longitude", 0),
                "timezone":     data.get("timezone", ""),
                "isp":          data.get("org", ""),
                "org":          data.get("org", ""),
                "asn":          data.get("asn", ""),
                "asn_name":     data.get("org", ""),
                "is_mobile":    False,
                "is_proxy":     False,
                "is_hosting":   False,
                "source":       "ipapi.co",
                "fetched_at":   datetime.now().isoformat(),
            }
    except Exception:
        pass
    return None


# ── Hostname reverse lookup ───────────────────────────────────────────────────
def _rdns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


# ── Main enrichment function ──────────────────────────────────────────────────
def enrich(ip: str, force_refresh: bool = False) -> dict:
    """
    Returns enriched IP data dict. Uses cache, falls back to APIs.
    Never fails — returns minimal data on error.
    """
    if _is_private(ip):
        return {
            "ip": ip, "country": "Local/Private", "country_code": "LO",
            "city": "Local Network", "isp": "Private",
            "is_threat": False, "threat_type": "none",
            "threat_label": "", "threat_score": 0,
            "rdns": "localhost",
        }

    with _cache_lock:
        if not force_refresh and ip in _cache:
            cached = _cache[ip]
            # Re-check threat in case database updated
            threat = _classify_threat(ip, cached)
            cached.update({
                "is_threat":    threat["is_threat"],
                "threat_type":  threat["type"],
                "threat_label": threat["label"],
                "threat_score": threat["score"],
            })
            return cached

    # Fetch from API
    data = _fetch_ip_api(ip) or _fetch_ipapi_co(ip)

    if not data:
        # Offline fallback — basic geo from attack_map ranges
        from attack_map import ip_to_latlon
        lat, lon, country = ip_to_latlon(ip)
        data = {
            "ip": ip, "country": country, "country_code": "??",
            "city": "", "region": "", "isp": "Unknown",
            "org": "", "asn": "", "asn_name": "",
            "lat": lat, "lon": lon,
            "is_mobile": False, "is_proxy": False, "is_hosting": False,
            "source": "offline_fallback",
            "fetched_at": datetime.now().isoformat(),
        }

    # Add threat classification
    threat = _classify_threat(ip, data)
    data.update({
        "is_threat":    threat["is_threat"],
        "threat_type":  threat["type"],
        "threat_label": threat["label"],
        "threat_score": threat["score"],
    })

    # Add reverse DNS
    data["rdns"] = _rdns(ip)

    # Save to cache
    with _cache_lock:
        _cache[ip] = data
        _save_cache()

    return data


def enrich_async(ip: str, callback=None):
    """Non-blocking enrichment. Calls callback(ip, data) when done."""
    def _run():
        data = enrich(ip)
        if callback:
            try:
                callback(ip, data)
            except Exception:
                pass
    threading.Thread(target=_run, daemon=True).start()


# ── Batch enrichment ──────────────────────────────────────────────────────────
def enrich_all_logs(log_path: str = "logs/honeypot_master.log") -> dict:
    """Enrich all unique IPs found in logs. Returns {ip: data}."""
    ips = set()
    try:
        with open(log_path) as f:
            for line in f:
                try:
                    e = json.loads(line.strip())
                    ip = e.get("ip", "")
                    if ip and not _is_private(ip):
                        ips.add(ip)
                except Exception:
                    pass
    except FileNotFoundError:
        pass

    results = {}
    for ip in ips:
        results[ip] = enrich(ip)
        time.sleep(0.1)   # Rate limit: 10 req/sec max

    return results


# ── Summary stats ─────────────────────────────────────────────────────────────
def get_threat_summary() -> dict:
    with _cache_lock:
        cache_copy = dict(_cache)

    threats    = [v for v in cache_copy.values() if v.get("is_threat")]
    tor_exits  = [v for v in threats if v.get("threat_type") == "tor_exit"]
    scanners   = [v for v in threats if v.get("threat_type") == "scanner"]
    datacenters= [v for v in cache_copy.values()
                  if v.get("threat_type") == "datacenter"]
    countries  = defaultdict(int)
    for v in cache_copy.values():
        c = v.get("country", "Unknown")
        countries[c] += 1

    return {
        "total_ips":     len(cache_copy),
        "threats":       len(threats),
        "tor_exits":     len(tor_exits),
        "scanners":      len(scanners),
        "datacenters":   len(datacenters),
        "top_countries": sorted(countries.items(),
                                key=lambda x: x[1], reverse=True)[:10],
    }


if __name__ == "__main__":
    # CLI test
    import sys
    ip = sys.argv[1] if len(sys.argv) > 1 else "185.220.101.5"
    print(f"\nEnriching {ip}...")
    data = enrich(ip)
    print(json.dumps(data, indent=2))
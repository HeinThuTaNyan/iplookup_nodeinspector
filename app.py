import ipaddress
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, wait
from flask import Flask, abort, jsonify, request, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import requests
from requests.adapters import HTTPAdapter

load_dotenv()

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, static_folder=None)

CORS(
    app,
    resources={
        r"/api/*": {
            "origins": [
                "http://127.0.0.1:5000",
                "http://localhost:5000",
                "http://127.0.0.1:5500",
                "http://localhost:5500",
                r"^https://.*\.vercel\.app$"
            ]
        }
    }
)

ALLOWED_STATIC_FILES = {"style.css", "script.js"}
API_TIMEOUT = (1.5, 2.2)

INTEL_CACHE = {}
CACHE_LOCK = threading.Lock()
CACHE_TTL_SECONDS = 120
MAX_CACHE_SIZE = 500

RATE_LIMIT_STORE = {}
RATE_LIMIT_LOCK = threading.Lock()
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 30

_thread_local = threading.local()
EXECUTOR = ThreadPoolExecutor(max_workers=10)


def get_http_session():
    if not hasattr(_thread_local, "session"):
        session = requests.Session()
        adapter = HTTPAdapter(pool_connections=10, pool_maxsize=10, max_retries=0)
        session.mount("https://", adapter)
        session.mount("http://", adapter)
        session.headers.update({
            "User-Agent": "NetworkNodeInspector/4.5.2 (+https://github.com/h7n)"
        })
        _thread_local.session = session
    return _thread_local.session


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://va.vercel-scripts.com; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' https: http://127.0.0.1:5000 http://localhost:5000; "
        "frame-src https://www.google.com https://maps.google.com; "
        "img-src 'self' data: https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    return response


def get_client_ip():
    vercel_ip = request.headers.get("X-Vercel-Forwarded-For", "").strip()
    if vercel_ip:
        return vercel_ip.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP", "").strip()
    if real_ip:
        return real_ip

    forwarded_for = request.headers.get("X-Forwarded-For", "").strip()
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return (request.remote_addr or "127.0.0.1").strip()


def is_rate_limited(client_ip):
    now = time.time()
    with RATE_LIMIT_LOCK:
        if len(RATE_LIMIT_STORE) > 1000:
            cutoff = now - RATE_LIMIT_WINDOW
            stale_keys = [k for k, v in RATE_LIMIT_STORE.items() if not v or v[-1] < cutoff]
            for k in stale_keys:
                RATE_LIMIT_STORE.pop(k, None)

        timestamps = RATE_LIMIT_STORE.get(client_ip, [])
        cutoff = now - RATE_LIMIT_WINDOW
        timestamps = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
            RATE_LIMIT_STORE[client_ip] = timestamps
            return True

        timestamps.append(now)
        RATE_LIMIT_STORE[client_ip] = timestamps
        return False


def get_cached_intel(ip_key):
    now = time.time()
    with CACHE_LOCK:
        entry = INTEL_CACHE.get(ip_key)
        if not entry:
            return None
        if now - entry["timestamp"] > CACHE_TTL_SECONDS:
            INTEL_CACHE.pop(ip_key, None)
            return None
        return entry["data"]


def set_cached_intel(ip_key, data):
    now = time.time()
    with CACHE_LOCK:
        if len(INTEL_CACHE) >= MAX_CACHE_SIZE:
            expired = [k for k, v in INTEL_CACHE.items() if now - v["timestamp"] > CACHE_TTL_SECONDS]
            for k in expired:
                INTEL_CACHE.pop(k, None)
            if len(INTEL_CACHE) >= MAX_CACHE_SIZE:
                oldest_key = min(INTEL_CACHE.keys(), key=lambda k: INTEL_CACHE[k]["timestamp"])
                INTEL_CACHE.pop(oldest_key, None)

        INTEL_CACHE[ip_key] = {"timestamp": now, "data": data}


def validate_public_ip(raw_ip):
    if not raw_ip or len(raw_ip) > 64:
        return None, "IP address is empty or exceeds maximum length."

    try:
        ip_obj = ipaddress.ip_address(raw_ip)
    except ValueError:
        return None, "Invalid IPv4 or IPv6 address syntax."

    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
        or not ip_obj.is_global
    ):
        return None, f"Target IP ({ip_obj.compressed}) is in a non-routable or reserved RFC range."

    return ip_obj.compressed, None


def safe_dict(val):
    if isinstance(val, dict):
        return val
    if isinstance(val, list) and len(val) > 0 and isinstance(val[0], dict):
        return val[0]
    return {}


def pick_first(*values):
    for val in values:
        if val is not None and val != "" and val != "N/A" and val != "-":
            return val
    return None


def safe_future_result(future):
    if not future.done():
        return {}
    try:
        return safe_dict(future.result())
    except Exception:
        return {}


def fetch_abuseipdb(target_ip, api_key):
    if not api_key or api_key == "your_real_abuseipdb_key_here":
        return {}
    try:
        res = get_http_session().get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Accept": "application/json", "Key": api_key},
            params={"ipAddress": target_ip, "maxAgeInDays": "90"},
            timeout=API_TIMEOUT
        )
        if res.status_code == 200:
            return safe_dict(res.json()).get("data", {})
    except Exception:
        pass
    return {}


def fetch_shodan(target_ip):
    try:
        res = get_http_session().get(
            f"https://internetdb.shodan.io/{target_ip}",
            timeout=API_TIMEOUT
        )
        if res.status_code == 200:
            return safe_dict(res.json())
    except Exception:
        pass
    return {}


def fetch_ipapi_is(target_ip):
    try:
        res = get_http_session().get(
            "https://api.ipapi.is/",
            params={"q": target_ip},
            timeout=API_TIMEOUT
        )
        if res.status_code == 200:
            return safe_dict(res.json())
    except Exception:
        pass
    return {}


def fetch_ipwhois_backend(target_ip):
    try:
        res = get_http_session().get(
            f"https://ipwho.is/{target_ip}",
            timeout=API_TIMEOUT
        )
        if res.status_code == 200:
            data = safe_dict(res.json())
            if data.get("success") is not False:
                return data
    except Exception:
        pass
    return {}


def classify_node_role(abuse_data, shodan_data, vpn_intel, open_ports):
    usage_type = (abuse_data.get("usageType") or "").lower()
    is_whitelisted = bool(abuse_data.get("isWhitelisted"))
    ports_set = set(open_ports or [])

    if vpn_intel.get("is_tor") or abuse_data.get("isTor"):
        return {
            "node_role": "TOR EXIT / RELAY NODE",
            "role_badge_text": "NODE: TOR EXIT [HIGH RISK]",
            "role_badge_level": "danger"
        }

    if vpn_intel.get("is_vpn"):
        vpn_service = vpn_intel.get("vpn_service")
        role_label = f"VPN NODE ({vpn_service})" if vpn_service else "COMMERCIAL VPN GATEWAY"
        return {
            "node_role": role_label,
            "role_badge_text": "NODE: VPN DETECTED",
            "role_badge_level": "warn"
        }

    if vpn_intel.get("is_proxy"):
        return {
            "node_role": "OPEN PROXY / ANONYMIZER",
            "role_badge_text": "NODE: PROXY DETECTED",
            "role_badge_level": "warn"
        }

    if is_whitelisted or (53 in ports_set and ("dns" in usage_type or "content delivery" in usage_type)):
        return {
            "node_role": "PUBLIC DNS / CORE INFRASTRUCTURE",
            "role_badge_text": "NODE: PUBLIC INFRASTRUCTURE",
            "role_badge_level": "clean"
        }

    if vpn_intel.get("is_datacenter") or any(k in usage_type for k in ["data center", "web hosting", "transit"]):
        if ports_set.intersection({80, 443, 8080, 8443}):
            return {
                "node_role": "CLOUD WEB / API SERVER",
                "role_badge_text": "NODE: CLOUD SERVER",
                "role_badge_level": "warn"
            }
        return {
            "node_role": "DATACENTER / HOSTING NODE",
            "role_badge_text": "NODE: DATACENTER",
            "role_badge_level": "warn"
        }

    if vpn_intel.get("is_mobile") or "mobile" in usage_type:
        return {
            "node_role": "MOBILE CARRIER NAT NODE",
            "role_badge_text": "NODE: MOBILE ISP [CLEAN]",
            "role_badge_level": "clean"
        }

    return {
        "node_role": "RESIDENTIAL ISP CLIENT",
        "role_badge_text": "NODE: RESIDENTIAL [CLEAN]",
        "role_badge_level": "clean"
    }


@app.route("/", methods=["GET"])
def serve_index():
    return send_from_directory(ROOT_DIR, "index.html")


@app.route("/<path:filename>", methods=["GET"])
def serve_static_allowlist(filename):
    if filename in ALLOWED_STATIC_FILES:
        return send_from_directory(ROOT_DIR, filename)
    abort(404)


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "awake", "version": "4.5.2"}), 200


@app.route("/api/threat-intel", methods=["GET"])
def get_threat_intel():
    try:
        client_ip = get_client_ip()
        if is_rate_limited(client_ip):
            return jsonify({"error": "Rate limit exceeded. Please wait a moment before scanning again."}), 429

        target_ip = request.args.get("ip", "").strip()

        if not target_ip:
            candidate_ip, err = validate_public_ip(client_ip)
            if candidate_ip:
                target_ip = candidate_ip
            else:
                for echo_url in ["https://api.ipify.org", "https://icanhazip.com"]:
                    try:
                        r = get_http_session().get(echo_url, timeout=(1.2, 1.5))
                        if r.status_code == 200:
                            discovered, _ = validate_public_ip(r.text.strip())
                            if discovered:
                                target_ip = discovered
                                break
                    except Exception:
                        continue

        normalized_ip, validation_error = validate_public_ip(target_ip)
        if not normalized_ip:
            return jsonify({"error": validation_error or "Invalid IP address."}), 400

        cached = get_cached_intel(normalized_ip)
        if cached:
            return jsonify(cached), 200

        abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

        fut_abuse = EXECUTOR.submit(fetch_abuseipdb, normalized_ip, abuse_key)
        fut_shodan = EXECUTOR.submit(fetch_shodan, normalized_ip)
        fut_ipapi_is = EXECUTOR.submit(fetch_ipapi_is, normalized_ip)
        fut_ipwhois = EXECUTOR.submit(fetch_ipwhois_backend, normalized_ip)

        wait([fut_abuse, fut_shodan, fut_ipapi_is, fut_ipwhois], timeout=2.6)

        abuse_data = safe_future_result(fut_abuse)
        shodan_data = safe_future_result(fut_shodan)
        ipapi_is_data = safe_future_result(fut_ipapi_is)
        ipwhois_data = safe_future_result(fut_ipwhois)

        active_sources = []
        if abuse_data:
            active_sources.append("AbuseIPDB")
        if shodan_data:
            active_sources.append("Shodan")
        if ipapi_is_data:
            active_sources.append("ipapi.is")
        if ipwhois_data:
            active_sources.append("ipwho.is")

        open_ports = shodan_data.get("ports") if isinstance(shodan_data.get("ports"), list) else []
        port_map = {
            21: "21/FTP", 22: "22/SSH", 23: "23/Telnet", 25: "25/SMTP",
            53: "53/DNS", 80: "80/HTTP", 110: "110/POP3", 143: "143/IMAP",
            443: "443/HTTPS", 445: "445/SMB", 3306: "3306/MySQL",
            3389: "3389/RDP", 5432: "5432/PostgreSQL", 8080: "8080/HTTP-Alt",
            8443: "8443/HTTPS-Alt"
        }
        detected_services = [port_map.get(p, str(p)) for p in open_ports[:8]]

        vpn_obj = safe_dict(ipapi_is_data.get("vpn"))
        whois_sec = safe_dict(ipwhois_data.get("security"))
        vpn_intel = {
            "is_vpn": bool(ipapi_is_data.get("is_vpn") or vpn_obj.get("is_vpn") or whois_sec.get("vpn")),
            "vpn_service": vpn_obj.get("service"),
            "is_proxy": bool(ipapi_is_data.get("is_proxy") or whois_sec.get("proxy")),
            "is_tor": bool(ipapi_is_data.get("is_tor") or abuse_data.get("isTor") or whois_sec.get("tor")),
            "is_datacenter": bool(ipapi_is_data.get("is_datacenter") or whois_sec.get("hosting")),
            "is_mobile": bool(ipapi_is_data.get("is_mobile")),
            "is_abuser": bool(ipapi_is_data.get("is_abuser")),
            "is_crawler": bool(ipapi_is_data.get("is_crawler"))
        }

        anonymizer_flags = []
        if vpn_intel["is_tor"]:
            anonymizer_flags.append("Tor Node")
        if vpn_intel["is_vpn"]:
            svc = f" ({vpn_intel['vpn_service']})" if vpn_intel["vpn_service"] else ""
            anonymizer_flags.append(f"VPN{svc}")
        if vpn_intel["is_proxy"]:
            anonymizer_flags.append("Open Proxy")
        if vpn_intel["is_datacenter"]:
            anonymizer_flags.append("Datacenter/Hosting")
        if vpn_intel["is_abuser"]:
            anonymizer_flags.append("Known Abuser Feed")
        if vpn_intel["is_crawler"]:
            anonymizer_flags.append("Search Crawler")

        role_info = classify_node_role(abuse_data, shodan_data, vpn_intel, open_ports)

        ipapi_asn = safe_dict(ipapi_is_data.get("asn"))
        ipapi_comp = safe_dict(ipapi_is_data.get("company"))
        ipapi_loc = safe_dict(ipapi_is_data.get("location"))
        whois_conn = safe_dict(ipwhois_data.get("connection"))
        whois_tz = safe_dict(ipwhois_data.get("timezone"))

        abuse_hostnames = abuse_data.get("hostnames") if isinstance(abuse_data.get("hostnames"), list) else []
        shodan_hostnames = shodan_data.get("hostnames") if isinstance(shodan_data.get("hostnames"), list) else []

        geo_fallback = {
            "ip": normalized_ip,
            "org": pick_first(
                abuse_data.get("isp"),
                ipapi_comp.get("name"),
                ipapi_asn.get("org"),
                whois_conn.get("isp"),
                whois_conn.get("org")
            ),
            "asn": pick_first(
                f"AS{ipapi_asn['asn']}" if ipapi_asn.get("asn") else None,
                f"AS{whois_conn['asn']}" if whois_conn.get("asn") else None
            ),
            "network": pick_first(ipapi_asn.get("route"), ipapi_comp.get("network")),
            "domain": pick_first(
                abuse_data.get("domain"),
                ipapi_comp.get("domain"),
                ipapi_asn.get("domain"),
                whois_conn.get("domain")
            ),
            "hostname": pick_first(
                abuse_hostnames[0] if abuse_hostnames else None,
                shodan_hostnames[0] if shodan_hostnames else None
            ),
            "city": pick_first(ipapi_loc.get("city"), ipwhois_data.get("city")),
            "region": pick_first(ipapi_loc.get("state"), ipwhois_data.get("region")),
            "country_name": pick_first(ipapi_loc.get("country"), ipwhois_data.get("country")),
            "country_code": pick_first(
                abuse_data.get("countryCode"),
                ipapi_loc.get("country_code"),
                ipwhois_data.get("country_code")
            ),
            "postal": pick_first(ipapi_loc.get("zip"), ipwhois_data.get("postal")),
            "timezone": pick_first(ipapi_loc.get("timezone"), whois_tz.get("id")),
            "utc_offset": pick_first(whois_tz.get("utc")),
            "latitude": pick_first(ipapi_loc.get("latitude"), ipwhois_data.get("latitude")),
            "longitude": pick_first(ipapi_loc.get("longitude"), ipwhois_data.get("longitude"))
        }

        result = {
            "ip": normalized_ip,
            "abuseipdb_active": bool(abuse_data),
            "abuse_score": abuse_data.get("abuseConfidenceScore") if abuse_data else None,
            "total_reports": abuse_data.get("totalReports", 0) if abuse_data else 0,
            "distinct_users": abuse_data.get("numDistinctUsers", 0) if abuse_data else 0,
            "is_whitelisted": bool(abuse_data.get("isWhitelisted")) if abuse_data else False,
            "usage_type": pick_first(
                abuse_data.get("usageType"),
                ipapi_asn.get("type", "").title() if ipapi_asn.get("type") else None,
                "Port + VPN Analysis"
            ),
            "node_role": role_info["node_role"],
            "role_badge_text": role_info["role_badge_text"],
            "role_badge_level": role_info["role_badge_level"],
            "anonymizer_flags": anonymizer_flags,
            "open_ports": open_ports,
            "detected_services": detected_services,
            "vulns": shodan_data.get("vulns") if isinstance(shodan_data.get("vulns"), list) else [],
            "tags": shodan_data.get("tags") if isinstance(shodan_data.get("tags"), list) else [],
            "active_backend_sources": active_sources,
            "geo_fallback": geo_fallback
        }

        if active_sources:
            set_cached_intel(normalized_ip, result)

        return jsonify(result), 200

    except Exception:
        traceback.print_exc()
        return jsonify({"error": "Internal server error while aggregating node telemetry."}), 500


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    debug_mode = os.getenv("FLASK_DEBUG", "0") == "1"
    host_bind = os.getenv("FLASK_HOST", "127.0.0.1")
    app.run(host=host_bind, port=port, debug=debug_mode, threaded=True)
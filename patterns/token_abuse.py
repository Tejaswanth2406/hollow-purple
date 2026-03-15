"""
patterns/token_abuse.py

Detects API token and session credential abuse.

Strategies:
  1. Multi-IP token usage (credential sharing / theft)
  2. Impossible travel: two IPs from distant geolocations in short time
  3. Token used after explicit revocation event
  4. Token reuse from Tor/VPN/datacenter ASNs
  5. High-frequency token requests (brute-force / enumeration)
  6. Token used outside declared allowed IP range (CIDR policy)
  7. Credential stuffing: same IP trying many different tokens
"""

import time
import math
import logging
from collections import defaultdict
from ipaddress import ip_address, ip_network, AddressValueError

logger = logging.getLogger("hollow_purple.token_abuse")

# --- State stores ---
_token_usage:    dict[str, list[tuple[str, float]]] = defaultdict(list)   # token -> [(ip, ts)]
_token_geo:      dict[str, list[tuple[float, float, float]]] = defaultdict(list)  # token -> [(lat, lon, ts)]
_revoked_tokens: set[str] = set()
_ip_tokens:      dict[str, list[tuple[str, float]]] = defaultdict(list)  # ip -> [(token, ts)]

# Knobs
MULTI_IP_THRESHOLD        = 3     # distinct IPs per token in window
IP_WINDOW_SEC             = 120   # 2-minute window
IMPOSSIBLE_TRAVEL_KMH     = 900   # max credible travel speed (below commercial flight)
HIGH_FREQ_THRESHOLD       = 30    # requests per token in 60s
STUFFING_THRESHOLD        = 10    # distinct tokens per IP in 60s
STUFFING_WINDOW_SEC       = 60

# Known datacenter/VPN ASN prefixes (simplified; in prod, pull from GeoIP DB)
SUSPICIOUS_ASN_PREFIXES = {"datacenter", "vpn", "tor", "proxy", "hosting", "anonymous"}


def revoke_token(token: str):
    """Called by the ingestion layer when a revocation event is received."""
    _revoked_tokens.add(token)


def detect_token_abuse(event: dict) -> list[dict]:
    alerts = []
    token  = event.get("token")
    if not token:
        return alerts

    ip    = event.get("ip", "")
    lat   = event.get("geo_lat")
    lon   = event.get("geo_lon")
    asn   = event.get("asn", "").lower()
    cidr  = event.get("allowed_cidr")      # declared allowed IP range for this token
    now   = time.time()

    _token_usage[token].append((ip, now))
    _ip_tokens[ip].append((token, now))
    if lat is not None and lon is not None:
        _token_geo[token].append((lat, lon, now))

    recent_ips = _ips_in_window(token, now)

    # --- 1. Multi-IP token usage ---
    if len(recent_ips) > MULTI_IP_THRESHOLD:
        alerts.append({
            "type":     "token_abuse",
            "subtype":  "multi_ip_usage",
            "token":    _mask(token),
            "ips":      list(recent_ips),
            "severity": "high",
            "detail":   f"Token seen from {len(recent_ips)} distinct IPs "
                        f"within {IP_WINDOW_SEC}s",
        })

    # --- 2. Impossible travel ---
    if lat is not None and lon is not None:
        travel_alert = _check_impossible_travel(token, lat, lon, now)
        if travel_alert:
            alerts.append(travel_alert)

    # --- 3. Revoked token reuse ---
    if token in _revoked_tokens:
        alerts.append({
            "type":     "token_abuse",
            "subtype":  "revoked_token_reuse",
            "token":    _mask(token),
            "ip":       ip,
            "severity": "critical",
            "detail":   "Token used after explicit revocation",
        })

    # --- 4. Suspicious ASN ---
    if asn and any(sus in asn for sus in SUSPICIOUS_ASN_PREFIXES):
        alerts.append({
            "type":     "token_abuse",
            "subtype":  "suspicious_network_origin",
            "token":    _mask(token),
            "ip":       ip,
            "asn":      asn,
            "severity": "medium",
            "detail":   f"Token used from suspicious ASN: {asn}",
        })

    # --- 5. High-frequency requests ---
    recent_all = [ts for _, ts in _token_usage[token] if now - ts <= 60]
    if len(recent_all) > HIGH_FREQ_THRESHOLD:
        alerts.append({
            "type":     "token_abuse",
            "subtype":  "high_frequency",
            "token":    _mask(token),
            "ip":       ip,
            "severity": "medium",
            "detail":   f"Token used {len(recent_all)} times in 60s",
        })

    # --- 6. Out-of-CIDR usage ---
    if cidr and ip:
        try:
            if ip_address(ip) not in ip_network(cidr, strict=False):
                alerts.append({
                    "type":     "token_abuse",
                    "subtype":  "out_of_cidr",
                    "token":    _mask(token),
                    "ip":       ip,
                    "allowed":  cidr,
                    "severity": "high",
                    "detail":   f"Token used from IP outside declared CIDR {cidr}",
                })
        except (AddressValueError, ValueError):
            pass

    # --- 7. Credential stuffing from this IP ---
    recent_ip_tokens = {t for t, ts in _ip_tokens[ip] if now - ts <= STUFFING_WINDOW_SEC}
    if len(recent_ip_tokens) > STUFFING_THRESHOLD:
        alerts.append({
            "type":     "token_abuse",
            "subtype":  "credential_stuffing",
            "ip":       ip,
            "severity": "critical",
            "detail":   f"IP {ip} tried {len(recent_ip_tokens)} distinct tokens "
                        f"in {STUFFING_WINDOW_SEC}s",
            "token_count": len(recent_ip_tokens),
        })

    return alerts


# ------------------------------------------------------------------ #
#  Helpers                                                            #
# ------------------------------------------------------------------ #

def _ips_in_window(token: str, now: float) -> set[str]:
    return {ip for ip, ts in _token_usage[token] if now - ts <= IP_WINDOW_SEC}


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return 2 * R * math.asin(math.sqrt(a))


def _check_impossible_travel(token, lat, lon, now) -> dict | None:
    history = _token_geo[token]
    if len(history) < 2:
        return None
    prev_lat, prev_lon, prev_ts = history[-2]
    elapsed_hours = max((now - prev_ts) / 3600, 1e-6)
    distance_km   = _haversine_km(prev_lat, prev_lon, lat, lon)
    speed_kmh     = distance_km / elapsed_hours
    if speed_kmh > IMPOSSIBLE_TRAVEL_KMH:
        return {
            "type":      "token_abuse",
            "subtype":   "impossible_travel",
            "token":     _mask(token),
            "speed_kmh": round(speed_kmh, 1),
            "distance_km": round(distance_km, 1),
            "elapsed_hours": round(elapsed_hours, 4),
            "severity":  "critical",
            "detail":    f"Token traveled {distance_km:.0f}km in "
                         f"{elapsed_hours*60:.1f}min ({speed_kmh:.0f}km/h)",
        }
    return None


def _mask(token: str) -> str:
    """Partially mask token for safe logging."""
    if len(token) <= 8:
        return "****"
    return token[:4] + "****" + token[-4:]
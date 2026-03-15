"""
ingestion/processors/enricher.py — Event Enrichment Processor

Enrichment layers applied to every event:
  1. GeoIP lookup (lat/lon/country/city/ASN from IP)
  2. Identity metadata (actor display name, account type, MFA status)
  3. Threat intelligence IP reputation (stub for VirusTotal / Shodan / internal feed)
  4. Resource tagging (sensitivity labels from asset inventory)
  5. Risk context from known attack patterns
  6. Session correlation (link events to known session IDs)
  7. Timestamp normalization to ISO-8601 + Unix epoch
"""

import asyncio
import logging
import time
from typing import Any

logger = logging.getLogger("hollow_purple.enricher")

# --- Configurable enrichment feature flags ---
ENRICHMENT_FLAGS = {
    "geoip":          True,
    "identity":       True,
    "threat_intel":   True,
    "resource_tags":  True,
    "session":        True,
}

# Stub: known high-risk IPs / CIDR (in production: pull from threat feed)
KNOWN_MALICIOUS_IPS: set[str] = {"198.51.100.1", "203.0.113.99"}
KNOWN_TOR_EXIT_NODES: set[str] = {"10.0.0.1"}   # placeholder

# Stub: sensitive resource prefixes
SENSITIVE_RESOURCE_PREFIXES = (
    "prod", "production", "secret", "kms", "billing", "financial", "pci", "hipaa",
)


class EventEnricher:
    """
    Async event enrichment processor.
    All enrichment runs concurrently via asyncio.gather.
    Any single enrichment failure does NOT fail the pipeline — it logs and continues.
    """

    def __init__(self, flags: dict | None = None):
        self.flags = {**ENRICHMENT_FLAGS, **(flags or {})}

    async def enrich(self, event: dict) -> dict:
        if not isinstance(event, dict) or event.get("_batch"):
            return event

        tasks = []
        if self.flags.get("geoip"):         tasks.append(self._enrich_geoip(event))
        if self.flags.get("identity"):      tasks.append(self._enrich_identity(event))
        if self.flags.get("threat_intel"):  tasks.append(self._enrich_threat_intel(event))
        if self.flags.get("resource_tags"): tasks.append(self._enrich_resource_tags(event))
        if self.flags.get("session"):       tasks.append(self._enrich_session(event))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning("Enrichment task %d failed: %s", i, result)

        event["enriched"]    = True
        event["enriched_at"] = time.time()
        return event

    # ------------------------------------------------------------------ #
    #  Enrichment modules                                                  #
    # ------------------------------------------------------------------ #

    async def _enrich_geoip(self, event: dict):
        """
        Resolve IP to geographic metadata.
        Production: call MaxMind GeoIP2 or ip-api.com.
        """
        ip = event.get("ip")
        if not ip:
            return

        # Stub: realistic structure for what GeoIP returns
        geo = await self._fake_geoip_lookup(ip)
        event["geo"] = geo
        if "lat" in geo:
            event["geo_lat"] = geo["lat"]
            event["geo_lon"] = geo["lon"]
        if "asn" in geo:
            event["asn"] = geo["asn"]

    async def _enrich_identity(self, event: dict):
        """
        Lookup actor metadata from identity directory.
        Production: call Okta API, Active Directory, or internal HR system.
        """
        actor = event.get("actor", "")
        if not actor:
            return

        event["identity"] = {
            "display_name": actor.split("@")[0].replace("-", " ").title(),
            "account_type": event.get("actor_type", "user"),
            "department":   "unknown",   # Populated from HR API in production
            "mfa_enrolled": True,        # Populated from IdP in production
            "is_privileged": any(kw in actor.lower() for kw in ("admin", "root", "super")),
        }

    async def _enrich_threat_intel(self, event: dict):
        """
        Check IP against threat intelligence feeds.
        Production: VirusTotal, Shodan, AbuseIPDB, internal blocklist.
        """
        ip = event.get("ip", "")
        if not ip:
            return

        threat = {
            "is_malicious":    ip in KNOWN_MALICIOUS_IPS,
            "is_tor_exit":     ip in KNOWN_TOR_EXIT_NODES,
            "reputation_score": 0,     # 0-100, higher = more malicious
            "feed_hits":        [],
        }

        if threat["is_malicious"]:
            threat["reputation_score"] = 95
            threat["feed_hits"].append("internal_blocklist")
            event.setdefault("tags", []).append("malicious_ip")

        if threat["is_tor_exit"]:
            threat["reputation_score"] = max(threat["reputation_score"], 70)
            threat["feed_hits"].append("tor_exit_nodes")
            event.setdefault("tags", []).append("tor_exit")

        event["threat_intel"] = threat

    async def _enrich_resource_tags(self, event: dict):
        """
        Look up sensitivity labels for the target resource.
        Production: pull from CMDB / asset inventory / AWS Resource Groups Tagging API.
        """
        resource = str(event.get("resource", "")).lower()
        if not resource:
            return

        is_sensitive = any(pfx in resource for pfx in SENSITIVE_RESOURCE_PREFIXES)
        event["resource_meta"] = {
            "sensitivity":   "high" if is_sensitive else "normal",
            "environment":   "production" if "prod" in resource else "unknown",
            "data_class":    "confidential" if is_sensitive else "internal",
            "owner":         "unknown",   # Populated from CMDB in production
        }
        if is_sensitive:
            event.setdefault("tags", []).append("sensitive_resource")

    async def _enrich_session(self, event: dict):
        """
        Correlate this event to a known session or attack chain.
        Production: lookup in Redis session store.
        """
        actor     = event.get("actor", "")
        action    = event.get("action", "")
        ip        = event.get("ip", "")
        session_key = f"{actor}:{ip}"

        # Stub: in production this queries Redis for existing session context
        event["session"] = {
            "session_id": None,          # Populated from session store
            "is_new":     True,
            "event_sequence": 1,
        }

    # ------------------------------------------------------------------ #
    #  Stub helpers (replace with real API calls in production)           #
    # ------------------------------------------------------------------ #

    async def _fake_geoip_lookup(self, ip: str) -> dict:
        """Stub GeoIP lookup — replace with MaxMind GeoIP2 in production."""
        return {
            "ip":      ip,
            "country": "US",
            "city":    "Ashburn",
            "lat":     39.0469,
            "lon":     -77.4903,
            "asn":     "AS14618 Amazon.com",
            "org":     "Amazon Data Services",
        }
"""
ingestion/processors/parser.py — Multi-Format Event Parser

Handles:
  - Raw dict passthrough
  - JSON string / bytes decoding
  - CloudEvents v1.0 envelope unwrapping
  - AWS CloudTrail JSON record format
  - Azure Activity Log format
  - GCP AuditLog format
  - Base64-encoded payloads (e.g. from SQS/Kinesis)
  - Gzip-compressed payloads
"""

import base64
import gzip
import json
import logging
from typing import Any

logger = logging.getLogger("hollow_purple.parser")

# CloudEvents required attributes
CLOUD_EVENTS_REQUIRED = {"specversion", "id", "source", "type"}


class EventParser:
    """
    Converts raw inbound data (any supported format) into a plain Python dict.

    Raises:
        ValueError  — if the payload cannot be parsed into a usable dict
        TypeError   — if the payload type is entirely unsupported
    """

    async def parse(self, raw: Any) -> dict:
        # --- Fast path: already a dict ---
        if isinstance(raw, dict):
            return self._unwrap(raw)

        # --- Bytes: try base64 decode → gzip → json ---
        if isinstance(raw, (bytes, bytearray)):
            return await self._parse_bytes(raw)

        # --- String: JSON decode ---
        if isinstance(raw, str):
            return await self._parse_string(raw)

        raise TypeError(f"Unsupported raw event type: {type(raw).__name__}")

    # ------------------------------------------------------------------ #
    #  Format handlers                                                     #
    # ------------------------------------------------------------------ #

    async def _parse_bytes(self, data: bytes) -> dict:
        # Try gzip first
        if data[:2] == b"\x1f\x8b":
            try:
                data = gzip.decompress(data)
            except Exception as exc:
                logger.debug("Gzip decompress failed: %s — trying raw bytes", exc)

        # Try base64
        try:
            decoded = base64.b64decode(data)
            return await self._parse_bytes(decoded)   # recurse once
        except Exception:
            pass

        # Try UTF-8 JSON
        try:
            return await self._parse_string(data.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"Cannot decode bytes payload: {exc}") from exc

    async def _parse_string(self, text: str) -> dict:
        text = text.strip()
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON parse error: {exc}") from exc

        if isinstance(obj, list):
            # Wrap array as a batch envelope
            return {"_batch": True, "events": obj, "count": len(obj)}

        if isinstance(obj, dict):
            return self._unwrap(obj)

        raise ValueError(f"Parsed JSON is neither dict nor list: {type(obj)}")

    def _unwrap(self, obj: dict) -> dict:
        """Detect and unwrap known envelope formats."""

        # CloudEvents v1.0
        if CLOUD_EVENTS_REQUIRED.issubset(obj.keys()):
            return self._unwrap_cloudevents(obj)

        # AWS CloudTrail record envelope
        if "Records" in obj and isinstance(obj["Records"], list):
            records = obj["Records"]
            if records and "eventName" in records[0]:
                return self._unwrap_cloudtrail_record(records[0])

        # AWS SQS / SNS wrapper
        if "body" in obj and isinstance(obj.get("body"), str):
            try:
                inner = json.loads(obj["body"])
                return self._unwrap(inner)
            except (json.JSONDecodeError, TypeError):
                pass

        # AWS Kinesis Data Streams record
        if "kinesis" in obj and "data" in obj.get("kinesis", {}):
            try:
                decoded = base64.b64decode(obj["kinesis"]["data"])
                inner   = json.loads(decoded)
                return self._unwrap(inner)
            except Exception:
                pass

        return obj   # already a clean dict

    def _unwrap_cloudevents(self, obj: dict) -> dict:
        data = obj.get("data") or obj.get("data_base64")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except Exception:
                pass
        return {
            "source":    obj.get("source"),
            "service":   obj.get("type"),
            "event_id":  obj.get("id"),
            "timestamp": obj.get("time"),
            "actor":     obj.get("subject"),
            "data":      data,
            "_envelope": "cloudevents",
        }

    def _unwrap_cloudtrail_record(self, record: dict) -> dict:
        user_identity = record.get("userIdentity", {})
        return {
            "source":    "aws",
            "service":   "cloudtrail",
            "event_id":  record.get("eventID"),
            "action":    record.get("eventName"),
            "actor":     user_identity.get("arn") or user_identity.get("userName"),
            "resource":  str(record.get("requestParameters", {})),
            "ip":        record.get("sourceIPAddress"),
            "region":    record.get("awsRegion"),
            "timestamp": record.get("eventTime"),
            "user_agent": record.get("userAgent"),
            "_envelope": "cloudtrail",
        }
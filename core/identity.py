"""
identity.py — Hollow Purple Core Layer
========================================
Identity management: creation, derivation, validation, fingerprinting.

All identity hashes use SHA-256.
Deterministic UUID generation is based on UUID5 (name-based).

Author: Hollow Purple Infrastructure Team
Version: 1.0.0
"""

from __future__ import annotations

import hashlib
import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

from .constants import (
    HASH_ALGORITHM,
    HASH_ENCODING,
    IDENTITY_NAMESPACE,
    IDENTITY_PREFIX,
    TIMESTAMP_FORMAT,
)
from .models import Identity

logger = logging.getLogger(__name__)

# Precompile UUID5 namespace
_UUID_NAMESPACE: uuid.UUID = uuid.UUID(IDENTITY_NAMESPACE)

# Regex for a valid identity_id: prefix + hyphen + UUID4/5 hex chars
_IDENTITY_ID_PATTERN: re.Pattern = re.compile(
    r"^[a-z]{1,16}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _utcnow_iso() -> str:
    """Return the current UTC time as an ISO-8601 microsecond-precision string."""
    return datetime.now(tz=timezone.utc).strftime(TIMESTAMP_FORMAT)


def _compute_fingerprint(identity_id: str, name: str, created_at: str) -> str:
    """
    Compute a deterministic SHA-256 fingerprint for an identity.

    The fingerprint is derived from the identity_id, name, and created_at
    fields, joined by a null byte separator to prevent trivial collisions.

    Args:
        identity_id: Unique identifier string.
        name: Human-readable name of the identity.
        created_at: ISO-8601 UTC creation timestamp.

    Returns:
        64-char hex-encoded SHA-256 digest.
    """
    raw: str = "\x00".join([identity_id, name, created_at])
    h = hashlib.new(HASH_ALGORITHM)
    h.update(raw.encode(HASH_ENCODING))
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_identity(name: str, node_id: Optional[str] = None) -> Identity:
    """
    Create a new unique Identity with a random UUID.

    The identity's fingerprint is computed deterministically from its
    identity_id, name, and creation timestamp.

    Args:
        name: Human-readable label for the identity.
        node_id: Optional node qualifier appended to the prefix for scoping.

    Returns:
        A fully constructed, immutable Identity.

    Raises:
        ValueError: If name is empty.
    """
    if not name or not name.strip():
        raise ValueError("Identity name must not be empty.")

    prefix: str = f"{IDENTITY_PREFIX}-{node_id}" if node_id else IDENTITY_PREFIX
    raw_id: str = str(uuid.uuid4())
    identity_id: str = f"{prefix}-{raw_id}"
    created_at: str = _utcnow_iso()
    fingerprint: str = _compute_fingerprint(identity_id, name.strip(), created_at)

    identity = Identity(
        identity_id=identity_id,
        name=name.strip(),
        fingerprint=fingerprint,
        created_at=created_at,
    )

    logger.debug(
        "Identity created.",
        extra={"identity_id": identity_id, "fingerprint": fingerprint},
    )
    return identity


def derive_deterministic_identity(name: str, namespace: str = IDENTITY_NAMESPACE) -> Identity:
    """
    Derive a deterministic Identity from a name using UUID5.

    Given the same name and namespace, this function always produces
    the same identity_id and fingerprint. Useful for system-level
    actors whose identities must be stable across restarts.

    Args:
        name: Canonical name to derive the identity from.
        namespace: UUID5 namespace string (defaults to IDENTITY_NAMESPACE).

    Returns:
        A fully constructed, immutable Identity.

    Raises:
        ValueError: If name is empty.
    """
    if not name or not name.strip():
        raise ValueError("Name for deterministic identity must not be empty.")

    ns: uuid.UUID = uuid.UUID(namespace) if namespace != IDENTITY_NAMESPACE else _UUID_NAMESPACE
    raw_id: str = str(uuid.uuid5(ns, name.strip()))
    identity_id: str = f"{IDENTITY_PREFIX}-{raw_id}"

    # Deterministic timestamp: use the UUID5 hex as a stable seed
    created_at: str = "1970-01-01T00:00:00.000000Z"
    fingerprint: str = _compute_fingerprint(identity_id, name.strip(), created_at)

    identity = Identity(
        identity_id=identity_id,
        name=name.strip(),
        fingerprint=fingerprint,
        created_at=created_at,
    )

    logger.debug(
        "Deterministic identity derived.",
        extra={"identity_id": identity_id, "name": name},
    )
    return identity


def validate_identity(identity: Identity) -> bool:
    """
    Validate that an Identity object is internally consistent.

    Checks performed:
      1. identity_id matches the expected prefix-UUID pattern.
      2. fingerprint is a valid 64-char hex string.
      3. Recomputed fingerprint matches the stored one.

    Args:
        identity: The Identity object to validate.

    Returns:
        True if the identity passes all checks.

    Raises:
        ValueError: On the first validation failure, with a descriptive message.
    """
    if not _IDENTITY_ID_PATTERN.match(identity.identity_id):
        raise ValueError(
            f"identity_id '{identity.identity_id}' does not match expected pattern."
        )

    if len(identity.fingerprint) != 64:
        raise ValueError(
            "fingerprint must be exactly 64 hex characters (SHA-256 digest)."
        )

    expected_fp: str = _compute_fingerprint(
        identity.identity_id, identity.name, identity.created_at
    )
    if identity.fingerprint != expected_fp:
        raise ValueError(
            "Identity fingerprint is invalid: content has been tampered with."
        )

    logger.debug(
        "Identity validated successfully.",
        extra={"identity_id": identity.identity_id},
    )
    return True


def identity_fingerprint(identity: Identity) -> str:
    """
    Return the cryptographic fingerprint for the given Identity.

    This is a convenience accessor that recomputes and returns the fingerprint,
    confirming it matches what is stored (raises ValueError on mismatch).

    Args:
        identity: The Identity to fingerprint.

    Returns:
        64-char SHA-256 hex digest string.

    Raises:
        ValueError: If the stored fingerprint is inconsistent.
    """
    validate_identity(identity)
    return identity.fingerprint


def identity_from_dict(data: dict) -> Identity:
    """
    Deserialize an Identity from a plain dictionary and validate it.

    Args:
        data: Dictionary produced by Identity.to_dict().

    Returns:
        A validated, immutable Identity object.

    Raises:
        KeyError: If required fields are missing.
        ValueError: If the identity fails validation.
    """
    identity = Identity.from_dict(data)
    validate_identity(identity)
    return identity
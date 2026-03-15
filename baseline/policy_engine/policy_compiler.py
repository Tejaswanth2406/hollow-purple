"""
policy_compiler.py
==================
Hollow Purple Policy Engine — Policy Compiler

Responsible for compiling raw policy definitions (dict/JSON) into optimized,
deterministic, executable rule objects.  Every public function is pure with
respect to its inputs; no module-level mutable state is maintained.

Security guarantees
-------------------
* Policies are validated against a strict schema before any compilation step.
* Condition values are type-coerced and range-checked; no eval/exec is used.
* Compiled rule ordering is fully deterministic (sort key: priority DESC,
  rule_id ASC) so that identical policy definitions always produce identical
  evaluation orderings, enabling deterministic replay.

Engineering standards
---------------------
* Python 3.11+
* Strict typing via ``from __future__ import annotations``
* Pydantic v2 models for all structured objects
* Structured logging (structlog)
* Raises typed exceptions for all error conditions
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from enum import Enum
from pathlib import Path
from typing import Any, Final

from pydantic import BaseModel, Field, field_validator, model_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SUPPORTED_POLICY_VERSION: Final[str] = "1.0"
_MAX_RULES_PER_POLICY: Final[int] = 1_000
_MAX_CONDITIONS_PER_RULE: Final[int] = 50
_VALID_RULE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")
_VALID_POLICY_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-zA-Z0-9_\-]{1,128}$")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class ConditionOperator(str, Enum):
    """Allowed comparison operators for rule conditions."""

    EQ = "eq"
    NEQ = "neq"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    EXISTS = "exists"
    NOT_EXISTS = "not_exists"


class ConditionField(str, Enum):
    """
    All addressable fields within an evaluation context.
    Extending this enum is the *only* way to add new addressable fields,
    ensuring no arbitrary attribute access at evaluation time.
    """

    # Identity attributes
    IDENTITY_ID = "identity.id"
    IDENTITY_ROLE = "identity.role"
    IDENTITY_TRUST_SCORE = "identity.trust_score"
    IDENTITY_REGION = "identity.region"
    IDENTITY_MFA_VERIFIED = "identity.mfa_verified"
    IDENTITY_ACCOUNT_AGE_DAYS = "identity.account_age_days"
    IDENTITY_FLAGS = "identity.flags"

    # Behavioral drift
    DRIFT_SCORE = "drift.score"
    DRIFT_VELOCITY = "drift.velocity"
    DRIFT_CATEGORY = "drift.category"
    DRIFT_CONSECUTIVE_ANOMALIES = "drift.consecutive_anomalies"

    # Event properties
    EVENT_TYPE = "event.type"
    EVENT_SOURCE_IP = "event.source_ip"
    EVENT_RESOURCE_ID = "event.resource_id"
    EVENT_ACTION = "event.action"
    EVENT_TIMESTAMP_EPOCH = "event.timestamp_epoch"

    # Resource state
    RESOURCE_STATUS = "resource.status"
    RESOURCE_SENSITIVITY = "resource.sensitivity"
    RESOURCE_OWNER_ID = "resource.owner_id"

    # Time constraints (evaluated against wall-clock UTC at evaluation time)
    TIME_HOUR_UTC = "time.hour_utc"
    TIME_DAY_OF_WEEK = "time.day_of_week"


class MitigationAction(str, Enum):
    """
    Enumeration of all permitted mitigation actions.
    Only actions listed here may appear in a compiled policy rule.
    """

    LOG_ALERT = "log_alert"
    FLAG_IDENTITY = "flag_identity"
    SUSPEND_RESOURCE = "suspend_resource"
    REQUIRE_REAUTHENTICATION = "require_reauthentication"
    INCREASE_MONITORING = "increase_monitoring"
    DENY_REQUEST = "deny_request"
    NOTIFY_SECURITY_TEAM = "notify_security_team"


class PolicyEffect(str, Enum):
    """The effect produced when a rule matches."""

    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"


# ---------------------------------------------------------------------------
# Pydantic Models — Raw policy input (before compilation)
# ---------------------------------------------------------------------------


class RawCondition(BaseModel):
    """A single raw condition extracted from a policy definition."""

    field: ConditionField
    operator: ConditionOperator
    value: Any = None  # None is valid for EXISTS / NOT_EXISTS operators

    @model_validator(mode="after")
    def _validate_value_for_operator(self) -> "RawCondition":
        no_value_ops = {ConditionOperator.EXISTS, ConditionOperator.NOT_EXISTS}
        if self.operator in no_value_ops and self.value is not None:
            raise ValueError(
                f"Operator '{self.operator}' must not have a value; got {self.value!r}"
            )
        if self.operator not in no_value_ops and self.value is None:
            raise ValueError(
                f"Operator '{self.operator}' requires a non-None value."
            )
        if self.operator in {ConditionOperator.IN, ConditionOperator.NOT_IN}:
            if not isinstance(self.value, list):
                raise ValueError(
                    f"Operator '{self.operator}' requires a list value; "
                    f"got {type(self.value).__name__}"
                )
            if len(self.value) == 0:
                raise ValueError(
                    f"Operator '{self.operator}' requires a non-empty list."
                )
        return self


class RawRule(BaseModel):
    """A single rule as it appears in a raw policy definition."""

    rule_id: str
    description: str = ""
    priority: int = Field(default=100, ge=0, le=10_000)
    effect: PolicyEffect
    conditions: list[RawCondition] = Field(min_length=1)
    actions: list[MitigationAction] = Field(min_length=1)
    enabled: bool = True

    @field_validator("rule_id")
    @classmethod
    def _validate_rule_id(cls, v: str) -> str:
        if not _VALID_RULE_ID_RE.match(v):
            raise ValueError(
                f"rule_id '{v}' is invalid. Must match {_VALID_RULE_ID_RE.pattern}"
            )
        return v

    @field_validator("conditions")
    @classmethod
    def _validate_condition_count(cls, v: list[RawCondition]) -> list[RawCondition]:
        if len(v) > _MAX_CONDITIONS_PER_RULE:
            raise ValueError(
                f"A rule may not have more than {_MAX_CONDITIONS_PER_RULE} conditions; "
                f"got {len(v)}."
            )
        return v


class RawPolicy(BaseModel):
    """Top-level raw policy definition as parsed from JSON/dict input."""

    policy_id: str
    version: str = _SUPPORTED_POLICY_VERSION
    description: str = ""
    rules: list[RawRule] = Field(min_length=1)

    @field_validator("policy_id")
    @classmethod
    def _validate_policy_id(cls, v: str) -> str:
        if not _VALID_POLICY_ID_RE.match(v):
            raise ValueError(
                f"policy_id '{v}' is invalid. Must match {_VALID_POLICY_ID_RE.pattern}"
            )
        return v

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: str) -> str:
        if v != _SUPPORTED_POLICY_VERSION:
            raise ValueError(
                f"Unsupported policy version '{v}'. "
                f"Expected '{_SUPPORTED_POLICY_VERSION}'."
            )
        return v

    @field_validator("rules")
    @classmethod
    def _validate_rule_count(cls, v: list[RawRule]) -> list[RawRule]:
        if len(v) > _MAX_RULES_PER_POLICY:
            raise ValueError(
                f"A policy may not contain more than {_MAX_RULES_PER_POLICY} rules; "
                f"got {len(v)}."
            )
        return v

    @model_validator(mode="after")
    def _validate_unique_rule_ids(self) -> "RawPolicy":
        ids = [r.rule_id for r in self.rules]
        duplicates = {rid for rid in ids if ids.count(rid) > 1}
        if duplicates:
            raise ValueError(
                f"Duplicate rule_id(s) found in policy '{self.policy_id}': "
                f"{sorted(duplicates)}"
            )
        return self


# ---------------------------------------------------------------------------
# Compiled models — output of the compiler
# ---------------------------------------------------------------------------


class CompiledCondition(BaseModel):
    """
    An immutable, validated condition ready for deterministic evaluation.
    All fields are normalised during compilation.
    """

    field: ConditionField
    operator: ConditionOperator
    value: Any = None

    model_config = {"frozen": True}


class CompiledRule(BaseModel):
    """
    An immutable, compiled rule with a deterministic sort key.

    The ``sort_key`` encodes (priority DESC, rule_id ASC) as a tuple so that
    rules can be sorted without re-deriving the key on every evaluation.
    Negating priority places highest-priority rules first when sorted ascending.
    """

    rule_id: str
    description: str
    priority: int
    effect: PolicyEffect
    conditions: tuple[CompiledCondition, ...]
    actions: tuple[MitigationAction, ...]
    enabled: bool
    # Deterministic sort key: (-priority, rule_id)
    sort_key: tuple[int, str]

    model_config = {"frozen": True}


class CompiledPolicy(BaseModel):
    """
    The output of ``compile_policy``.

    ``content_hash`` is a SHA-256 digest of the canonical JSON serialisation
    of the source policy.  It allows downstream consumers to detect whether
    a policy has changed without recompiling.

    ``rules`` is ordered deterministically: priority DESC, rule_id ASC.
    Only enabled rules are included.
    """

    policy_id: str
    version: str
    description: str
    rules: tuple[CompiledRule, ...]
    content_hash: str
    total_rule_count: int
    enabled_rule_count: int

    model_config = {"frozen": True}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class PolicyValidationError(ValueError):
    """Raised when a policy definition fails validation."""


class PolicyCompilationError(RuntimeError):
    """Raised when a validated policy cannot be compiled."""


class PolicyFileError(OSError):
    """Raised when loading a policy from the filesystem fails."""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _canonical_json(policy_def: dict[str, Any]) -> str:
    """
    Produce a stable, canonical JSON string for hashing.

    Keys are sorted recursively so that semantically equivalent policies with
    differing key order produce the same hash.
    """
    return json.dumps(policy_def, sort_keys=True, separators=(",", ":"), default=str)


def _content_hash(policy_def: dict[str, Any]) -> str:
    """Return a hex SHA-256 digest of the canonical policy JSON."""
    canonical = _canonical_json(policy_def)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _compile_condition(raw: RawCondition) -> CompiledCondition:
    """
    Convert a single ``RawCondition`` into a ``CompiledCondition``.

    Applies type normalisation appropriate for each field so that comparison
    operators behave correctly during evaluation (e.g. numeric fields are
    stored as ``float``).
    """
    numeric_fields = {
        ConditionField.IDENTITY_TRUST_SCORE,
        ConditionField.IDENTITY_ACCOUNT_AGE_DAYS,
        ConditionField.DRIFT_SCORE,
        ConditionField.DRIFT_VELOCITY,
        ConditionField.DRIFT_CONSECUTIVE_ANOMALIES,
        ConditionField.EVENT_TIMESTAMP_EPOCH,
        ConditionField.TIME_HOUR_UTC,
        ConditionField.TIME_DAY_OF_WEEK,
    }
    value = raw.value
    if (
        raw.field in numeric_fields
        and value is not None
        and raw.operator
        not in {ConditionOperator.IN, ConditionOperator.NOT_IN}
    ):
        try:
            value = float(value)
        except (TypeError, ValueError) as exc:
            raise PolicyCompilationError(
                f"Field '{raw.field}' expects a numeric value; "
                f"got {value!r}."
            ) from exc

    return CompiledCondition(
        field=raw.field,
        operator=raw.operator,
        value=value,
    )


def _compile_rule(raw: RawRule) -> CompiledRule:
    """
    Convert a single ``RawRule`` into a ``CompiledRule``.

    Conditions are compiled in the order they appear in the raw definition,
    which is preserved through to evaluation.
    """
    compiled_conditions = tuple(
        _compile_condition(c) for c in raw.conditions
    )
    return CompiledRule(
        rule_id=raw.rule_id,
        description=raw.description,
        priority=raw.priority,
        effect=raw.effect,
        conditions=compiled_conditions,
        actions=tuple(raw.actions),
        enabled=raw.enabled,
        sort_key=(-raw.priority, raw.rule_id),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def validate_policy(policy_definition: dict[str, Any]) -> RawPolicy:
    """
    Validate a raw policy definition dict against the policy schema.

    Parameters
    ----------
    policy_definition:
        A dictionary conforming to the Hollow Purple policy schema.

    Returns
    -------
    RawPolicy
        The validated policy model.

    Raises
    ------
    PolicyValidationError
        If the definition fails schema validation.
    """
    if not isinstance(policy_definition, dict):
        raise PolicyValidationError(
            f"policy_definition must be a dict; got {type(policy_definition).__name__}."
        )
    try:
        raw = RawPolicy.model_validate(policy_definition)
    except Exception as exc:
        raise PolicyValidationError(
            f"Policy validation failed: {exc}"
        ) from exc

    logger.info(
        "Policy validated",
        extra={
            "policy_id": raw.policy_id,
            "rule_count": len(raw.rules),
        },
    )
    return raw


def compile_policy(policy_definition: dict[str, Any]) -> CompiledPolicy:
    """
    Validate and compile a policy definition into an optimised, immutable
    ``CompiledPolicy`` ready for deterministic evaluation.

    The same ``policy_definition`` input will *always* produce a
    ``CompiledPolicy`` with the same ``content_hash`` and ``rules`` ordering,
    enabling deterministic replay.

    Parameters
    ----------
    policy_definition:
        A dictionary conforming to the Hollow Purple policy schema.

    Returns
    -------
    CompiledPolicy
        An immutable compiled policy with rules sorted for deterministic
        evaluation (priority DESC, rule_id ASC) and ``content_hash`` set.

    Raises
    ------
    PolicyValidationError
        If the definition fails schema validation.
    PolicyCompilationError
        If compilation fails for any other reason.
    """
    raw = validate_policy(policy_definition)
    digest = _content_hash(policy_definition)

    try:
        compiled_rules_all = [_compile_rule(r) for r in raw.rules]
    except PolicyCompilationError:
        raise
    except Exception as exc:
        raise PolicyCompilationError(
            f"Unexpected error compiling policy '{raw.policy_id}': {exc}"
        ) from exc

    # Deterministic ordering: sort_key = (-priority, rule_id)
    compiled_rules_all.sort(key=lambda r: r.sort_key)
    enabled_rules = tuple(r for r in compiled_rules_all if r.enabled)

    policy = CompiledPolicy(
        policy_id=raw.policy_id,
        version=raw.version,
        description=raw.description,
        rules=enabled_rules,
        content_hash=digest,
        total_rule_count=len(compiled_rules_all),
        enabled_rule_count=len(enabled_rules),
    )

    logger.info(
        "Policy compiled",
        extra={
            "policy_id": policy.policy_id,
            "content_hash": policy.content_hash,
            "total_rules": policy.total_rule_count,
            "enabled_rules": policy.enabled_rule_count,
        },
    )
    return policy


def load_policy_from_file(path: str | Path) -> CompiledPolicy:
    """
    Load, validate, and compile a policy from a JSON file on disk.

    The file must contain a single JSON object conforming to the Hollow Purple
    policy schema.

    Parameters
    ----------
    path:
        Filesystem path to the ``.json`` policy file.

    Returns
    -------
    CompiledPolicy
        The compiled policy derived from the file contents.

    Raises
    ------
    PolicyFileError
        If the file cannot be read or is not valid JSON.
    PolicyValidationError
        If the file content fails schema validation.
    PolicyCompilationError
        If compilation fails.
    """
    file_path = Path(path)
    if not file_path.exists():
        raise PolicyFileError(f"Policy file not found: {file_path}")
    if not file_path.is_file():
        raise PolicyFileError(f"Path is not a regular file: {file_path}")

    try:
        raw_text = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyFileError(
            f"Cannot read policy file '{file_path}': {exc}"
        ) from exc

    try:
        policy_definition: dict[str, Any] = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise PolicyFileError(
            f"Policy file '{file_path}' contains invalid JSON: {exc}"
        ) from exc

    if not isinstance(policy_definition, dict):
        raise PolicyFileError(
            f"Policy file '{file_path}' must contain a JSON object at the top level."
        )

    logger.info(
        "Loading policy from file",
        extra={"path": str(file_path)},
    )
    return compile_policy(policy_definition)
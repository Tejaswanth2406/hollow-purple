"""
scripts/simulate_attack.py
===========================
Enterprise red-team attack simulation engine for Hollow Purple / Mahoraga.

Purpose
-------
Generates realistic, multi-stage attack event sequences for:
  - Mahoraga adaptive defense training
  - Baseline model seeding (benign traffic)
  - Anomaly detector calibration and threshold tuning
  - End-to-end integration testing of the detection pipeline
  - Red-team exercise replay and scoring

Attack scenarios implemented
-----------------------------
1. CREDENTIAL_STUFFING     — High-volume failed logins → success
2. LATERAL_MOVEMENT        — Host-to-host propagation via service accounts
3. PRIVILEGE_ESCALATION    — Low-priv → admin via misconfigured role
4. DATA_EXFILTRATION       — Bulk reads from sensitive stores
5. SUPPLY_CHAIN            — Compromised service account in CI/CD pipeline
6. INSIDER_THREAT          — Legitimate user accessing unusual resources
7. RANSOMWARE_PREP         — Reconnaissance → staging → encryption attempt

Usage
-----
::

    # Print 10 random attack events
    python scripts/simulate_attack.py --count 10

    # Run a specific scenario
    python scripts/simulate_attack.py --scenario lateral_movement

    # Seed baseline (benign traffic) then inject attack
    python scripts/simulate_attack.py --scenario credential_stuffing --baseline-events 500

    # Write events to JSON-lines file for run_pipeline.py
    python scripts/simulate_attack.py --scenario privilege_escalation --output events.jsonl

    # Run all scenarios and pipe to pipeline
    python scripts/simulate_attack.py --all-scenarios | python scripts/run_pipeline.py --stdin --report
"""

from __future__ import annotations

import argparse
import json
import logging
import random
import sys
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Callable, Dict, Generator, List, Optional

logger = logging.getLogger("simulate_attack")


# ---------------------------------------------------------------------------
# Asset and identity registries
# ---------------------------------------------------------------------------

HOSTS = [
    "web-01", "web-02", "api-gateway", "auth-service",
    "db-prod-01", "db-prod-02", "db-replica",
    "k8s-control-plane", "k8s-worker-01", "k8s-worker-02",
    "secrets-vault", "ci-runner-01", "ci-runner-02",
    "monitoring", "log-aggregator",
]

STORAGE = [
    "s3-bucket-prod", "s3-bucket-backup", "gcs-bucket-pii",
    "rds-prod", "redis-cache", "kafka-cluster",
]

USERS = [
    "alice", "bob", "carol", "dave", "eve",
    "frank", "grace", "heidi", "ivan", "judy",
]

SERVICE_ACCOUNTS = [
    "sa-ci-deploy", "sa-k8s-controller", "sa-monitoring",
    "sa-backup", "sa-api-gateway", "sa-db-replicator",
]

ADMIN_ACCOUNTS = ["admin-alice", "admin-bob", "sre-carol"]

SENSITIVE_RESOURCES = [
    "secrets-vault", "rds-prod", "gcs-bucket-pii",
    "s3-bucket-backup", "k8s-control-plane",
]

ACTIONS = {
    "benign": [
        "login", "logout", "read_file", "list_objects",
        "api_call", "health_check", "deploy_artifact",
        "query_db", "cache_read", "log_write",
    ],
    "suspicious": [
        "privilege_escalation", "lateral_movement", "assume_role",
        "secret_access", "iam_modify", "admin_login",
        "bulk_data_read", "export_data", "disable_logging",
        "install_backdoor", "port_scan", "ssh_brute_force",
    ],
}


# ---------------------------------------------------------------------------
# Event builder helpers
# ---------------------------------------------------------------------------


def _ts(offset_minutes: float = 0.0) -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=offset_minutes)).isoformat()


def _event(
    identity: str,
    event_type: str,
    resource: str,
    *,
    success: bool = True,
    tenant_id: str = "acme-corp",
    offset_minutes: float = 0.0,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        "event_id": uuid.uuid4().hex,
        "identity": identity,
        "event_type": event_type,
        "resource": resource,
        "success": success,
        "tenant_id": tenant_id,
        "timestamp": _ts(offset_minutes),
        "source": "simulate_attack",
    }
    if extra:
        ev.update(extra)
    return ev


# ---------------------------------------------------------------------------
# Benign baseline generator
# ---------------------------------------------------------------------------


def generate_baseline(n: int = 200) -> List[Dict[str, Any]]:
    """
    Generate ``n`` realistic benign events to seed the baseline engine.
    Distributes actions realistically across users, hosts, and time.
    """
    events = []
    for i in range(n):
        identity = random.choice(USERS + SERVICE_ACCOUNTS)
        action = random.choice(ACTIONS["benign"])
        resource = random.choice(HOSTS + STORAGE)
        offset = -random.uniform(0, 480)  # up to 8 hours ago
        events.append(
            _event(identity, action, resource, offset_minutes=offset)
        )
    return events


# ---------------------------------------------------------------------------
# Attack scenario generators
# ---------------------------------------------------------------------------


@dataclass
class AttackScenario:
    """A named multi-stage attack event sequence."""
    name: str
    description: str
    events: List[Dict[str, Any]] = field(default_factory=list)

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(e, default=str) for e in self.events)


def scenario_credential_stuffing(
    target_user: Optional[str] = None,
    attempt_count: int = 50,
) -> AttackScenario:
    """
    Stage 1: Mass failed logins from one identity
    Stage 2: Successful login after credential found
    Stage 3: Rapid resource enumeration post-compromise
    """
    attacker = target_user or random.choice(USERS)
    events: List[Dict[str, Any]] = []

    # Stage 1: brute force
    for i in range(attempt_count):
        events.append(_event(
            attacker, "login", "auth-service",
            success=False, offset_minutes=-5 + i * 0.05,
            extra={"attempt": i + 1, "stage": "credential_stuffing"},
        ))

    # Stage 2: success
    events.append(_event(
        attacker, "login", "auth-service",
        success=True, offset_minutes=0,
        extra={"stage": "initial_access"},
    ))

    # Stage 3: enumeration
    for resource in random.sample(HOSTS + STORAGE, k=8):
        events.append(_event(
            attacker, "api_call", resource,
            offset_minutes=random.uniform(0, 5),
            extra={"stage": "reconnaissance"},
        ))

    return AttackScenario(
        name="credential_stuffing",
        description=f"Credential stuffing attack by {attacker} → {attempt_count} attempts",
        events=events,
    )


def scenario_lateral_movement(
    entry_host: Optional[str] = None,
) -> AttackScenario:
    """
    Stage 1: Compromise an initial host
    Stage 2: Enumerate service account credentials
    Stage 3: Hop to adjacent hosts using stolen credentials
    Stage 4: Reach a sensitive target
    """
    sa = random.choice(SERVICE_ACCOUNTS)
    chain = [entry_host or "web-01"]
    visited: set = {chain[0]}
    events: List[Dict[str, Any]] = []
    t = 0.0

    # Stage 1: Initial foothold
    events.append(_event(sa, "admin_login", chain[0], offset_minutes=t,
                         extra={"stage": "initial_foothold"}))
    t += 0.5

    # Stage 2: Credential harvest
    events.append(_event(sa, "secret_access", "secrets-vault", offset_minutes=t,
                         extra={"stage": "credential_harvest"}))
    t += 0.2

    # Stage 3: Lateral hops
    available = [h for h in HOSTS if h not in visited]
    for _ in range(random.randint(3, 6)):
        if not available:
            break
        next_host = random.choice(available)
        available.remove(next_host)
        visited.add(next_host)
        chain.append(next_host)
        events.append(_event(sa, "lateral_movement", next_host, offset_minutes=t,
                             extra={"stage": "lateral_movement", "via": chain[-2]}))
        t += random.uniform(0.3, 1.5)

    # Stage 4: Reach sensitive target
    target = random.choice(SENSITIVE_RESOURCES)
    events.append(_event(sa, "bulk_data_read", target, offset_minutes=t,
                         extra={"stage": "objective", "chain": chain}))

    return AttackScenario(
        name="lateral_movement",
        description=f"Lateral movement: {' → '.join(chain)} → {target}",
        events=events,
    )


def scenario_privilege_escalation(
    victim: Optional[str] = None,
) -> AttackScenario:
    """
    Stage 1: Normal low-priv activity (cover)
    Stage 2: Exploit misconfigured IAM role
    Stage 3: Assume admin role
    Stage 4: High-value resource access
    """
    user = victim or random.choice(USERS)
    events: List[Dict[str, Any]] = []
    t = -10.0

    # Stage 1: Cover traffic
    for _ in range(5):
        events.append(_event(user, random.choice(ACTIONS["benign"]),
                             random.choice(HOSTS[:5]), offset_minutes=t,
                             extra={"stage": "normal_activity"}))
        t += random.uniform(0.5, 2.0)

    t = 0.0
    # Stage 2: IAM misconfiguration exploit
    events.append(_event(user, "iam_modify", "auth-service", offset_minutes=t,
                         extra={"stage": "iam_exploit", "target_role": "admin"}))
    t += 0.3

    # Stage 3: Role assumption
    events.append(_event(user, "assume_role", "auth-service", offset_minutes=t,
                         extra={"stage": "privilege_escalation", "assumed_role": "AdminRole"}))
    t += 0.2

    # Stage 4: Admin actions
    for resource in SENSITIVE_RESOURCES:
        events.append(_event(user, "secret_access", resource, offset_minutes=t,
                             extra={"stage": "post_escalation"}))
        t += random.uniform(0.1, 0.5)

    return AttackScenario(
        name="privilege_escalation",
        description=f"Privilege escalation by {user} → AdminRole",
        events=events,
    )


def scenario_data_exfiltration(
    actor: Optional[str] = None,
) -> AttackScenario:
    """
    Stage 1: Establish persistence
    Stage 2: Enumerate data stores
    Stage 3: Bulk read sensitive data
    Stage 4: Disable logging
    Stage 5: Export
    """
    actor = actor or random.choice(SERVICE_ACCOUNTS)
    events: List[Dict[str, Any]] = []
    t = 0.0

    events.append(_event(actor, "admin_login", "api-gateway", offset_minutes=t,
                         extra={"stage": "persistence"}))
    t += 0.5

    for resource in STORAGE:
        events.append(_event(actor, "list_objects", resource, offset_minutes=t,
                             extra={"stage": "enumeration"}))
        t += 0.1

    events.append(_event(actor, "disable_logging", "log-aggregator", offset_minutes=t,
                         extra={"stage": "defense_evasion"}))
    t += 0.2

    for resource in SENSITIVE_RESOURCES:
        events.append(_event(actor, "bulk_data_read", resource, offset_minutes=t,
                             extra={"stage": "collection", "bytes_read": random.randint(100_000, 10_000_000)}))
        t += random.uniform(0.3, 1.0)

    events.append(_event(actor, "export_data", "s3-bucket-backup", offset_minutes=t,
                         extra={"stage": "exfiltration"}))

    return AttackScenario(
        name="data_exfiltration",
        description=f"Data exfiltration by {actor}",
        events=events,
    )


def scenario_insider_threat(
    insider: Optional[str] = None,
) -> AttackScenario:
    """
    Insider accesses unusual resources outside normal working hours.
    Subtle — designed to test entropy-based and peer-deviation detectors.
    """
    insider = insider or random.choice(USERS)
    events: List[Dict[str, Any]] = []
    t = 0.0

    # Off-hours access (02:00 UTC)
    off_hours_ts = datetime.now(timezone.utc).replace(hour=2, minute=0)

    for resource in SENSITIVE_RESOURCES + random.sample(STORAGE, k=3):
        events.append({
            "event_id": uuid.uuid4().hex,
            "identity": insider,
            "event_type": "read_file",
            "resource": resource,
            "success": True,
            "tenant_id": "acme-corp",
            "timestamp": (off_hours_ts + timedelta(minutes=t)).isoformat(),
            "source": "simulate_attack",
            "stage": "insider_exfil",
        })
        t += random.uniform(1, 5)

    return AttackScenario(
        name="insider_threat",
        description=f"Insider threat: {insider} accessing sensitive data off-hours",
        events=events,
    )


def scenario_ransomware_prep(
    entry: Optional[str] = None,
) -> AttackScenario:
    """
    Ransomware preparation:
    Recon → C2 install → credential dump → spread → encryption staging
    """
    actor = entry or random.choice(SERVICE_ACCOUNTS)
    events: List[Dict[str, Any]] = []
    t = 0.0

    # Recon
    for h in random.sample(HOSTS, k=5):
        events.append(_event(actor, "port_scan", h, offset_minutes=t,
                             extra={"stage": "recon"}))
        t += 0.1

    # Credential dump
    events.append(_event(actor, "secret_access", "secrets-vault", offset_minutes=t,
                         extra={"stage": "credential_dump"}))
    t += 0.3

    # Lateral spread
    for h in random.sample(HOSTS, k=6):
        events.append(_event(actor, "install_backdoor", h, offset_minutes=t,
                             extra={"stage": "persistence_install"}))
        t += random.uniform(0.2, 0.8)

    # Encryption staging
    for store in STORAGE:
        events.append(_event(actor, "bulk_data_read", store, offset_minutes=t,
                             extra={"stage": "pre_encryption_staging"}))
        t += 0.2

    return AttackScenario(
        name="ransomware_prep",
        description=f"Ransomware preparation by {actor}",
        events=events,
    )


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS: Dict[str, Callable[[], AttackScenario]] = {
    "credential_stuffing":  scenario_credential_stuffing,
    "lateral_movement":     scenario_lateral_movement,
    "privilege_escalation": scenario_privilege_escalation,
    "data_exfiltration":    scenario_data_exfiltration,
    "insider_threat":       scenario_insider_threat,
    "ransomware_prep":      scenario_ransomware_prep,
}


# ---------------------------------------------------------------------------
# AttackSimulator
# ---------------------------------------------------------------------------


class AttackSimulator:
    """
    Programmatic attack event generator.

    Usage
    -----
    ::

        sim = AttackSimulator(tenant_id="acme-corp", seed=42)

        # Generate baseline + specific scenario
        events = sim.generate(
            scenario="lateral_movement",
            baseline_events=200,
        )

        # Generate all scenarios
        all_events = sim.generate_all(baseline_events=100)
    """

    def __init__(
        self,
        *,
        tenant_id: str = "acme-corp",
        seed: Optional[int] = None,
    ) -> None:
        self.tenant_id = tenant_id
        if seed is not None:
            random.seed(seed)

    def generate_event(self) -> Dict[str, Any]:
        """Generate a single random benign event."""
        return _event(
            random.choice(USERS + SERVICE_ACCOUNTS),
            random.choice(ACTIONS["benign"]),
            random.choice(HOSTS + STORAGE),
            tenant_id=self.tenant_id,
        )

    def generate(
        self,
        scenario: str,
        *,
        baseline_events: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Generate events for a named scenario, optionally prepended with
        ``baseline_events`` benign events for model seeding.
        """
        if scenario not in SCENARIOS:
            raise ValueError(
                f"Unknown scenario '{scenario}'. "
                f"Available: {sorted(SCENARIOS.keys())}"
            )

        events: List[Dict[str, Any]] = []

        if baseline_events > 0:
            events.extend(generate_baseline(baseline_events))

        attack = SCENARIOS[scenario]()
        events.extend(attack.events)

        logger.info(
            "Attack scenario generated",
            extra={
                "scenario": scenario,
                "baseline_events": baseline_events,
                "attack_events": len(attack.events),
                "total": len(events),
                "description": attack.description,
            },
        )
        return events

    def generate_all(
        self, *, baseline_events: int = 100
    ) -> List[Dict[str, Any]]:
        """Generate events for every registered scenario."""
        events: List[Dict[str, Any]] = generate_baseline(baseline_events)
        for name, factory in SCENARIOS.items():
            scenario = factory()
            events.extend(scenario.events)
            logger.info(
                "Scenario added",
                extra={"scenario": name, "events": len(scenario.events)},
            )
        return events


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Hollow Purple red-team attack event simulator"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--scenario",
        choices=sorted(SCENARIOS.keys()),
        help="Run a specific named attack scenario",
    )
    group.add_argument(
        "--all-scenarios",
        action="store_true",
        help="Run all attack scenarios",
    )
    parser.add_argument(
        "--count", type=int, default=10,
        help="Number of random events (when no scenario specified)",
    )
    parser.add_argument(
        "--baseline-events", type=int, default=0,
        help="Prepend N benign baseline events before the attack",
    )
    parser.add_argument(
        "--output", type=str, default=None,
        help="Write events to a JSON-lines file instead of stdout",
    )
    parser.add_argument(
        "--seed", type=int, default=None,
        help="Random seed for reproducible output",
    )
    parser.add_argument(
        "--list", action="store_true",
        help="List available scenarios and exit",
    )
    return parser.parse_args()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    args = _parse_args()

    if args.list:
        print("\nAvailable attack scenarios:\n")
        for name, fn in SCENARIOS.items():
            scenario = fn()
            print(f"  {name:<25} — {scenario.description}")
        print()
        sys.exit(0)

    sim = AttackSimulator(seed=args.seed)

    if args.scenario:
        events = sim.generate(args.scenario, baseline_events=args.baseline_events)
    elif args.all_scenarios:
        events = sim.generate_all(baseline_events=args.baseline_events)
    else:
        events = [sim.generate_event() for _ in range(args.count)]

    lines = [json.dumps(e, default=str) for e in events]

    if args.output:
        with open(args.output, "w") as f:
            f.write("\n".join(lines) + "\n")
        print(f"Wrote {len(events)} events to {args.output}", file=sys.stderr)
    else:
        print("\n".join(lines))
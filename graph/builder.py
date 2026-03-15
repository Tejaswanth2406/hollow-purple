"""
Graph Builder — Hollow Purple Phase 2 (Adversarially Hardened)

Phase 1 production fixes retained:
  FIX 1 — Edge lifecycle tracking (born_at, last_seen, is_active, revoked_at, observation_count)
  FIX 2 — Derived identity privilege via graph closure (active subgraph only)
  FIX 3 — Role inheritance expansion (ROLE_INHERITANCE table)
  FIX 4 — Resource privilege from ResourceType (no substring heuristics)

Phase 2 hardening:
  FIX 1 (upgrade) — Policy-based TTL per edge type (mark_decayed_edges)
                    trust=30d, permission=180d, inherits=365d, accessed=90d
  FIX 2 (upgrade) — DAG cycle prevention on role inheritance
  FIX 3 (upgrade) — Full privilege propagation through trust chains (iterative convergence)
  BONUS           — Canonical SA name resolution (FQDN→short form dedup)
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional, NamedTuple

import networkx as nx

from core.models import (
    BehaviorEvent, IdentityNode, RoleNode, ResourceNode,
    PermissionEdge, TrustEdge,
    IdentityType, ResourceType, EdgeType,
)

log = logging.getLogger(__name__)

# Policy-based TTL per edge type — privilege must be periodically reinforced
EDGE_TTL = {
    "permission": timedelta(days=180),
    "inherits":   timedelta(days=365),
    "trust":      timedelta(days=30),
    "accessed":   timedelta(days=90),
}

TRUST_ACTIONS = {
    "GenerateAccessToken", "GenerateIdToken", "SignJwt", "SignBlob", "ActAs",
    "AssumeRole",
}

RESOURCE_TYPE_MAP = [
    ("buckets/",       ResourceType.BUCKET),
    ("datasets/",      ResourceType.DATASET),
    ("secrets/",       ResourceType.SECRET),
    ("functions/",     ResourceType.FUNCTION),
    ("instances/",     ResourceType.VM),
    ("topics/",        ResourceType.TOPIC),
    ("subscriptions/", ResourceType.SUBSCRIPTION),
    ("projects/",      ResourceType.PROJECT),
]

ROLE_INHERITANCE: dict[str, list[str]] = {
    "roles/owner": [
        "roles/editor",
        "roles/viewer",
        "roles/resourcemanager.projectIamAdmin",
        "roles/iam.roleAdmin",
    ],
    "roles/editor": [
        "roles/viewer",
        "roles/storage.objectAdmin",
    ],
    "roles/resourcemanager.projectIamAdmin": [
        "roles/iam.roleAdmin",
    ],
    "roles/iam.serviceAccountAdmin": [
        "roles/iam.serviceAccountUser",
    ],
    "roles/iam.roleAdmin": [
        "roles/viewer",
    ],
    "roles/storage.objectAdmin": [
        "roles/storage.objectViewer",
    ],
}

_RESOURCE_PRIV = {
    ResourceType.SECRET:       8,
    ResourceType.VM:           5,
    ResourceType.BUCKET:       4,
    ResourceType.DATASET:      4,
    ResourceType.FUNCTION:     5,
    ResourceType.PROJECT:      6,
    ResourceType.TOPIC:        3,
    ResourceType.SUBSCRIPTION: 3,
    ResourceType.UNKNOWN:      2,
}


def _infer_identity_type(principal: str) -> IdentityType:
    if principal.startswith("serviceAccount:"):
        return IdentityType.SERVICE_ACCOUNT
    elif principal.startswith("group:"):
        return IdentityType.GROUP
    elif principal.startswith("domain:"):
        return IdentityType.DOMAIN
    return IdentityType.USER


def _infer_resource_type(resource_name: str) -> ResourceType:
    for pattern, rtype in RESOURCE_TYPE_MAP:
        if pattern in resource_name:
            return rtype
    return ResourceType.UNKNOWN


def _extract_project(resource_name: str, project_id: str) -> str:
    if "projects/" in resource_name:
        parts = resource_name.split("projects/")
        if len(parts) > 1:
            return parts[1].split("/")[0]
    return project_id


class EdgeLifecycle(NamedTuple):
    born_at:           datetime
    last_seen:         datetime
    is_active:         bool
    revoked_at:        Optional[datetime]
    observation_count: int = 1


class GraphBuilder:
    """
    Builds and maintains a temporal identity-permission graph.
    MultiDiGraph supports multiple edge types between the same node pair.

    Node key conventions:
      identity:{principal}
      role:{role_name}
      resource:{resource_path}

    Public API:
      ingest_event(event)
      ingest_batch(events)
      revoke_edge(src, dst, edge_type, ts)
      get_effective_privilege(identity_key) -> int
      derive_privilege_closure()
      mark_decayed_edges(now)
      invalidate_cache()
      stats() -> dict
    """

    def __init__(self, privilege_levels: dict[str, int] = None):
        self.G: nx.MultiDiGraph = nx.MultiDiGraph()
        self.privilege_levels   = privilege_levels or {}

        self._identity_cache:  dict[str, IdentityNode]  = {}
        self._role_cache:      dict[str, RoleNode]       = {}
        self._resource_cache:  dict[str, ResourceNode]   = {}
        self._edge_count = 0

        self._edge_lifecycle: dict[tuple, EdgeLifecycle] = {}
        self._dirty_identities: set[str]                 = set()
        self._effective_privilege: dict[str, int]        = {}
        self._cache_version: int                         = 0

    # ------------------------------------------------------------------
    # Privilege lookup
    # ------------------------------------------------------------------

    def _get_privilege(self, role: str) -> int:
        if not role:
            return 1
        if role in self.privilege_levels:
            return self.privilege_levels[role]
        r = role.lower()
        if "owner"  in r: return 10
        if "projectiamadmin" in r or "roleadmin" in r: return 9
        if "admin"  in r: return 8
        if "editor" in r: return 6
        if "viewer" in r or "reader" in r: return 2
        if "browser" in r: return 1
        return 3

    # ------------------------------------------------------------------
    # Node constructors
    # ------------------------------------------------------------------

    def _ensure_identity(self, principal: str, ts: datetime) -> IdentityNode:
        key = f"identity:{principal}"
        if principal not in self._identity_cache:
            node = IdentityNode(
                identity=principal,
                identity_type=_infer_identity_type(principal),
                first_seen=ts,
                last_seen=ts,
                privilege_level=0,
            )
            self._identity_cache[principal] = node
            self.G.add_node(key, type="identity", data=node, privilege_level=0)
            self._dirty_identities.add(key)
        else:
            node = self._identity_cache[principal]
            if ts > node.last_seen:
                node.last_seen = ts
        return node

    def _ensure_role(self, role: str) -> RoleNode:
        if role not in self._role_cache:
            priv = self._get_privilege(role)
            node = RoleNode(role=role, privilege_level=priv,
                            is_custom=not role.startswith("roles/"))
            self._role_cache[role] = node
            self.G.add_node(node.node_key, type="role", data=node, privilege_level=priv)
            self._expand_role_inheritance(role, node.node_key)
        return self._role_cache[role]

    def _expand_role_inheritance(self, role: str, role_key: str) -> None:
        """
        Add structural 'inherits' edges. DAG invariant enforced — cycles rejected.
        A cycle causes privilege inflation via unbounded closure; prevent at insert time.
        """
        for implied_role in ROLE_INHERITANCE.get(role, []):
            implied_node = self._ensure_role(implied_role)
            ikey = implied_node.node_key
            existing = self.G.get_edge_data(role_key, ikey) or {}
            has_inherit = any(v.get("edge_type") == "inherits" for v in existing.values())
            if not has_inherit:
                self.G.add_edge(
                    role_key, ikey,
                    edge_type="inherits",
                    edge_data=None,
                    born_at=datetime.now(timezone.utc),
                    last_seen=datetime.now(timezone.utc),
                    is_active=True,
                    revoked_at=None,
                    observation_count=1,
                )
                # DAG check — remove edge immediately if it creates a cycle
                role_nodes     = [n for n in self.G.nodes() if n.startswith("role:")]
                role_subgraph  = self.G.subgraph(role_nodes)
                if not nx.is_directed_acyclic_graph(role_subgraph):
                    self.G.remove_edge(role_key, ikey)
                    log.warning("builder.inheritance_cycle_rejected",
                                parent=role_key, child=ikey)

    def _ensure_resource(self, resource_name: str, project: str) -> ResourceNode:
        if resource_name not in self._resource_cache:
            rtype = _infer_resource_type(resource_name)
            priv  = _RESOURCE_PRIV.get(rtype, 2)
            node  = ResourceNode(resource_name=resource_name,
                                 resource_type=rtype, project=project,
                                 privilege_level=priv)
            self._resource_cache[resource_name] = node
            self.G.add_node(node.node_key, type="resource", data=node, privilege_level=priv)
        return self._resource_cache[resource_name]

    # ------------------------------------------------------------------
    # Edge lifecycle
    # ------------------------------------------------------------------

    def _add_edge_with_lifecycle(
        self, src: str, dst: str, edge_type: str,
        edge_data, ts: datetime, edge_id: str,
    ) -> None:
        lk = (src, dst, edge_type)
        if lk in self._edge_lifecycle:
            old        = self._edge_lifecycle[lk]
            new_last   = max(old.last_seen, ts)
            was_revoked = not old.is_active or old.revoked_at is not None
            if was_revoked:
                new_lc = EdgeLifecycle(
                    born_at=ts, last_seen=ts, is_active=True,
                    revoked_at=None, observation_count=old.observation_count + 1,
                )
            else:
                new_lc = EdgeLifecycle(
                    born_at=old.born_at, last_seen=new_last,
                    is_active=old.is_active, revoked_at=old.revoked_at,
                    observation_count=old.observation_count + 1,
                )
            self._edge_lifecycle[lk] = new_lc
            edges = self.G.get_edge_data(src, dst) or {}
            for k, v in edges.items():
                if v.get("edge_type") == edge_type:
                    if was_revoked:
                        v["born_at"] = ts; v["last_seen"] = ts
                        v["is_active"] = True; v["revoked_at"] = None
                    else:
                        v["last_seen"] = new_last
                    v["observation_count"] = new_lc.observation_count
                    break
            if was_revoked:
                self._dirty_identities.add(src)
                self._cache_version += 1
        else:
            self._edge_lifecycle[lk] = EdgeLifecycle(
                born_at=ts, last_seen=ts, is_active=True,
                revoked_at=None, observation_count=1,
            )
            self.G.add_edge(
                src, dst,
                edge_type=edge_type, edge_data=edge_data, key=edge_id,
                born_at=ts, last_seen=ts, is_active=True,
                revoked_at=None, observation_count=1,
            )
            self._edge_count    += 1
            self._cache_version += 1
            if self.G.nodes.get(src, {}).get("type") == "identity":
                self._dirty_identities.add(src)

    def revoke_edge(self, src: str, dst: str, edge_type: str, ts: datetime) -> None:
        lk = (src, dst, edge_type)
        if lk in self._edge_lifecycle:
            old = self._edge_lifecycle[lk]
            self._edge_lifecycle[lk] = EdgeLifecycle(
                born_at=old.born_at, last_seen=old.last_seen,
                is_active=False, revoked_at=ts,
                observation_count=old.observation_count,
            )
            edges = self.G.get_edge_data(src, dst) or {}
            for k, v in edges.items():
                if v.get("edge_type") == edge_type:
                    v["is_active"] = False; v["revoked_at"] = ts
                    break
            self._dirty_identities.add(src)
            self._cache_version += 1

    def invalidate_cache(self) -> None:
        self._cache_version += 1

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_event(self, event: BehaviorEvent) -> None:
        if not event.success:
            return
        ts           = event.timestamp
        method_short = event.metadata.get(
            "method_short",
            event.action.split(".")[-1].split("/")[-1]
        )
        identity_node = self._ensure_identity(event.principal, ts)
        id_key        = identity_node.node_key

        if method_short in TRUST_ACTIONS:
            if "serviceAccounts/" in event.resource:
                target_sa = "serviceAccount:" + event.resource.split("serviceAccounts/")[-1]
                # Canonical SA resolution: strip @domain suffix if short form exists
                resolved_sa = target_sa
                if "@" in target_sa:
                    short_form = target_sa.split("@")[0]
                    if short_form in self._identity_cache:
                        resolved_sa = short_form
                target_node = self._ensure_identity(resolved_sa, ts)
                edge = TrustEdge(
                    source_key=id_key, target_key=target_node.node_key,
                    trust_mechanism=method_short, observed_at=ts,
                    metadata={"action": event.action, "project": event.project},
                )
                self._add_edge_with_lifecycle(
                    id_key, target_node.node_key,
                    EdgeType.TRUST.value, edge, ts, edge.edge_id,
                )
            return

        if event.role:
            role_node     = self._ensure_role(event.role)
            resource_node = self._ensure_resource(
                event.resource,
                _extract_project(event.resource, event.project),
            )
            perm_edge = PermissionEdge(
                source_key=id_key, target_key=role_node.node_key,
                role=event.role, observed_at=ts,
                metadata={"action": event.action, "project": event.project},
            )
            self._add_edge_with_lifecycle(
                id_key, role_node.node_key,
                EdgeType.PERMISSION.value, perm_edge, ts, perm_edge.edge_id,
            )
            res_edge = PermissionEdge(
                source_key=role_node.node_key, target_key=resource_node.node_key,
                role=event.role, observed_at=ts,
                metadata={"action": event.action},
            )
            self._add_edge_with_lifecycle(
                role_node.node_key, resource_node.node_key,
                EdgeType.PERMISSION.value, res_edge, ts, res_edge.edge_id,
            )
            if role_node.privilege_level > identity_node.privilege_level:
                identity_node.privilege_level = role_node.privilege_level
                self.G.nodes[id_key]["privilege_level"] = role_node.privilege_level
        else:
            resource_node = self._ensure_resource(
                event.resource,
                _extract_project(event.resource, event.project),
            )
            access_edge = PermissionEdge(
                source_key=id_key, target_key=resource_node.node_key,
                role=None,
                observed_at=ts,
            )
            self._add_edge_with_lifecycle(
                id_key, resource_node.node_key,
                EdgeType.ACCESSED.value, access_edge, ts, access_edge.edge_id,
            )

    def ingest_batch(self, events: list[BehaviorEvent]) -> None:
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        for event in sorted_events:
            self.ingest_event(event)
        self.derive_privilege_closure()

    # ------------------------------------------------------------------
    # Privilege closure
    # ------------------------------------------------------------------

    def derive_privilege_closure(self) -> None:
        """
        Two-pass privilege computation:
          Pass 1: max role privilege via active subgraph for each dirty identity.
          Pass 2: propagate through trust chains (impersonator inherits full target priv).
                  Iterates until convergence (handles multi-hop trust).
        """
        active_G = self._active_subgraph_snapshot()

        def _max_role_priv_from(identity_key: str) -> int:
            if identity_key not in active_G:
                return 0
            max_priv = 0
            try:
                for desc in nx.descendants(active_G, identity_key):
                    if self.G.nodes.get(desc, {}).get("type") != "role":
                        continue
                    nd = self.G.nodes.get(desc, {}).get("data")
                    if nd:
                        p = getattr(nd, "privilege_level", 0)
                        if p > max_priv:
                            max_priv = p
            except (nx.NetworkXError, Exception):
                pass
            return max_priv

        # Pass 1: own role privilege
        for identity_key in list(self._dirty_identities):
            self._effective_privilege[identity_key] = _max_role_priv_from(identity_key)

        # Pass 2: trust propagation — iterate to convergence
        changed       = True
        max_iters     = 10
        iteration     = 0
        while changed and iteration < max_iters:
            changed   = False
            iteration += 1
            for src, dst, data in active_G.edges(data=True):
                if data.get("edge_type") != "trust":
                    continue
                if self.G.nodes.get(src, {}).get("type") != "identity":
                    continue
                if self.G.nodes.get(dst, {}).get("type") != "identity":
                    continue
                if dst not in self._effective_privilege:
                    self._effective_privilege[dst] = _max_role_priv_from(dst)
                target_priv  = self._effective_privilege[dst]
                current_priv = self._effective_privilege.get(src, 0)
                if target_priv > current_priv:
                    self._effective_privilege[src] = target_priv
                    changed = True

        # Write back to IdentityNode
        all_identities = (set(self._dirty_identities) |
                          set(self._effective_privilege.keys()))
        for identity_key in all_identities:
            node_obj = self.G.nodes.get(identity_key, {}).get("data")
            if node_obj is not None:
                node_obj.effective_privilege = self._effective_privilege.get(identity_key, 0)

        self._dirty_identities.clear()

    def get_effective_privilege(self, identity_key: str) -> int:
        if identity_key in self._dirty_identities:
            self.derive_privilege_closure()
        return self._effective_privilege.get(identity_key, 0)

    # ------------------------------------------------------------------
    # Active subgraph helpers
    # ------------------------------------------------------------------

    def _active_subgraph_snapshot(self) -> nx.DiGraph:
        """DiGraph of currently active edges (is_active=True, no time filter)."""
        G_active = nx.DiGraph()
        G_active.add_nodes_from(self.G.nodes(data=True))
        for src, dst, data in self.G.edges(data=True):
            if data.get("is_active", True):
                G_active.add_edge(src, dst, **data)
        return G_active

    def _active_subgraph_at(self, current_time: datetime) -> nx.DiGraph:
        """DiGraph of edges active AT current_time (temporal filter)."""
        G_active = nx.DiGraph()
        G_active.add_nodes_from(self.G.nodes(data=True))
        for src, dst, data in self.G.edges(data=True):
            born_at    = data.get("born_at")
            revoked_at = data.get("revoked_at")
            is_active  = data.get("is_active", True)
            if born_at    is not None and born_at    >  current_time: continue
            if revoked_at is not None and revoked_at <= current_time: continue
            if not is_active and revoked_at is None: continue
            G_active.add_edge(src, dst, **data)
        return G_active

    # ------------------------------------------------------------------
    # Backward-compatible query methods
    # ------------------------------------------------------------------

    def get_identity_paths(self, identity: str, max_hops: int = 3) -> list[list[str]]:
        identity_key = f"identity:{identity}"
        if identity_key not in self.G:
            return []
        paths = []
        for target in self.G.nodes():
            if target == identity_key:
                continue
            for path in nx.all_simple_paths(self.G, identity_key, target, cutoff=max_hops):
                paths.append(path)
        return paths

    def get_reachability(self, identity: str, min_privilege: int = 7) -> list[str]:
        identity_key = f"identity:{identity}"
        if identity_key not in self.G:
            return []
        reachable = []
        try:
            for node_key in nx.descendants(self.G, identity_key):
                node_data = self.G.nodes[node_key].get("data")
                if node_data and getattr(node_data, "privilege_level", 0) >= min_privilege:
                    reachable.append(node_key)
        except nx.NetworkXError:
            pass
        return reachable

    def stats(self) -> dict:
        node_types = defaultdict(int)
        for _, data in self.G.nodes(data=True):
            node_types[data.get("type", "unknown")] += 1
        edge_types = defaultdict(int)
        for _, _, data in self.G.edges(data=True):
            edge_types[data.get("edge_type", "unknown")] += 1
        return {
            "total_nodes":         self.G.number_of_nodes(),
            "total_edges":         self.G.number_of_edges(),
            "node_types":          dict(node_types),
            "edge_types":          dict(edge_types),
            "identities":          len(self._identity_cache),
            "roles":               len(self._role_cache),
            "resources":           len(self._resource_cache),
            "effective_privilege": dict(self._effective_privilege),
        }

    def mark_decayed_edges(self, now: datetime) -> None:
        """
        Policy-based TTL per edge type. Edges whose last_seen + TTL < now
        are marked inactive. Privilege must be periodically reinforced.
        """
        for src, dst, data in self.G.edges(data=True):
            edge_type = data.get("edge_type", "")
            lk        = (src, dst, edge_type)
            last_seen = data.get("last_seen")
            if not last_seen or not data.get("is_active", True):
                continue
            ttl = EDGE_TTL.get(edge_type, timedelta(days=90))
            if last_seen + ttl < now:
                data["is_active"]  = False
                data["revoked_at"] = now
                if lk in self._edge_lifecycle:
                    old_lc = self._edge_lifecycle[lk]
                    self._edge_lifecycle[lk] = EdgeLifecycle(
                        born_at=old_lc.born_at, last_seen=old_lc.last_seen,
                        is_active=False, revoked_at=now,
                        observation_count=old_lc.observation_count,
                    )
                if self.G.nodes.get(src, {}).get("type") == "identity":
                    self._dirty_identities.add(src)
        self._cache_version += 1

    def to_dict(self) -> dict:
        nodes = []
        for node_key, data in self.G.nodes(data=True):
            node_obj  = data.get("data")
            node_type = data.get("type", "unknown")
            priv      = getattr(node_obj, "privilege_level", 0) if node_obj else 0
            eff_p     = self._effective_privilege.get(node_key, priv)
            label     = (
                getattr(node_obj, "identity",      None) or
                getattr(node_obj, "role",          None) or
                getattr(node_obj, "resource_name", node_key)
            )
            nodes.append({
                "id":                  node_key,
                "type":                node_type,
                "label":               label.split(":")[-1] if ":" in label else label,
                "privilege_level":     priv,
                "effective_privilege": eff_p,
            })
        edges = []
        for src, dst, data in self.G.edges(data=True):
            edges.append({
                "source":     src,
                "target":     dst,
                "type":       data.get("edge_type", "unknown"),
                "born_at":    data["born_at"].isoformat() if data.get("born_at") else None,
                "is_active":  data.get("is_active", True),
                "revoked_at": data["revoked_at"].isoformat() if data.get("revoked_at") else None,
            })
        return {"nodes": nodes, "edges": edges}
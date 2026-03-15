from graph.graph_state import GraphState
from graph.exposure import compute_exposure, compute_blast_radius
from graph.pathfinder import find_attack_paths
from graph.closure import find_privilege_cycles, compute_strongly_connected_components


def compute_identity_risk(
    graph: GraphState,
    identity: str,
    depth: int = 6,
) -> dict:
    """
    Multi-factor risk score for a single identity.

    Factors:
    - Exposure breadth  (reachable node count, weighted by type)
    - Attack path count and total risk weight
    - Privilege cycle membership
    - Graph centrality (degree)
    - Blast radius critical nodes
    """
    exposure = compute_exposure(graph, identity)
    blast    = compute_blast_radius(graph, identity)
    paths    = find_attack_paths(graph, identity, depth=depth, min_risk=0.5)
    cycles   = find_privilege_cycles(graph)

    in_cycle = any(identity in c for c in cycles)

    # ── Component scores ────────────────────────────────────────────────

    max_nodes        = max(graph.node_count(), 1)
    exposure_score   = min(exposure["reachable_count"] / max(max_nodes * 0.1, 10), 1.0)
    weighted_score   = min(exposure["weighted_score"] / 50, 1.0)
    path_score       = min(len(paths) / 30, 1.0)
    critical_score   = min(len(blast["critical_nodes"]) / 10, 1.0)
    centrality_score = min(
        (graph.out_degree(identity) + graph.in_degree(identity)) / max(max_nodes * 0.05, 5),
        1.0,
    )
    cycle_penalty    = 0.25 if in_cycle else 0.0

    # ── Weighted aggregate ──────────────────────────────────────────────

    raw = (
        0.25 * exposure_score
      + 0.20 * weighted_score
      + 0.20 * path_score
      + 0.15 * critical_score
      + 0.10 * centrality_score
      + cycle_penalty
    )

    score = min(round(raw, 4), 1.0)

    # ── Risk tier ──────────────────────────────────────────────────────

    tier = (
        "CRITICAL" if score >= 0.80
        else "HIGH"     if score >= 0.60
        else "MEDIUM"   if score >= 0.35
        else "LOW"
    )

    return {
        "identity":        identity,
        "score":           score,
        "tier":            tier,
        "in_cycle":        in_cycle,
        "exposure_count":  exposure["reachable_count"],
        "critical_nodes":  blast["critical_nodes"],
        "top_paths":       paths[:10],
        "component_scores": {
            "exposure":    round(exposure_score, 4),
            "weighted":    round(weighted_score, 4),
            "paths":       round(path_score, 4),
            "critical":    round(critical_score, 4),
            "centrality":  round(centrality_score, 4),
            "cycle":       round(cycle_penalty, 4),
        },
    }


def compute_graph_wide_risk(graph: GraphState, top_n: int = 20) -> dict:
    """
    Scores every identity in the graph, returns ranked results.
    Includes graph-level structural metrics.
    """
    identities = [
        node_id
        for node_id, attrs in graph.all_nodes().items()
        if attrs.get("type") == "identity"
    ]

    scored = []
    for identity in identities:
        result = compute_identity_risk(graph, identity)
        scored.append(result)

    scored.sort(key=lambda x: x["score"], reverse=True)

    cycles      = find_privilege_cycles(graph)
    all_sccs    = compute_strongly_connected_components(graph)
    centrality  = graph.degree_centrality()
    top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "top_identities":       scored[:top_n],
        "total_identities":     len(identities),
        "privilege_cycles":     [list(c) for c in cycles],
        "cycle_count":          len(cycles),
        "scc_count":            len(all_sccs),
        "top_central_nodes":    top_central,
        "graph_node_count":     graph.node_count(),
        "graph_edge_count":     graph.edge_count(),
        "critical_identity_count": sum(1 for s in scored if s["tier"] == "CRITICAL"),
    }
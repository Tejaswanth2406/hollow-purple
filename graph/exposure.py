from collections import deque
import heapq
from graph.graph_state import GraphState


def find_attack_paths(
    graph: GraphState,
    start: str,
    depth: int = 6,
    min_risk: float = 0.0,
) -> list[dict]:
    """
    BFS path enumeration with risk-weight accumulation.
    Returns paths sorted by total risk (descending).
    """
    results: list[dict] = []
    queue: deque = deque()
    queue.append((start, [start], 0.0))

    while queue:
        node, path, risk = queue.popleft()

        if len(path) > depth:
            continue

        for neighbor, meta in graph.neighbors(node).items():
            if neighbor in path:      # no cycles in path
                continue

            edge_risk = meta.weight * meta.risk_multiplier
            new_risk  = risk + edge_risk
            new_path  = path + [neighbor]

            if new_risk >= min_risk:
                results.append({
                    "path":       new_path,
                    "risk":       round(new_risk, 4),
                    "length":     len(new_path),
                    "edge_types": _extract_edge_types(graph, new_path),
                })

            queue.append((neighbor, new_path, new_risk))

    results.sort(key=lambda x: x["risk"], reverse=True)
    return results


def find_shortest_attack_path(
    graph: GraphState,
    start: str,
    target: str,
) -> list[str] | None:
    """
    BFS shortest path from start to target.
    """
    queue  = deque([(start, [start])])
    seen   = {start}

    while queue:
        node, path = queue.popleft()
        for neighbor in graph.neighbors(node):
            if neighbor == target:
                return path + [neighbor]
            if neighbor not in seen:
                seen.add(neighbor)
                queue.append((neighbor, path + [neighbor]))

    return None


def find_paths_to_target(
    graph: GraphState,
    start: str,
    target: str,
    depth: int = 6,
) -> list[list[str]]:
    """
    All paths from start to target within depth limit.
    """
    results = []
    queue: deque = deque()
    queue.append((start, [start]))

    while queue:
        node, path = queue.popleft()
        if len(path) > depth:
            continue
        for neighbor in graph.neighbors(node):
            if neighbor in path:
                continue
            new_path = path + [neighbor]
            if neighbor == target:
                results.append(new_path)
            else:
                queue.append((neighbor, new_path))

    return results


def highest_risk_path(graph: GraphState, start: str, depth: int = 6) -> dict | None:
    """
    Returns the single highest-risk path from a given identity.
    """
    paths = find_attack_paths(graph, start, depth=depth)
    return paths[0] if paths else None


def _extract_edge_types(graph: GraphState, path: list[str]) -> list[str]:
    types = []
    for i in range(len(path) - 1):
        meta = graph.neighbors(path[i]).get(path[i + 1])
        types.append(meta.edge_type if meta else "unknown")
    return types
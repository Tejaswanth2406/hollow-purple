"""
Probabilistic Attack Graph Engine

This module implements probabilistic reasoning for cyber attack prediction using
Bayesian networks, Markov chains, and probabilistic graphical models to model
attack likelihood and propagation through the cyber defense graph.
"""

import numpy as np
import pandas as pd
from typing import Dict, List, Tuple, Optional, Any, Set, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import networkx as nx
from collections import defaultdict, deque
import heapq
from scipy.stats import beta, norm
import json

logger = logging.getLogger(__name__)

@dataclass
class ProbabilisticNode:
    """Node in the probabilistic attack graph"""
    node_id: str
    node_type: str
    base_vulnerability: float  # Base probability of compromise
    current_probability: float = 0.0
    evidence_count: int = 0
    last_updated: datetime = field(default_factory=datetime.now)

    # Conditional probability distributions
    parents: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)
    cpd: Dict[Tuple, float] = field(default_factory=dict)  # Conditional probability distribution

@dataclass
class ProbabilisticEdge:
    """Edge in the probabilistic attack graph"""
    source_id: str
    target_id: str
    edge_type: str
    success_probability: float  # P(success | source_compromised)
    detection_probability: float  # P(detection | attempt)
    cost: float  # Attacker effort required
    prerequisites: List[str] = field(default_factory=list)  # Required conditions

@dataclass
class AttackHypothesis:
    """Hypothesis about an attack scenario"""
    hypothesis_id: str
    description: str
    prior_probability: float
    current_probability: float
    supporting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    conflicting_evidence: List[Dict[str, Any]] = field(default_factory=list)
    predicted_outcomes: List[Dict[str, Any]] = field(default_factory=list)

class BayesianAttackGraph:
    """
    Bayesian network representation of cyber attack possibilities
    """

    def __init__(self):
        self.nodes: Dict[str, ProbabilisticNode] = {}
        self.edges: Dict[Tuple[str, str], ProbabilisticEdge] = {}
        self.graph = nx.DiGraph()

        # Evidence tracking
        self.evidence_log: List[Dict[str, Any]] = []

        # Attack hypotheses
        self.hypotheses: Dict[str, AttackHypothesis] = {}

        # Markov chain for temporal evolution
        self.transition_matrix: Dict[Tuple[str, str], float] = {}

    def add_node(self, node: ProbabilisticNode):
        """Add a node to the probabilistic graph"""
        self.nodes[node.node_id] = node
        self.graph.add_node(node.node_id, **vars(node))

    def add_edge(self, edge: ProbabilisticEdge):
        """Add an edge to the probabilistic graph"""
        key = (edge.source_id, edge.target_id)
        self.edges[key] = edge

        self.graph.add_edge(edge.source_id, edge.target_id, **vars(edge))

        # Update node relationships
        if edge.source_id in self.nodes:
            self.nodes[edge.source_id].children.append(edge.target_id)
        if edge.target_id in self.nodes:
            self.nodes[edge.target_id].parents.append(edge.source_id)

    def update_node_probability(self, node_id: str, new_probability: float,
                              evidence: Optional[Dict[str, Any]] = None):
        """Update the probability of a node being compromised"""
        if node_id not in self.nodes:
            return

        node = self.nodes[node_id]
        old_probability = node.current_probability
        node.current_probability = new_probability
        node.last_updated = datetime.now()
        node.evidence_count += 1

        # Log evidence
        if evidence:
            evidence_entry = {
                'timestamp': datetime.now(),
                'node_id': node_id,
                'old_probability': old_probability,
                'new_probability': new_probability,
                'evidence': evidence
            }
            self.evidence_log.append(evidence_entry)

        # Propagate probability changes through the graph
        self._propagate_probability_update(node_id)

    def _propagate_probability_update(self, start_node_id: str):
        """Propagate probability updates using belief propagation"""
        # Simple implementation - in practice, use full belief propagation
        visited = set()
        queue = deque([start_node_id])

        while queue:
            current_id = queue.popleft()
            if current_id in visited:
                continue
            visited.add(current_id)

            current_node = self.nodes[current_id]

            # Update children probabilities
            for child_id in current_node.children:
                if child_id not in self.nodes:
                    continue

                child_node = self.nodes[child_id]
                edge = self.edges.get((current_id, child_id))
                if not edge:
                    continue

                # Calculate conditional probability
                # P(child | parent) = success_probability * P(parent)
                conditional_prob = edge.success_probability * current_node.current_probability

                # Combine with other parent influences (simplified)
                other_parent_prob = 1.0
                for parent_id in child_node.parents:
                    if parent_id != current_id:
                        parent_node = self.nodes.get(parent_id)
                        if parent_node:
                            other_parent_prob *= (1 - parent_node.current_probability)

                # Update child probability using noisy-OR gate (simplified)
                new_child_prob = 1 - (1 - conditional_prob) * other_parent_prob
                child_node.current_probability = new_child_prob

                queue.append(child_id)

    def add_evidence(self, evidence: Dict[str, Any]):
        """Add evidence that affects node probabilities"""
        evidence_type = evidence.get('type', '')
        node_id = evidence.get('node_id', '')
        confidence = evidence.get('confidence', 1.0)

        if node_id not in self.nodes:
            logger.warning(f"Evidence for unknown node: {node_id}")
            return

        # Update probability based on evidence type
        if evidence_type == 'compromise_detected':
            new_probability = min(1.0, self.nodes[node_id].current_probability + confidence * 0.3)
        elif evidence_type == 'anomaly_detected':
            new_probability = min(1.0, self.nodes[node_id].current_probability + confidence * 0.2)
        elif evidence_type == 'normal_activity':
            new_probability = max(0.0, self.nodes[node_id].current_probability - confidence * 0.1)
        elif evidence_type == 'security_control':
            new_probability = max(0.0, self.nodes[node_id].current_probability - confidence * 0.4)
        else:
            return

        self.update_node_probability(node_id, new_probability, evidence)

    def calculate_attack_probability(self, target_node_id: str) -> Dict[str, Any]:
        """Calculate the probability of reaching a target node"""
        if target_node_id not in self.nodes:
            return {'probability': 0.0, 'confidence': 0.0}

        # Use Dijkstra-like algorithm to find most probable attack path
        probabilities = {node_id: 0.0 for node_id in self.nodes}
        probabilities[target_node_id] = 1.0  # Target is compromised

        # Work backwards from target
        queue = [(1.0, target_node_id)]  # (probability, node_id)
        visited = set()

        while queue:
            current_prob, current_id = heapq.heappop(queue)
            current_prob = -current_prob  # Convert back from negative for max-heap

            if current_id in visited:
                continue
            visited.add(current_id)

            current_node = self.nodes[current_id]

            # Update probability for this node
            probabilities[current_id] = max(probabilities[current_id], current_prob)

            # Propagate to parents
            for parent_id in current_node.parents:
                edge = self.edges.get((parent_id, current_id))
                if edge:
                    # Reverse probability: P(parent | child) using Bayes' rule (simplified)
                    parent_prob = current_prob * edge.success_probability
                    heapq.heappush(queue, (-parent_prob, parent_id))

        target_prob = probabilities[target_node_id]
        confidence = self._calculate_probability_confidence(target_prob, target_node_id)

        return {
            'probability': target_prob,
            'confidence': confidence,
            'supporting_paths': self._find_supporting_paths(target_node_id, probabilities),
            'risk_factors': self._identify_risk_factors(target_node_id)
        }

    def _calculate_probability_confidence(self, probability: float, node_id: str) -> float:
        """Calculate confidence in the probability estimate"""
        node = self.nodes[node_id]

        # Base confidence on evidence count and probability stability
        evidence_confidence = min(1.0, node.evidence_count / 10.0)

        # Probability-based confidence (extreme probabilities are more confident)
        prob_confidence = 1 - 2 * abs(probability - 0.5)  # Peaks at 0.5, minimum at 0/1

        # Combine confidences
        return (evidence_confidence + prob_confidence) / 2

    def _find_supporting_paths(self, target_id: str, probabilities: Dict[str, float]) -> List[Dict[str, Any]]:
        """Find attack paths that support the probability calculation"""
        paths = []

        # Find all paths from entry points to target
        entry_points = [node_id for node_id, node in self.nodes.items()
                       if node.node_type in ['external_ip', 'user', 'service']]

        for entry_point in entry_points:
            try:
                all_paths = list(nx.all_simple_paths(self.graph, entry_point, target_id, cutoff=5))

                for path in all_paths[:3]:  # Limit to top 3 paths per entry point
                    path_prob = self._calculate_path_probability(path)
                    if path_prob > 0.1:  # Only include significant paths
                        paths.append({
                            'path': path,
                            'probability': path_prob,
                            'entry_point': entry_point,
                            'length': len(path)
                        })

            except nx.NetworkXNoPath:
                continue

        # Sort by probability
        paths.sort(key=lambda x: x['probability'], reverse=True)
        return paths[:10]  # Return top 10 paths

    def _calculate_path_probability(self, path: List[str]) -> float:
        """Calculate the probability of success for an attack path"""
        if len(path) < 2:
            return 0.0

        path_prob = 1.0

        for i in range(len(path) - 1):
            source_id = path[i]
            target_id = path[i + 1]

            edge = self.edges.get((source_id, target_id))
            if edge:
                # Include success probability and detection avoidance
                step_prob = edge.success_probability * (1 - edge.detection_probability)
                path_prob *= step_prob
            else:
                # No direct edge - assume low probability
                path_prob *= 0.1

        return path_prob

    def _identify_risk_factors(self, node_id: str) -> List[Dict[str, Any]]:
        """Identify risk factors contributing to node vulnerability"""
        risk_factors = []

        node = self.nodes[node_id]

        # Base vulnerability
        if node.base_vulnerability > 0.5:
            risk_factors.append({
                'factor': 'high_base_vulnerability',
                'impact': node.base_vulnerability,
                'description': f'Node has high inherent vulnerability ({node.base_vulnerability:.2f})'
            })

        # Parent vulnerabilities
        for parent_id in node.parents:
            parent_node = self.nodes.get(parent_id)
            if parent_node and parent_node.current_probability > 0.3:
                risk_factors.append({
                    'factor': 'vulnerable_parent',
                    'impact': parent_node.current_probability,
                    'description': f'Parent node {parent_id} is likely compromised'
                })

        # Weak edges
        for parent_id in node.parents:
            edge = self.edges.get((parent_id, node_id))
            if edge and edge.success_probability > 0.7:
                risk_factors.append({
                    'factor': 'easy_attack_vector',
                    'impact': edge.success_probability,
                    'description': f'Easy attack vector from {parent_id}'
                })

        # Sort by impact
        risk_factors.sort(key=lambda x: x['impact'], reverse=True)
        return risk_factors[:5]

    def generate_attack_hypotheses(self) -> List[AttackHypothesis]:
        """Generate hypotheses about potential attack scenarios"""
        hypotheses = []

        # Hypothesis 1: Targeted attack on high-value assets
        high_value_nodes = [node_id for node_id, node in self.nodes.items()
                           if node.node_type in ['database', 'crown_jewel', 'admin_system']]

        for target_id in high_value_nodes:
            attack_prob = self.calculate_attack_probability(target_id)

            hypothesis = AttackHypothesis(
                hypothesis_id=f"targeted_attack_{target_id}",
                description=f"Attacker is targeting high-value asset {target_id}",
                prior_probability=0.1,  # Base prior
                current_probability=attack_prob['probability'],
                supporting_evidence=self._get_supporting_evidence(target_id),
                predicted_outcomes=self._predict_attack_outcomes(target_id)
            )

            hypotheses.append(hypothesis)

        # Hypothesis 2: Lateral movement pattern
        lateral_movement_prob = self._calculate_lateral_movement_probability()

        if lateral_movement_prob > 0.3:
            hypothesis = AttackHypothesis(
                hypothesis_id="lateral_movement",
                description="Attacker is performing lateral movement across the network",
                prior_probability=0.15,
                current_probability=lateral_movement_prob,
                supporting_evidence=self._get_lateral_movement_evidence(),
                predicted_outcomes=self._predict_lateral_movement_outcomes()
            )

            hypotheses.append(hypothesis)

        # Hypothesis 3: Data exfiltration attempt
        exfil_prob = self._calculate_exfiltration_probability()

        if exfil_prob > 0.2:
            hypothesis = AttackHypothesis(
                hypothesis_id="data_exfiltration",
                description="Attacker is attempting to exfiltrate sensitive data",
                prior_probability=0.1,
                current_probability=exfil_prob,
                supporting_evidence=self._get_exfiltration_evidence(),
                predicted_outcomes=self._predict_exfiltration_outcomes()
            )

            hypotheses.append(hypothesis)

        # Update hypothesis probabilities based on evidence
        for hypothesis in hypotheses:
            hypothesis.current_probability = self._update_hypothesis_probability(hypothesis)

        # Sort by probability
        hypotheses.sort(key=lambda x: x.current_probability, reverse=True)

        return hypotheses

    def _calculate_lateral_movement_probability(self) -> float:
        """Calculate probability of lateral movement attack pattern"""
        # Look for patterns of compromise across similar node types
        compromised_servers = [node_id for node_id, node in self.nodes.items()
                              if node.node_type == 'server' and node.current_probability > 0.5]

        if len(compromised_servers) < 2:
            return 0.0

        # Calculate connectivity between compromised servers
        connections = 0
        for i, server1 in enumerate(compromised_servers):
            for server2 in compromised_servers[i+1:]:
                if (server1, server2) in self.edges or (server2, server1) in self.edges:
                    connections += 1

        # Higher connectivity suggests lateral movement
        return min(0.8, connections / (len(compromised_servers) * 0.5))

    def _calculate_exfiltration_probability(self) -> float:
        """Calculate probability of data exfiltration"""
        # Look for access to sensitive data followed by external connections
        sensitive_nodes = [node_id for node_id, node in self.nodes.items()
                          if node.node_type in ['database', 'file_server'] and node.current_probability > 0.3]

        external_connections = 0
        for sensitive_node in sensitive_nodes:
            # Check for edges to external nodes
            for edge_key, edge in self.edges.items():
                if edge.source_id == sensitive_node or edge.target_id == sensitive_node:
                    target_type = self.nodes.get(edge.target_id if edge.source_id == sensitive_node else edge.source_id, ProbabilisticNode('', '', 0)).node_type
                    if target_type in ['external_ip', 'internet']:
                        external_connections += 1

        return min(0.9, external_connections * 0.3)

    def _get_supporting_evidence(self, target_id: str) -> List[Dict[str, Any]]:
        """Get evidence supporting an attack hypothesis"""
        evidence = []

        # Recent compromises leading to target
        target_node = self.nodes[target_id]
        for parent_id in target_node.parents:
            parent_node = self.nodes.get(parent_id)
            if parent_node and parent_node.current_probability > 0.4:
                evidence.append({
                    'type': 'compromised_parent',
                    'node_id': parent_id,
                    'probability': parent_node.current_probability,
                    'timestamp': parent_node.last_updated
                })

        # Recent evidence log entries
        recent_evidence = [e for e in self.evidence_log
                          if (datetime.now() - e['timestamp']) < timedelta(hours=24)]

        for ev in recent_evidence:
            if ev['node_id'] in [target_id] + target_node.parents:
                evidence.append(ev)

        return evidence[:10]

    def _get_lateral_movement_evidence(self) -> List[Dict[str, Any]]:
        """Get evidence for lateral movement hypothesis"""
        evidence = []

        # Find compromised servers
        compromised_servers = [(node_id, node) for node_id, node in self.nodes.items()
                              if node.node_type == 'server' and node.current_probability > 0.5]

        for server_id, server in compromised_servers:
            evidence.append({
                'type': 'compromised_server',
                'node_id': server_id,
                'probability': server.current_probability,
                'timestamp': server.last_updated
            })

        return evidence

    def _get_exfiltration_evidence(self) -> List[Dict[str, Any]]:
        """Get evidence for exfiltration hypothesis"""
        evidence = []

        # Find access to sensitive data
        sensitive_access = []
        for edge_key, edge in self.edges.items():
            source_node = self.nodes.get(edge.source_id)
            target_node = self.nodes.get(edge.target_id)

            if ((source_node and source_node.node_type in ['database', 'file_server']) or
                (target_node and target_node.node_type in ['database', 'file_server'])):

                accessing_node = source_node if source_node and source_node.node_type not in ['database', 'file_server'] else target_node
                accessed_node = target_node if accessing_node == source_node else source_node

                if accessing_node and accessing_node.current_probability > 0.3:
                    sensitive_access.append({
                        'type': 'sensitive_data_access',
                        'accessing_node': accessing_node.node_id,
                        'accessed_node': accessed_node.node_id if accessed_node else 'unknown',
                        'probability': accessing_node.current_probability
                    })

        return sensitive_access

    def _predict_attack_outcomes(self, target_id: str) -> List[Dict[str, Any]]:
        """Predict potential outcomes of an attack on target"""
        outcomes = []

        node = self.nodes[target_id]

        # Data breach outcome
        if node.node_type == 'database':
            outcomes.append({
                'outcome': 'data_breach',
                'probability': 0.8,
                'impact': 'high',
                'description': 'Sensitive data could be exposed or stolen'
            })

        # System compromise outcome
        if node.node_type in ['server', 'admin_system']:
            outcomes.append({
                'outcome': 'system_compromise',
                'probability': 0.9,
                'impact': 'high',
                'description': 'Complete system control could be achieved'
            })

        # Lateral movement outcome
        outcomes.append({
            'outcome': 'lateral_movement',
            'probability': 0.6,
            'impact': 'medium',
            'description': 'Attacker could move to other systems'
        })

        return outcomes

    def _predict_lateral_movement_outcomes(self) -> List[Dict[str, Any]]:
        """Predict outcomes of lateral movement"""
        return [
            {
                'outcome': 'expanded_compromise',
                'probability': 0.7,
                'impact': 'high',
                'description': 'Attacker gains access to multiple critical systems'
            },
            {
                'outcome': 'data_exfiltration',
                'probability': 0.5,
                'impact': 'high',
                'description': 'Sensitive data could be stolen during movement'
            }
        ]

    def _predict_exfiltration_outcomes(self) -> List[Dict[str, Any]]:
        """Predict outcomes of data exfiltration"""
        return [
            {
                'outcome': 'data_loss',
                'probability': 0.9,
                'impact': 'critical',
                'description': 'Sensitive data is stolen and could be sold or used'
            },
            {
                'outcome': 'compliance_violation',
                'probability': 0.8,
                'impact': 'high',
                'description': 'Regulatory compliance requirements violated'
            }
        ]

    def _update_hypothesis_probability(self, hypothesis: AttackHypothesis) -> float:
        """Update hypothesis probability based on evidence"""
        prior = hypothesis.prior_probability
        likelihood = 1.0

        # Incorporate supporting evidence
        for evidence in hypothesis.supporting_evidence:
            evidence_strength = evidence.get('probability', 0.5)
            likelihood *= (1 + evidence_strength)

        # Penalize conflicting evidence
        for evidence in hypothesis.conflicting_evidence:
            evidence_strength = evidence.get('probability', 0.5)
            likelihood *= (1 - evidence_strength * 0.5)

        # Normalize
        likelihood = min(likelihood, 2.0)  # Cap at 2x boost

        # Bayesian update (simplified)
        posterior = (prior * likelihood) / ((prior * likelihood) + ((1 - prior) * 1))

        return posterior

    def export_graph(self, format: str = 'json') -> Union[str, Dict[str, Any]]:
        """Export the probabilistic graph"""
        graph_data = {
            'nodes': {node_id: vars(node) for node_id, node in self.nodes.items()},
            'edges': {f"{k[0]}_{k[1]}": vars(edge) for k, edge in self.edges.items()},
            'evidence_log': [vars(e) if hasattr(e, '__dict__') else e for e in self.evidence_log],
            'export_timestamp': datetime.now().isoformat()
        }

        if format == 'json':
            return json.dumps(graph_data, indent=2, default=str)
        else:
            return graph_data

class RiskPropagationEngine:
    """
    Engine for propagating risk through the probabilistic attack graph
    """

    def __init__(self, attack_graph: BayesianAttackGraph):
        self.graph = attack_graph

    def propagate_risk(self, initial_risks: Dict[str, float],
                      max_iterations: int = 10) -> Dict[str, float]:
        """
        Propagate risk through the graph using iterative belief propagation

        Args:
            initial_risks: Initial risk values for nodes
            max_iterations: Maximum number of propagation iterations

        Returns:
            final_risks: Final risk values after propagation
        """
        current_risks = initial_risks.copy()

        for iteration in range(max_iterations):
            new_risks = current_risks.copy()
            max_change = 0.0

            for node_id in self.graph.nodes:
                if node_id not in current_risks:
                    current_risks[node_id] = 0.0

                # Calculate incoming risk from parents
                parent_risk = 0.0
                parent_count = 0

                for parent_id in self.graph.nodes[node_id].parents:
                    edge = self.graph.edges.get((parent_id, node_id))
                    if edge:
                        # Risk propagation through edge
                        propagated_risk = current_risks[parent_id] * edge.success_probability
                        parent_risk += propagated_risk
                        parent_count += 1

                if parent_count > 0:
                    parent_risk /= parent_count  # Average parent risk

                # Combine with node's base vulnerability
                base_risk = self.graph.nodes[node_id].base_vulnerability
                combined_risk = 1 - (1 - parent_risk) * (1 - base_risk)

                # Damping to prevent oscillation
                damping_factor = 0.8
                new_risks[node_id] = damping_factor * combined_risk + (1 - damping_factor) * current_risks[node_id]

                max_change = max(max_change, abs(new_risks[node_id] - current_risks[node_id]))

            current_risks = new_risks

            # Early stopping if convergence
            if max_change < 0.001:
                logger.info(f"Risk propagation converged after {iteration + 1} iterations")
                break

        return current_risks

    def calculate_system_risk(self, node_risks: Dict[str, float]) -> Dict[str, Any]:
        """Calculate overall system risk metrics"""
        if not node_risks:
            return {'overall_risk': 0.0, 'high_risk_nodes': [], 'risk_distribution': {}}

        risk_values = list(node_risks.values())

        # Overall system risk (weighted average)
        weights = [self._get_node_weight(node_id) for node_id in node_risks.keys()]
        overall_risk = np.average(risk_values, weights=weights)

        # High-risk nodes
        high_risk_threshold = np.percentile(risk_values, 80)
        high_risk_nodes = [
            node_id for node_id, risk in node_risks.items()
            if risk >= high_risk_threshold
        ]

        # Risk distribution
        risk_bins = [0, 0.2, 0.4, 0.6, 0.8, 1.0]
        risk_distribution = {}
        for i in range(len(risk_bins) - 1):
            count = sum(1 for r in risk_values if risk_bins[i] <= r < risk_bins[i+1])
            risk_distribution[f"{risk_bins[i]}-{risk_bins[i+1]}"] = count

        return {
            'overall_risk': overall_risk,
            'high_risk_nodes': high_risk_nodes,
            'risk_distribution': risk_distribution,
            'max_risk': max(risk_values),
            'mean_risk': np.mean(risk_values),
            'risk_std': np.std(risk_values)
        }

    def _get_node_weight(self, node_id: str) -> float:
        """Get importance weight for a node"""
        node = self.graph.nodes.get(node_id)
        if not node:
            return 1.0

        # Weight based on node type
        type_weights = {
            'crown_jewel': 10.0,
            'database': 8.0,
            'admin_system': 7.0,
            'server': 5.0,
            'user': 3.0,
            'workstation': 2.0,
            'service': 4.0,
            'network_device': 6.0
        }

        return type_weights.get(node.node_type, 1.0)

# Example usage and testing
if __name__ == "__main__":
    # Create a sample probabilistic attack graph
    graph = BayesianAttackGraph()

    # Add nodes
    nodes = [
        ProbabilisticNode("external_ip", "external_ip", 0.1),
        ProbabilisticNode("web_server", "server", 0.3),
        ProbabilisticNode("app_server", "server", 0.4),
        ProbabilisticNode("database", "database", 0.6),
        ProbabilisticNode("admin_system", "admin_system", 0.8)
    ]

    for node in nodes:
        graph.add_node(node)

    # Add edges
    edges = [
        ProbabilisticEdge("external_ip", "web_server", "network_access", 0.7, 0.2, 1.0),
        ProbabilisticEdge("web_server", "app_server", "service_call", 0.8, 0.3, 2.0),
        ProbabilisticEdge("app_server", "database", "database_query", 0.6, 0.4, 3.0),
        ProbabilisticEdge("database", "admin_system", "privilege_escalation", 0.4, 0.6, 4.0)
    ]

    for edge in edges:
        graph.add_edge(edge)

    # Add some evidence
    graph.add_evidence({
        'type': 'compromise_detected',
        'node_id': 'web_server',
        'confidence': 0.8
    })

    # Calculate attack probabilities
    db_attack = graph.calculate_attack_probability("database")
    admin_attack = graph.calculate_attack_probability("admin_system")

    print("Database attack probability:", db_attack['probability'])
    print("Admin system attack probability:", admin_attack['probability'])

    # Generate hypotheses
    hypotheses = graph.generate_attack_hypotheses()
    print(f"Generated {len(hypotheses)} attack hypotheses")

    for hyp in hypotheses[:3]:
        print(f"- {hyp.description}: {hyp.current_probability:.3f}")

    # Risk propagation
    risk_engine = RiskPropagationEngine(graph)
    initial_risks = {node.node_id: node.base_vulnerability for node in nodes}
    final_risks = risk_engine.propagate_risk(initial_risks)

    system_risk = risk_engine.calculate_system_risk(final_risks)
    print(f"Overall system risk: {system_risk['overall_risk']:.3f}")
    print(f"High-risk nodes: {system_risk['high_risk_nodes']}")
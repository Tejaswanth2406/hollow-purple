"""
Risk Propagation Engine for Attack Graphs

This module implements advanced risk propagation algorithms for cyber attack graphs,
including multi-dimensional risk assessment, temporal risk evolution, and
quantitative risk analysis with uncertainty modeling.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import networkx as nx
from scipy.optimize import minimize_scalar
import pandas as pd

logger = logging.getLogger(__name__)

@dataclass
class RiskVector:
    """Multi-dimensional risk representation"""
    confidentiality: float  # Risk to data confidentiality
    integrity: float        # Risk to data/system integrity
    availability: float     # Risk to system availability
    financial: float        # Financial impact risk
    operational: float      # Operational impact risk
    reputational: float     # Reputational impact risk

    def magnitude(self) -> float:
        """Calculate overall risk magnitude"""
        # Weighted combination of risk dimensions
        weights = {
            'confidentiality': 0.25,
            'integrity': 0.25,
            'availability': 0.2,
            'financial': 0.15,
            'operational': 0.1,
            'reputational': 0.05
        }

        weighted_sum = sum(getattr(self, dim) * weight for dim, weight in weights.items())
        return weighted_sum

    def dominant_dimension(self) -> str:
        """Return the dominant risk dimension"""
        dimensions = ['confidentiality', 'integrity', 'availability',
                     'financial', 'operational', 'reputational']
        values = [getattr(self, dim) for dim in dimensions]
        return dimensions[np.argmax(values)]

@dataclass
class RiskPropagationResult:
    """Result of risk propagation analysis"""
    node_risks: Dict[str, RiskVector]
    edge_risks: Dict[Tuple[str, str], RiskVector]
    propagation_paths: List[Dict[str, Any]]
    critical_paths: List[Dict[str, Any]]
    risk_evolution: Dict[str, List[float]]
    convergence_metrics: Dict[str, Any]
    timestamp: datetime

class RiskPropagationEngine:
    """
    Advanced engine for propagating risk through attack graphs
    """

    def __init__(self, damping_factor: float = 0.85, max_iterations: int = 100,
                 convergence_threshold: float = 1e-6):
        self.damping_factor = damping_factor
        self.max_iterations = max_iterations
        self.convergence_threshold = convergence_threshold

        # Risk propagation parameters
        self.propagation_weights = {
            'direct_compromise': 0.9,
            'lateral_movement': 0.7,
            'privilege_escalation': 0.8,
            'data_flow': 0.6,
            'network_access': 0.5
        }

        # Impact multipliers for different asset types
        self.asset_impact_multipliers = {
            'crown_jewel': 1.0,
            'database': 0.9,
            'admin_system': 0.85,
            'server': 0.7,
            'workstation': 0.5,
            'network_device': 0.6,
            'service': 0.4,
            'user': 0.3
        }

    def propagate_risk(self, attack_graph: Any, initial_risks: Dict[str, RiskVector] = None,
                      propagation_type: str = 'iterative') -> RiskPropagationResult:
        """
        Propagate risk through the attack graph

        Args:
            attack_graph: The attack graph (BayesianAttackGraph or similar)
            initial_risks: Initial risk vectors for nodes
            propagation_type: Type of propagation ('iterative', 'markov', 'monte_carlo')

        Returns:
            propagation_result: Complete risk propagation analysis
        """
        if initial_risks is None:
            initial_risks = self._initialize_default_risks(attack_graph)

        if propagation_type == 'iterative':
            return self._iterative_propagation(attack_graph, initial_risks)
        elif propagation_type == 'markov':
            return self._markov_propagation(attack_graph, initial_risks)
        elif propagation_type == 'monte_carlo':
            return self._monte_carlo_propagation(attack_graph, initial_risks)
        else:
            raise ValueError(f"Unknown propagation type: {propagation_type}")

    def _initialize_default_risks(self, attack_graph: Any) -> Dict[str, RiskVector]:
        """Initialize default risk vectors for all nodes"""
        initial_risks = {}

        for node_id, node in attack_graph.nodes.items():
            # Base risk depends on node type and vulnerability
            base_risk = node.base_vulnerability

            # Asset type multiplier
            asset_multiplier = self.asset_impact_multipliers.get(node.node_type, 0.5)

            # Initialize risk vector
            risk_vector = RiskVector(
                confidentiality=base_risk * asset_multiplier,
                integrity=base_risk * asset_multiplier,
                availability=base_risk * asset_multiplier * 0.8,  # Slightly lower for availability
                financial=base_risk * asset_multiplier * 0.6,
                operational=base_risk * asset_multiplier * 0.7,
                reputational=base_risk * asset_multiplier * 0.4
            )

            initial_risks[node_id] = risk_vector

        return initial_risks

    def _iterative_propagation(self, attack_graph: Any,
                             initial_risks: Dict[str, RiskVector]) -> RiskPropagationResult:
        """Perform iterative risk propagation using relaxation method"""
        current_risks = {node_id: risk.magnitude() for node_id, risk in initial_risks.items()}
        edge_risks = {}

        convergence_history = []
        propagation_paths = []

        for iteration in range(self.max_iterations):
            new_risks = {}
            max_change = 0.0

            # Process each node
            for node_id in attack_graph.nodes:
                incoming_risk = 0.0
                contributing_paths = []

                # Calculate risk from parent nodes
                for parent_id in attack_graph.nodes[node_id].parents:
                    edge = attack_graph.edges.get((parent_id, node_id))
                    if edge:
                        parent_risk = current_risks.get(parent_id, 0.0)
                        edge_weight = self._get_edge_propagation_weight(edge)

                        # Calculate propagated risk
                        propagated_risk = parent_risk * edge.success_probability * edge_weight
                        incoming_risk += propagated_risk

                        # Track edge risk
                        edge_key = (parent_id, node_id)
                        if edge_key not in edge_risks:
                            edge_risks[edge_key] = self._calculate_edge_risk_vector(
                                initial_risks.get(parent_id, RiskVector(0,0,0,0,0,0)),
                                initial_risks.get(node_id, RiskVector(0,0,0,0,0,0)),
                                edge
                            )

                        contributing_paths.append({
                            'from_node': parent_id,
                            'to_node': node_id,
                            'risk_contribution': propagated_risk,
                            'edge_type': edge.edge_type
                        })

                # Combine with node's base risk
                base_risk = attack_graph.nodes[node_id].base_vulnerability
                combined_risk = (1 - self.damping_factor) * base_risk + self.damping_factor * incoming_risk

                # Ensure risk stays within bounds
                combined_risk = max(0.0, min(1.0, combined_risk))

                new_risks[node_id] = combined_risk

                # Track change for convergence
                if node_id in current_risks:
                    change = abs(combined_risk - current_risks[node_id])
                    max_change = max(max_change, change)

                # Store propagation path
                if contributing_paths:
                    propagation_paths.append({
                        'node_id': node_id,
                        'iteration': iteration,
                        'incoming_risk': incoming_risk,
                        'final_risk': combined_risk,
                        'contributing_paths': contributing_paths
                    })

            current_risks = new_risks
            convergence_history.append(max_change)

            # Check convergence
            if max_change < self.convergence_threshold:
                logger.info(f"Risk propagation converged after {iteration + 1} iterations")
                break

        # Convert back to risk vectors
        final_node_risks = {}
        for node_id, risk_magnitude in current_risks.items():
            # Scale the original risk vector by the propagated magnitude
            original_vector = initial_risks.get(node_id, RiskVector(0,0,0,0,0,0))
            scale_factor = risk_magnitude / max(original_vector.magnitude(), 1e-6)
            final_node_risks[node_id] = RiskVector(
                confidentiality=min(1.0, original_vector.confidentiality * scale_factor),
                integrity=min(1.0, original_vector.integrity * scale_factor),
                availability=min(1.0, original_vector.availability * scale_factor),
                financial=min(1.0, original_vector.financial * scale_factor),
                operational=min(1.0, original_vector.operational * scale_factor),
                reputational=min(1.0, original_vector.reputational * scale_factor)
            )

        # Identify critical paths
        critical_paths = self._identify_critical_paths(final_node_risks, propagation_paths)

        # Calculate risk evolution (simplified)
        risk_evolution = self._calculate_risk_evolution(convergence_history)

        convergence_metrics = {
            'iterations': len(convergence_history),
            'final_max_change': convergence_history[-1] if convergence_history else 0.0,
            'convergence_achieved': convergence_history[-1] < self.convergence_threshold if convergence_history else False
        }

        return RiskPropagationResult(
            node_risks=final_node_risks,
            edge_risks=edge_risks,
            propagation_paths=propagation_paths,
            critical_paths=critical_paths,
            risk_evolution=risk_evolution,
            convergence_metrics=convergence_metrics,
            timestamp=datetime.now()
        )

    def _get_edge_propagation_weight(self, edge: Any) -> float:
        """Get propagation weight for an edge type"""
        return self.propagation_weights.get(edge.edge_type, 0.5)

    def _calculate_edge_risk_vector(self, source_risk: RiskVector,
                                  target_risk: RiskVector, edge: Any) -> RiskVector:
        """Calculate risk vector for an edge"""
        # Edge risk is combination of source and target risks, modulated by edge properties
        propagation_factor = edge.success_probability * self._get_edge_propagation_weight(edge)

        return RiskVector(
            confidentiality=(source_risk.confidentiality + target_risk.confidentiality) * propagation_factor / 2,
            integrity=(source_risk.integrity + target_risk.integrity) * propagation_factor / 2,
            availability=(source_risk.availability + target_risk.availability) * propagation_factor / 2,
            financial=(source_risk.financial + target_risk.financial) * propagation_factor / 2,
            operational=(source_risk.operational + target_risk.operational) * propagation_factor / 2,
            reputational=(source_risk.reputational + target_risk.reputational) * propagation_factor / 2
        )

    def _identify_critical_paths(self, node_risks: Dict[str, RiskVector],
                               propagation_paths: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical risk propagation paths"""
        critical_paths = []

        # Find nodes with high risk
        high_risk_nodes = [
            node_id for node_id, risk in node_risks.items()
            if risk.magnitude() > 0.7
        ]

        # For each high-risk node, find the most significant propagation paths
        for node_id in high_risk_nodes:
            node_paths = [p for p in propagation_paths if p['node_id'] == node_id]

            if node_paths:
                # Sort by risk contribution
                sorted_paths = sorted(
                    node_paths,
                    key=lambda x: sum(cp['risk_contribution'] for cp in x['contributing_paths']),
                    reverse=True
                )

                # Take top contributing path
                top_path = sorted_paths[0]
                critical_paths.append({
                    'target_node': node_id,
                    'total_risk': top_path['final_risk'],
                    'primary_contributors': top_path['contributing_paths'][:3],  # Top 3 contributors
                    'path_length': len(top_path['contributing_paths'])
                })

        return critical_paths

    def _calculate_risk_evolution(self, convergence_history: List[float]) -> Dict[str, List[float]]:
        """Calculate risk evolution over iterations"""
        # Simplified: just return convergence history as risk evolution
        return {
            'convergence': convergence_history,
            'smoothed_risk': self._exponential_smooth(convergence_history, alpha=0.3)
        }

    def _exponential_smooth(self, values: List[float], alpha: float) -> List[float]:
        """Apply exponential smoothing to values"""
        if not values:
            return []

        smoothed = [values[0]]
        for value in values[1:]:
            smoothed_value = alpha * value + (1 - alpha) * smoothed[-1]
            smoothed.append(smoothed_value)

        return smoothed

    def _markov_propagation(self, attack_graph: Any,
                          initial_risks: Dict[str, RiskVector]) -> RiskPropagationResult:
        """Perform Markov chain-based risk propagation"""
        # Simplified Markov chain implementation
        # In practice, this would use proper Markov chain Monte Carlo

        states = list(attack_graph.nodes.keys())
        n_states = len(states)

        # Build transition matrix based on attack graph edges
        transition_matrix = np.zeros((n_states, n_states))

        for i, source_id in enumerate(states):
            for j, target_id in enumerate(states):
                if source_id == target_id:
                    # Self-transition with damping
                    transition_matrix[i, j] = 0.1
                else:
                    edge = attack_graph.edges.get((source_id, target_id))
                    if edge:
                        transition_matrix[i, j] = edge.success_probability * 0.8
                    else:
                        transition_matrix[i, j] = 0.01  # Small probability for indirect paths

            # Normalize row
            row_sum = np.sum(transition_matrix[i, :])
            if row_sum > 0:
                transition_matrix[i, :] /= row_sum

        # Initialize state vector with initial risks
        state_vector = np.array([initial_risks.get(node_id, RiskVector(0,0,0,0,0,0)).magnitude()
                                for node_id in states])

        # Evolve through Markov chain
        evolution_history = [state_vector.copy()]

        for iteration in range(self.max_iterations):
            new_state = np.dot(state_vector, transition_matrix)
            evolution_history.append(new_state)

            # Check convergence
            change = np.max(np.abs(new_state - state_vector))
            if change < self.convergence_threshold:
                break

            state_vector = new_state

        # Convert back to risk vectors (simplified)
        final_node_risks = {}
        for i, node_id in enumerate(states):
            magnitude = state_vector[i]
            original_vector = initial_risks.get(node_id, RiskVector(0,0,0,0,0,0))
            scale_factor = magnitude / max(original_vector.magnitude(), 1e-6)

            final_node_risks[node_id] = RiskVector(
                confidentiality=min(1.0, original_vector.confidentiality * scale_factor),
                integrity=min(1.0, original_vector.integrity * scale_factor),
                availability=min(1.0, original_vector.availability * scale_factor),
                financial=min(1.0, original_vector.financial * scale_factor),
                operational=min(1.0, original_vector.operational * scale_factor),
                reputational=min(1.0, original_vector.reputational * scale_factor)
            )

        return RiskPropagationResult(
            node_risks=final_node_risks,
            edge_risks={},  # Not calculated in Markov method
            propagation_paths=[],
            critical_paths=[],
            risk_evolution={'markov_states': [state.tolist() for state in evolution_history]},
            convergence_metrics={'method': 'markov', 'iterations': len(evolution_history)},
            timestamp=datetime.now()
        )

    def _monte_carlo_propagation(self, attack_graph: Any,
                               initial_risks: Dict[str, RiskVector],
                               n_simulations: int = 1000) -> RiskPropagationResult:
        """Perform Monte Carlo risk propagation"""
        node_ids = list(attack_graph.nodes.keys())
        risk_samples = {node_id: [] for node_id in node_ids}

        for simulation in range(n_simulations):
            # Sample initial risks
            current_risks = {}
            for node_id in node_ids:
                base_risk = initial_risks.get(node_id, RiskVector(0,0,0,0,0,0)).magnitude()
                # Add noise to simulate uncertainty
                sampled_risk = np.random.beta(2, 5) * base_risk  # Conservative sampling
                current_risks[node_id] = sampled_risk

            # Propagate through one iteration (simplified)
            for node_id in node_ids:
                incoming_risk = 0.0

                for parent_id in attack_graph.nodes[node_id].parents:
                    edge = attack_graph.edges.get((parent_id, node_id))
                    if edge:
                        parent_risk = current_risks[parent_id]
                        propagation_prob = np.random.beta(2, 2)  # Sample propagation probability
                        propagated_risk = parent_risk * edge.success_probability * propagation_prob
                        incoming_risk += propagated_risk

                # Combine risks
                base_risk = attack_graph.nodes[node_id].base_vulnerability
                final_risk = (1 - self.damping_factor) * base_risk + self.damping_factor * incoming_risk
                current_risks[node_id] = max(0.0, min(1.0, final_risk))

            # Store samples
            for node_id in node_ids:
                risk_samples[node_id].append(current_risks[node_id])

        # Calculate statistics from samples
        final_node_risks = {}
        risk_statistics = {}

        for node_id in node_ids:
            samples = risk_samples[node_id]
            mean_risk = np.mean(samples)
            std_risk = np.std(samples)

            risk_statistics[node_id] = {
                'mean': mean_risk,
                'std': std_risk,
                'percentile_95': np.percentile(samples, 95),
                'percentile_5': np.percentile(samples, 5)
            }

            # Create risk vector scaled by mean risk
            original_vector = initial_risks.get(node_id, RiskVector(0,0,0,0,0,0))
            scale_factor = mean_risk / max(original_vector.magnitude(), 1e-6)

            final_node_risks[node_id] = RiskVector(
                confidentiality=min(1.0, original_vector.confidentiality * scale_factor),
                integrity=min(1.0, original_vector.integrity * scale_factor),
                availability=min(1.0, original_vector.availability * scale_factor),
                financial=min(1.0, original_vector.financial * scale_factor),
                operational=min(1.0, original_vector.operational * scale_factor),
                reputational=min(1.0, original_vector.reputational * scale_factor)
            )

        return RiskPropagationResult(
            node_risks=final_node_risks,
            edge_risks={},
            propagation_paths=[],
            critical_paths=[],
            risk_evolution={'monte_carlo_statistics': risk_statistics},
            convergence_metrics={'method': 'monte_carlo', 'n_simulations': n_simulations},
            timestamp=datetime.now()
        )

    def calculate_risk_metrics(self, propagation_result: RiskPropagationResult) -> Dict[str, Any]:
        """Calculate comprehensive risk metrics from propagation results"""
        metrics = {
            'overall_system_risk': 0.0,
            'risk_distribution': {},
            'high_risk_nodes': [],
            'risk_centers': [],
            'temporal_risk_trends': {},
            'risk_correlations': {}
        }

        # Calculate overall system risk
        node_risks = [risk.magnitude() for risk in propagation_result.node_risks.values()]
        if node_risks:
            metrics['overall_system_risk'] = np.mean(node_risks)

        # Risk distribution
        if node_risks:
            metrics['risk_distribution'] = {
                'mean': np.mean(node_risks),
                'median': np.median(node_risks),
                'std': np.std(node_risks),
                'min': np.min(node_risks),
                'max': np.max(node_risks),
                'percentiles': {
                    '25th': np.percentile(node_risks, 25),
                    '75th': np.percentile(node_risks, 75),
                    '90th': np.percentile(node_risks, 90),
                    '95th': np.percentile(node_risks, 95)
                }
            }

        # High-risk nodes
        risk_threshold = np.percentile(node_risks, 80) if node_risks else 0.5
        metrics['high_risk_nodes'] = [
            node_id for node_id, risk in propagation_result.node_risks.items()
            if risk.magnitude() > risk_threshold
        ]

        # Risk centers (nodes with high connectivity and risk)
        risk_centers = self._identify_risk_centers(propagation_result)
        metrics['risk_centers'] = risk_centers

        # Temporal risk trends
        if 'convergence' in propagation_result.risk_evolution:
            convergence = propagation_result.risk_evolution['convergence']
            if convergence:
                metrics['temporal_risk_trends'] = {
                    'initial_risk': convergence[0],
                    'final_risk': convergence[-1],
                    'risk_reduction': convergence[0] - convergence[-1],
                    'convergence_rate': len([c for c in convergence if c > self.convergence_threshold])
                }

        return metrics

    def _identify_risk_centers(self, propagation_result: RiskPropagationResult) -> List[Dict[str, Any]]:
        """Identify central nodes that are critical for risk propagation"""
        risk_centers = []

        for node_id, risk_vector in propagation_result.node_risks.items():
            # Calculate centrality based on propagation paths
            incoming_paths = [
                path for path in propagation_result.propagation_paths
                if path['node_id'] == node_id
            ]

            if incoming_paths:
                total_contribution = sum(
                    sum(cp['risk_contribution'] for cp in path['contributing_paths'])
                    for path in incoming_paths
                )

                risk_centers.append({
                    'node_id': node_id,
                    'risk_magnitude': risk_vector.magnitude(),
                    'propagation_influence': total_contribution,
                    'dominant_risk_dimension': risk_vector.dominant_dimension()
                })

        # Sort by influence
        risk_centers.sort(key=lambda x: x['propagation_influence'], reverse=True)

        return risk_centers[:10]  # Top 10 risk centers

    def optimize_risk_mitigation(self, propagation_result: RiskPropagationResult,
                               mitigation_budget: float) -> Dict[str, Any]:
        """
        Optimize risk mitigation strategies given a budget constraint

        Args:
            propagation_result: Risk propagation results
            mitigation_budget: Available budget for mitigation (0-1 scale)

        Returns:
            optimization_result: Optimal mitigation strategy
        """
        # Simplified optimization: prioritize high-risk nodes
        high_risk_nodes = [
            (node_id, risk.magnitude()) for node_id, risk in propagation_result.node_risks.items()
            if risk.magnitude() > 0.5
        ]

        high_risk_nodes.sort(key=lambda x: x[1], reverse=True)

        # Allocate budget to top risk nodes
        mitigation_actions = []
        remaining_budget = mitigation_budget

        for node_id, risk_level in high_risk_nodes:
            if remaining_budget <= 0:
                break

            # Cost of mitigation (higher risk = higher cost)
            mitigation_cost = min(risk_level * 0.3, remaining_budget)
            risk_reduction = mitigation_cost * 2  # Assume 2x return on mitigation investment

            mitigation_actions.append({
                'node_id': node_id,
                'current_risk': risk_level,
                'mitigation_cost': mitigation_cost,
                'expected_risk_reduction': risk_reduction,
                'final_risk': max(0.0, risk_level - risk_reduction)
            })

            remaining_budget -= mitigation_cost

        total_risk_reduction = sum(action['expected_risk_reduction'] for action in mitigation_actions)

        return {
            'mitigation_actions': mitigation_actions,
            'total_budget_used': mitigation_budget - remaining_budget,
            'total_risk_reduction': total_risk_reduction,
            'cost_effectiveness': total_risk_reduction / max(mitigation_budget, 1e-6),
            'remaining_budget': remaining_budget
        }

# Example usage
if __name__ == "__main__":
    from .attack_graph_builder import BayesianAttackGraph, ProbabilisticNode, ProbabilisticEdge

    # Create sample attack graph
    graph = BayesianAttackGraph()

    # Add nodes
    nodes = [
        ProbabilisticNode("entry_point", "external_ip", 0.1),
        ProbabilisticNode("web_server", "server", 0.3),
        ProbabilisticNode("app_server", "server", 0.4),
        ProbabilisticNode("database", "database", 0.8)
    ]

    for node in nodes:
        graph.add_node(node)

    # Add edges
    edges = [
        ProbabilisticEdge("entry_point", "web_server", "network_access", 0.7, 0.2, 1.0),
        ProbabilisticEdge("web_server", "app_server", "service_call", 0.8, 0.3, 2.0),
        ProbabilisticEdge("app_server", "database", "database_query", 0.9, 0.1, 3.0)
    ]

    for edge in edges:
        graph.add_edge(edge)

    # Initialize risk propagation engine
    risk_engine = RiskPropagationEngine()

    # Perform risk propagation
    propagation_result = risk_engine.propagate_risk(graph)

    # Calculate risk metrics
    risk_metrics = risk_engine.calculate_risk_metrics(propagation_result)

    print("Risk Propagation Results:")
    print(f"Overall system risk: {risk_metrics['overall_system_risk']:.3f}")
    print(f"High-risk nodes: {len(risk_metrics['high_risk_nodes'])}")
    print(f"Risk centers: {len(risk_metrics['risk_centers'])}")

    # Optimize mitigation
    mitigation_plan = risk_engine.optimize_risk_mitigation(propagation_result, mitigation_budget=0.5)

    print(f"\nMitigation Plan:")
    print(f"Total risk reduction: {mitigation_plan['total_risk_reduction']:.3f}")
    print(f"Budget used: {mitigation_plan['total_budget_used']:.3f}")
    print(f"Cost effectiveness: {mitigation_plan['cost_effectiveness']:.3f}")
"""
Attack Prediction Engine using Graph Neural Networks

This module implements advanced attack prediction capabilities using GNNs,
temporal analysis, and probabilistic reasoning to predict attacker movements
and potential attack paths in the cyber defense graph.
"""

import torch
import torch.nn as nn
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import heapq

from .gnn_model import AttackPredictionEngine, ThreatPredictor
from .graph_feature_builder import AdvancedGraphFeatureBuilder

logger = logging.getLogger(__name__)

@dataclass
class AttackPath:
    """Represents a predicted attack path"""
    nodes: List[str]
    edges: List[Tuple[str, str]]
    probability: float
    risk_score: float
    estimated_time: timedelta
    required_privileges: List[str]
    detection_points: List[str]

@dataclass
class AttackerProfile:
    """Profile of an attacker based on observed behavior"""
    attacker_id: str
    tactics: List[str]  # MITRE ATT&CK tactics
    techniques: List[str]  # MITRE ATT&CK techniques
    tools: List[str]
    typical_entry_points: List[str]
    common_targets: List[str]
    risk_tolerance: float  # 0-1 scale
    sophistication_level: str  # 'low', 'medium', 'high', 'advanced'

class TemporalAttackPredictor:
    """
    Predicts attacks using temporal graph analysis and GNNs
    """

    def __init__(self, model_path: Optional[str] = None):
        self.gnn_engine = AttackPredictionEngine(model_path)
        self.feature_builder = AdvancedGraphFeatureBuilder()

        # Temporal analysis components
        self.temporal_window = timedelta(hours=24)  # Analysis window
        self.prediction_horizon = timedelta(hours=4)  # How far ahead to predict

        # Attack pattern database
        self.attack_patterns = self._load_attack_patterns()

        # Attacker profiling
        self.attacker_profiles = {}

        # Prediction cache
        self.prediction_cache = {}
        self.cache_ttl = timedelta(minutes=30)

    def _load_attack_patterns(self) -> Dict[str, Any]:
        """Load known attack patterns and tactics"""
        return {
            'lateral_movement': {
                'indicators': ['multiple_host_access', 'credential_theft', 'psexec_usage'],
                'typical_sequence': ['initial_access', 'credential_access', 'lateral_movement'],
                'risk_multiplier': 2.5
            },
            'privilege_escalation': {
                'indicators': ['sudo_abuse', 'uac_bypass', 'kernel_exploit'],
                'typical_sequence': ['execution', 'privilege_escalation'],
                'risk_multiplier': 3.0
            },
            'data_exfiltration': {
                'indicators': ['large_data_transfer', 'dns_tunneling', 'cloud_upload'],
                'typical_sequence': ['collection', 'exfiltration'],
                'risk_multiplier': 2.0
            },
            'persistence': {
                'indicators': ['cron_job', 'startup_modification', 'service_creation'],
                'typical_sequence': ['execution', 'persistence'],
                'risk_multiplier': 1.5
            }
        }

    def predict_attack_evolution(self, current_graph: Dict[str, Any],
                               historical_events: List[Dict[str, Any]],
                               time_horizon: timedelta = None) -> Dict[str, Any]:
        """
        Predict how attacks might evolve in the cyber environment

        Args:
            current_graph: Current state of the cyber defense graph
            historical_events: Recent security events
            time_horizon: How far ahead to predict

        Returns:
            predictions: Attack evolution predictions
        """
        if time_horizon is None:
            time_horizon = self.prediction_horizon

        predictions = {
            'predicted_attacks': [],
            'risk_evolution': [],
            'critical_paths': [],
            'recommended_actions': [],
            'confidence_score': 0.0,
            'timestamp': datetime.now()
        }

        try:
            # 1. Analyze current attacker positions
            attacker_positions = self._identify_attacker_positions(historical_events)

            # 2. Build temporal graph features
            temporal_features = self._build_temporal_features(current_graph, historical_events)

            # 3. Predict next moves using GNN
            next_moves = self._predict_next_attacker_moves(
                current_graph, temporal_features, attacker_positions
            )

            # 4. Simulate attack evolution
            attack_simulations = self._simulate_attack_evolution(
                current_graph, next_moves, time_horizon
            )

            # 5. Identify critical assets at risk
            critical_assets = self._identify_critical_assets(current_graph, attack_simulations)

            # 6. Generate mitigation recommendations
            recommendations = self._generate_mitigation_recommendations(
                attack_simulations, critical_assets
            )

            predictions.update({
                'predicted_attacks': attack_simulations,
                'critical_paths': critical_assets,
                'recommended_actions': recommendations,
                'confidence_score': self._calculate_prediction_confidence(attack_simulations)
            })

        except Exception as e:
            logger.error(f"Error in attack evolution prediction: {e}")
            predictions['error'] = str(e)

        return predictions

    def _identify_attacker_positions(self, historical_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify current positions of potential attackers"""
        positions = []

        # Look for suspicious activities in recent events
        recent_events = self._filter_recent_events(historical_events, self.temporal_window)

        suspicious_activities = defaultdict(list)

        for event in recent_events:
            if self._is_suspicious_event(event):
                actor = event.get('actor', event.get('source_ip', 'unknown'))
                suspicious_activities[actor].append(event)

        # Analyze each suspicious actor
        for actor, events in suspicious_activities.items():
            position = {
                'actor': actor,
                'current_nodes': set(),
                'compromised_assets': set(),
                'techniques_used': set(),
                'risk_level': self._calculate_actor_risk(events),
                'last_seen': max(e.get('timestamp', datetime.now()) for e in events)
            }

            # Extract compromised assets and techniques
            for event in events:
                if 'target' in event:
                    position['current_nodes'].add(event['target'])
                    if self._is_high_value_asset(event['target']):
                        position['compromised_assets'].add(event['target'])

                technique = self._classify_attack_technique(event)
                if technique:
                    position['techniques_used'].add(technique)

            positions.append(position)

        return positions

    def _build_temporal_features(self, current_graph: Dict[str, Any],
                               historical_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build temporal features for graph analysis"""
        temporal_features = {
            'node_activity_timeline': defaultdict(list),
            'edge_usage_patterns': defaultdict(list),
            'anomaly_timeline': [],
            'risk_evolution': []
        }

        # Process events in chronological order
        sorted_events = sorted(historical_events,
                             key=lambda x: x.get('timestamp', datetime.now()))

        current_time = datetime.now()

        for event in sorted_events:
            timestamp = event.get('timestamp', current_time)
            hours_ago = (current_time - timestamp).total_seconds() / 3600

            # Skip very old events
            if hours_ago > 24:
                continue

            # Node activity timeline
            if 'source' in event:
                temporal_features['node_activity_timeline'][event['source']].append({
                    'timestamp': timestamp,
                    'activity': event.get('type', 'unknown'),
                    'risk': self._calculate_event_risk(event)
                })

            if 'target' in event:
                temporal_features['node_activity_timeline'][event['target']].append({
                    'timestamp': timestamp,
                    'activity': event.get('type', 'unknown'),
                    'risk': self._calculate_event_risk(event)
                })

            # Edge usage patterns
            if 'source' in event and 'target' in event:
                edge_key = (event['source'], event['target'])
                temporal_features['edge_usage_patterns'][edge_key].append({
                    'timestamp': timestamp,
                    'type': event.get('type', 'unknown'),
                    'success': event.get('success', True)
                })

        return temporal_features

    def _predict_next_attacker_moves(self, current_graph: Dict[str, Any],
                                   temporal_features: Dict[str, Any],
                                   attacker_positions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict next moves of identified attackers"""
        next_moves = []

        for position in attacker_positions:
            actor_moves = {
                'actor': position['actor'],
                'current_position': list(position['current_nodes']),
                'predicted_moves': [],
                'confidence': 0.0
            }

            # Use GNN to predict likely next targets
            for current_node in position['current_nodes']:
                if current_node in current_graph.get('nodes', {}):
                    node_data = current_graph['nodes'][current_node]

                    # Get node features
                    historical_node_events = temporal_features['node_activity_timeline'].get(current_node, [])
                    node_features = self.feature_builder.build_node_features(
                        node_data, historical_node_events
                    )

                    # Find potential target nodes
                    potential_targets = self._find_potential_targets(
                        current_graph, current_node, position
                    )

                    for target_node in potential_targets:
                        if target_node in current_graph.get('nodes', {}):
                            target_data = current_graph['nodes'][target_node]

                            # Build edge features for potential connection
                            edge_data = {
                                'type': 'predicted_access',
                                'weight': 0.5,
                                'source': current_node,
                                'target': target_node
                            }

                            edge_features = self.feature_builder.build_edge_features(
                                edge_data, node_data, target_data
                            )

                            # Predict attack probability using GNN
                            attack_prob = self._predict_attack_probability(
                                node_features, edge_features, position
                            )

                            if attack_prob > 0.3:  # Threshold for considering
                                actor_moves['predicted_moves'].append({
                                    'from_node': current_node,
                                    'to_node': target_node,
                                    'probability': attack_prob,
                                    'technique': self._predict_attack_technique(position, target_node),
                                    'estimated_time': self._estimate_attack_time(current_node, target_node)
                                })

            # Sort by probability and take top predictions
            actor_moves['predicted_moves'].sort(key=lambda x: x['probability'], reverse=True)
            actor_moves['predicted_moves'] = actor_moves['predicted_moves'][:5]  # Top 5

            # Calculate overall confidence
            if actor_moves['predicted_moves']:
                actor_moves['confidence'] = np.mean([m['probability'] for m in actor_moves['predicted_moves']])

            next_moves.append(actor_moves)

        return next_moves

    def _simulate_attack_evolution(self, current_graph: Dict[str, Any],
                                 next_moves: List[Dict[str, Any]],
                                 time_horizon: timedelta) -> List[Dict[str, Any]]:
        """Simulate how attacks might evolve over time"""
        attack_simulations = []

        for moves in next_moves:
            simulation = {
                'actor': moves['actor'],
                'attack_paths': [],
                'final_targets': set(),
                'total_risk': 0.0,
                'timeline': []
            }

            # Start from current positions
            current_positions = set(moves['current_position'])

            # Simulate step-by-step attack evolution
            steps = int(time_horizon.total_seconds() / 3600)  # Hourly steps

            for step in range(steps):
                step_time = datetime.now() + timedelta(hours=step)

                # Consider each predicted move
                successful_moves = []
                for move in moves['predicted_moves']:
                    if move['from_node'] in current_positions:
                        # Simulate success probability
                        success_prob = move['probability'] * self._calculate_success_probability(move)

                        if np.random.random() < success_prob:
                            successful_moves.append(move)
                            current_positions.add(move['to_node'])

                            simulation['timeline'].append({
                                'time': step_time,
                                'action': f"Move from {move['from_node']} to {move['to_node']}",
                                'technique': move['technique'],
                                'success_probability': success_prob
                            })

                # Check if any critical assets are reached
                for position in current_positions:
                    if self._is_critical_asset(current_graph, position):
                        simulation['final_targets'].add(position)

                if not successful_moves:
                    break  # No more moves possible

            # Calculate attack paths
            simulation['attack_paths'] = self._extract_attack_paths(
                moves['current_position'], list(current_positions), simulation['timeline']
            )

            # Calculate total risk
            simulation['total_risk'] = self._calculate_simulation_risk(simulation)

            attack_simulations.append(simulation)

        return attack_simulations

    def _identify_critical_assets(self, current_graph: Dict[str, Any],
                                attack_simulations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Identify critical assets that are at risk"""
        critical_assets = []

        # Get all targeted assets across simulations
        all_targets = set()
        for sim in attack_simulations:
            all_targets.update(sim['final_targets'])

        # Analyze each critical asset
        for asset_id in all_targets:
            if asset_id in current_graph.get('nodes', {}):
                asset_data = current_graph['nodes'][asset_id]

                # Calculate risk based on attack simulations
                asset_risk = {
                    'asset_id': asset_id,
                    'asset_type': asset_data.get('type', 'unknown'),
                    'business_value': asset_data.get('business_value', 1.0),
                    'attackers_targeting': [],
                    'risk_score': 0.0,
                    'time_to_compromise': timedelta.max
                }

                for sim in attack_simulations:
                    if asset_id in sim['final_targets']:
                        asset_risk['attackers_targeting'].append(sim['actor'])

                        # Find earliest compromise time
                        compromise_times = [
                            event['time'] for event in sim['timeline']
                            if asset_id in event['action']
                        ]
                        if compromise_times:
                            earliest_time = min(compromise_times)
                            time_to_compromise = earliest_time - datetime.now()
                            asset_risk['time_to_compromise'] = min(
                                asset_risk['time_to_compromise'], time_to_compromise
                            )

                # Calculate overall risk score
                asset_risk['risk_score'] = self._calculate_asset_risk(asset_risk)

                critical_assets.append(asset_risk)

        # Sort by risk score
        critical_assets.sort(key=lambda x: x['risk_score'], reverse=True)

        return critical_assets

    def _generate_mitigation_recommendations(self, attack_simulations: List[Dict[str, Any]],
                                           critical_assets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate mitigation recommendations based on predictions"""
        recommendations = []

        # Priority 1: Protect critical assets
        for asset in critical_assets[:5]:  # Top 5 most critical
            if asset['time_to_compromise'] < timedelta(hours=12):
                recommendations.append({
                    'priority': 'critical',
                    'type': 'asset_protection',
                    'target': asset['asset_id'],
                    'action': 'immediate_isolation',
                    'reason': f"Asset at high risk of compromise within {asset['time_to_compromise']}",
                    'impact': 'high'
                })

        # Priority 2: Block attack paths
        attack_paths = []
        for sim in attack_simulations:
            attack_paths.extend(sim['attack_paths'])

        # Find common chokepoints
        chokepoints = self._identify_chokepoints(attack_paths)

        for chokepoint in chokepoints[:3]:  # Top 3 chokepoints
            recommendations.append({
                'priority': 'high',
                'type': 'path_blocking',
                'target': chokepoint['node'],
                'action': 'access_restriction',
                'reason': f"Critical chokepoint used in {chokepoint['frequency']} attack paths",
                'impact': 'medium'
            })

        # Priority 3: Attacker-specific mitigations
        for sim in attack_simulations:
            if sim['total_risk'] > 0.7:
                recommendations.append({
                    'priority': 'medium',
                    'type': 'attacker_containment',
                    'target': sim['actor'],
                    'action': 'behavioral_blocking',
                    'reason': f"High-risk attacker with {len(sim['attack_paths'])} potential paths",
                    'impact': 'medium'
                })

        return recommendations

    def _calculate_prediction_confidence(self, attack_simulations: List[Dict[str, Any]]) -> float:
        """Calculate overall confidence in predictions"""
        if not attack_simulations:
            return 0.0

        confidences = []
        for sim in attack_simulations:
            # Base confidence on number of data points and consistency
            path_count = len(sim['attack_paths'])
            timeline_events = len(sim['timeline'])

            confidence = min(0.9, (path_count * 0.1 + timeline_events * 0.05))
            confidences.append(confidence)

        return np.mean(confidences) if confidences else 0.0

    # Helper methods
    def _filter_recent_events(self, events: List[Dict[str, Any]], time_window: timedelta) -> List[Dict[str, Any]]:
        """Filter events within the specified time window"""
        cutoff_time = datetime.now() - time_window
        return [e for e in events if e.get('timestamp', datetime.now()) > cutoff_time]

    def _is_suspicious_event(self, event: Dict[str, Any]) -> bool:
        """Determine if an event is suspicious"""
        suspicious_types = [
            'failed_login', 'privilege_escalation', 'unauthorized_access',
            'data_exfiltration', 'malware_detection', 'anomaly_detected'
        ]

        return event.get('type', '').lower() in suspicious_types

    def _calculate_actor_risk(self, events: List[Dict[str, Any]]) -> float:
        """Calculate risk level of an actor based on their events"""
        risk_score = 0.0

        for event in events:
            event_type = event.get('type', '').lower()

            # Risk weights for different event types
            risk_weights = {
                'privilege_escalation': 0.8,
                'data_exfiltration': 0.9,
                'unauthorized_access': 0.7,
                'malware_detection': 0.6,
                'failed_login': 0.2
            }

            risk_score += risk_weights.get(event_type, 0.1)

        return min(risk_score / len(events), 1.0) if events else 0.0

    def _is_high_value_asset(self, node_id: str) -> bool:
        """Determine if a node represents a high-value asset"""
        # This would be configured based on asset classification
        high_value_types = ['database', 'domain_controller', 'secret_store']
        return any(hvt in node_id.lower() for hvt in high_value_types)

    def _classify_attack_technique(self, event: Dict[str, Any]) -> Optional[str]:
        """Classify the attack technique used in an event"""
        # Simplified technique classification
        technique_mapping = {
            'password_spray': 'brute_force',
            'sudo_abuse': 'privilege_escalation',
            'lateral_movement': 'lateral_movement',
            'data_transfer': 'exfiltration'
        }

        event_type = event.get('type', '').lower()
        return technique_mapping.get(event_type)

    def _calculate_event_risk(self, event: Dict[str, Any]) -> float:
        """Calculate risk score for a single event"""
        base_risk = 0.1

        risk_indicators = {
            'privilege_escalation': 0.8,
            'data_exfiltration': 0.9,
            'unauthorized_access': 0.7,
            'malware': 0.6,
            'failed_login': 0.2
        }

        event_type = event.get('type', '').lower()
        return risk_indicators.get(event_type, base_risk)

    def _find_potential_targets(self, graph: Dict[str, Any], current_node: str,
                              attacker_position: Dict[str, Any]) -> List[str]:
        """Find potential target nodes from current position"""
        potential_targets = []

        nodes = graph.get('nodes', {})
        edges = graph.get('edges', [])

        # Find directly connected nodes
        connected_nodes = set()
        for edge in edges:
            if edge.get('source') == current_node:
                connected_nodes.add(edge.get('target'))
            elif edge.get('target') == current_node:
                connected_nodes.add(edge.get('source'))

        # Filter for valuable targets
        for node_id in connected_nodes:
            if node_id in nodes:
                node_data = nodes[node_id]

                # Check if it's a valuable target for this attacker
                if self._is_valuable_target(node_data, attacker_position):
                    potential_targets.append(node_id)

        return potential_targets

    def _is_valuable_target(self, node_data: Dict[str, Any], attacker_position: Dict[str, Any]) -> bool:
        """Determine if a node is a valuable target"""
        node_type = node_data.get('type', '').lower()

        # High-value target types
        valuable_types = ['database', 'server', 'admin_system', 'secret_store']

        if node_type in valuable_types:
            return True

        # Check business value
        business_value = node_data.get('business_value', 0.0)
        if business_value > 0.7:
            return True

        return False

    def _predict_attack_probability(self, source_features: np.ndarray,
                                  edge_features: np.ndarray,
                                  attacker_context: Dict[str, Any]) -> float:
        """Predict probability of successful attack"""
        # Simplified probability calculation
        # In practice, this would use the trained GNN model

        base_probability = 0.1

        # Factor in attacker sophistication
        risk_level = attacker_context.get('risk_level', 0.5)
        base_probability += risk_level * 0.3

        # Factor in target defenses (simplified)
        # This would be based on node features
        defense_score = np.mean(source_features[:10])  # Simplified
        base_probability -= defense_score * 0.2

        return max(0.0, min(1.0, base_probability))

    def _predict_attack_technique(self, attacker_position: Dict[str, Any], target_node: str) -> str:
        """Predict which technique an attacker might use"""
        techniques = attacker_position.get('techniques_used', set())

        # Based on attacker's history, predict next technique
        if 'credential_access' in techniques:
            return 'lateral_movement'
        elif 'privilege_escalation' in techniques:
            return 'data_exfiltration'
        else:
            return 'initial_access'

    def _estimate_attack_time(self, source_node: str, target_node: str) -> timedelta:
        """Estimate time required for an attack"""
        # Simplified time estimation
        base_time = timedelta(minutes=30)

        # Add complexity factors
        complexity_factors = {
            'cross_network': timedelta(hours=1),
            'privilege_required': timedelta(hours=2),
            'stealth_required': timedelta(hours=1)
        }

        # Randomly add some complexity (simplified)
        if np.random.random() < 0.3:
            base_time += timedelta(hours=1)

        return base_time

    def _calculate_success_probability(self, move: Dict[str, Any]) -> float:
        """Calculate probability of attack success"""
        base_prob = move.get('probability', 0.5)

        # Factor in technique effectiveness
        technique = move.get('technique', 'unknown')
        technique_effectiveness = {
            'lateral_movement': 0.7,
            'privilege_escalation': 0.5,
            'data_exfiltration': 0.6,
            'initial_access': 0.4
        }

        effectiveness = technique_effectiveness.get(technique, 0.5)
        base_prob *= effectiveness

        return min(1.0, base_prob)

    def _is_critical_asset(self, graph: Dict[str, Any], node_id: str) -> bool:
        """Check if a node is a critical asset"""
        if node_id not in graph.get('nodes', {}):
            return False

        node_data = graph['nodes'][node_id]
        node_type = node_data.get('type', '').lower()

        critical_types = ['database', 'domain_controller', 'crown_jewel', 'secret_store']
        business_value = node_data.get('business_value', 0.0)

        return node_type in critical_types or business_value > 0.8

    def _extract_attack_paths(self, start_nodes: List[str], end_nodes: Set[str],
                            timeline: List[Dict[str, Any]]) -> List[AttackPath]:
        """Extract attack paths from simulation timeline"""
        paths = []

        for end_node in end_nodes:
            # Find path from start to end
            path = self._reconstruct_path(start_nodes, end_node, timeline)
            if path:
                paths.append(path)

        return paths

    def _reconstruct_path(self, start_nodes: List[str], end_node: str,
                         timeline: List[Dict[str, Any]]) -> Optional[AttackPath]:
        """Reconstruct an attack path from timeline"""
        # Simplified path reconstruction
        # In practice, this would use graph traversal algorithms

        path_nodes = []
        path_edges = []
        total_prob = 1.0
        total_time = timedelta()

        # Start from any start node
        current_node = start_nodes[0] if start_nodes else None
        if not current_node:
            return None

        path_nodes.append(current_node)

        # Follow timeline to reach end node
        for event in timeline:
            action = event.get('action', '')
            if f"to {end_node}" in action:
                # Extract source and target
                parts = action.split()
                if len(parts) >= 6:
                    from_node = parts[3]
                    to_node = parts[5]

                    if from_node == current_node:
                        path_nodes.append(to_node)
                        path_edges.append((from_node, to_node))
                        current_node = to_node
                        total_prob *= event.get('success_probability', 0.5)
                        total_time += timedelta(hours=1)  # Simplified

                        if to_node == end_node:
                            break

        if path_nodes and path_nodes[-1] == end_node:
            return AttackPath(
                nodes=path_nodes,
                edges=path_edges,
                probability=total_prob,
                risk_score=self._calculate_path_risk(path_nodes),
                estimated_time=total_time,
                required_privileges=['user'],  # Simplified
                detection_points=['network_monitoring', 'endpoint_detection']  # Simplified
            )

        return None

    def _calculate_path_risk(self, path_nodes: List[str]) -> float:
        """Calculate risk score for an attack path"""
        # Simplified risk calculation
        risk_score = 0.0

        for node in path_nodes:
            if self._is_critical_asset({}, node):  # Would need graph context
                risk_score += 0.3

        return min(1.0, risk_score)

    def _calculate_simulation_risk(self, simulation: Dict[str, Any]) -> float:
        """Calculate overall risk for a simulation"""
        base_risk = 0.0

        # Factor in number of paths
        base_risk += len(simulation['attack_paths']) * 0.1

        # Factor in critical targets reached
        base_risk += len(simulation['final_targets']) * 0.2

        # Factor in timeline length
        base_risk += len(simulation['timeline']) * 0.05

        return min(1.0, base_risk)

    def _calculate_asset_risk(self, asset_risk: Dict[str, Any]) -> float:
        """Calculate risk score for an asset"""
        risk_score = asset_risk['business_value'] * 0.4

        # Factor in number of attackers targeting
        attacker_count = len(asset_risk['attackers_targeting'])
        risk_score += min(attacker_count * 0.2, 0.4)

        # Factor in time to compromise
        time_factor = 1.0
        if asset_risk['time_to_compromise'] < timedelta(hours=1):
            time_factor = 1.0
        elif asset_risk['time_to_compromise'] < timedelta(hours=24):
            time_factor = 0.7
        else:
            time_factor = 0.3

        risk_score *= time_factor

        return min(1.0, risk_score)

    def _identify_chokepoints(self, attack_paths: List[AttackPath]) -> List[Dict[str, Any]]:
        """Identify critical chokepoints in attack paths"""
        node_frequency = defaultdict(int)

        for path in attack_paths:
            for node in path.nodes:
                node_frequency[node] += 1

        chokepoints = [
            {'node': node, 'frequency': freq}
            for node, freq in node_frequency.items()
            if freq > 1  # Used in multiple paths
        ]

        chokepoints.sort(key=lambda x: x['frequency'], reverse=True)
        return chokepoints
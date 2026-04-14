"""
Bayesian Update Engine for Attack Graph Analysis

This module implements Bayesian inference and updating mechanisms for
dynamically updating attack probabilities based on new evidence and observations.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict
import pandas as pd
from scipy.stats import beta, norm
from scipy.special import betaln

logger = logging.getLogger(__name__)

@dataclass
class Evidence:
    """Represents a piece of evidence that can update beliefs"""
    evidence_id: str
    evidence_type: str
    description: str
    strength: float  # 0-1, how strong/confident this evidence is
    timestamp: datetime
    source: str
    metadata: Dict[str, Any] = None

@dataclass
class BeliefState:
    """Represents the current belief state for a hypothesis"""
    hypothesis: str
    prior_probability: float
    current_probability: float
    uncertainty: float  # Standard deviation or confidence interval width
    last_updated: datetime
    evidence_history: List[Evidence] = None
    confidence_score: float = 0.0

    def __post_init__(self):
        if self.evidence_history is None:
            self.evidence_history = []

class BayesianUpdateEngine:
    """
    Engine for performing Bayesian updates on attack graph probabilities
    """

    def __init__(self):
        self.belief_states: Dict[str, BeliefState] = {}
        self.evidence_log: List[Evidence] = []

        # Default priors for common hypotheses
        self._initialize_default_priors()

        # Evidence type mappings for likelihood calculations
        self.evidence_likelihoods = self._initialize_evidence_likelihoods()

    def _initialize_default_priors(self):
        """Initialize default prior probabilities for common security hypotheses"""
        default_priors = {
            'active_attack': 0.05,  # 5% prior probability of active attack
            'lateral_movement': 0.03,
            'data_exfiltration': 0.02,
            'privilege_escalation': 0.04,
            'credential_theft': 0.06,
            'malware_infection': 0.03,
            'insider_threat': 0.01,
            'supply_chain_attack': 0.005,
            'zero_day_exploit': 0.001,
            'normal_activity': 0.85  # High prior for normal activity
        }

        for hypothesis, prior in default_priors.items():
            self.belief_states[hypothesis] = BeliefState(
                hypothesis=hypothesis,
                prior_probability=prior,
                current_probability=prior,
                uncertainty=self._calculate_uncertainty_from_prior(prior),
                last_updated=datetime.now()
            )

    def _initialize_evidence_likelihoods(self) -> Dict[str, Dict[str, float]]:
        """Initialize likelihood tables for different evidence types"""
        return {
            'failed_login': {
                'active_attack': 0.8,
                'credential_theft': 0.9,
                'brute_force': 0.95,
                'normal_activity': 0.3
            },
            'successful_login_unusual_time': {
                'active_attack': 0.7,
                'credential_theft': 0.8,
                'insider_threat': 0.6,
                'normal_activity': 0.1
            },
            'anomalous_network_traffic': {
                'active_attack': 0.6,
                'data_exfiltration': 0.8,
                'lateral_movement': 0.7,
                'normal_activity': 0.2
            },
            'privilege_escalation_attempt': {
                'active_attack': 0.9,
                'privilege_escalation': 0.95,
                'malware_infection': 0.7,
                'normal_activity': 0.05
            },
            'file_access_violation': {
                'active_attack': 0.7,
                'data_exfiltration': 0.6,
                'insider_threat': 0.8,
                'normal_activity': 0.1
            },
            'malware_detection': {
                'active_attack': 0.8,
                'malware_infection': 0.95,
                'supply_chain_attack': 0.6,
                'normal_activity': 0.01
            },
            'unusual_process_execution': {
                'active_attack': 0.6,
                'malware_infection': 0.7,
                'zero_day_exploit': 0.8,
                'normal_activity': 0.15
            },
            'data_volume_anomaly': {
                'data_exfiltration': 0.85,
                'active_attack': 0.5,
                'normal_activity': 0.25
            }
        }

    def _calculate_uncertainty_from_prior(self, prior: float) -> float:
        """Calculate initial uncertainty based on prior probability"""
        # Use beta distribution properties for uncertainty
        # Assume prior corresponds to mean of beta distribution
        # Use conservative uncertainty estimate
        if prior < 0.1:
            # Low probability events have high relative uncertainty
            return min(prior * 2, 0.5)
        elif prior > 0.5:
            # High probability events have lower relative uncertainty
            return (1 - prior) * 0.5
        else:
            # Medium probability events
            return 0.2

    def add_evidence(self, evidence: Evidence) -> Dict[str, Any]:
        """
        Add new evidence and update all relevant belief states

        Args:
            evidence: The evidence to incorporate

        Returns:
            updates: Dictionary of belief updates for each hypothesis
        """
        self.evidence_log.append(evidence)

        updates = {}

        # Update each hypothesis that could be affected by this evidence
        affected_hypotheses = self._get_affected_hypotheses(evidence)

        for hypothesis in affected_hypotheses:
            if hypothesis in self.belief_states:
                update_result = self._update_belief_state(hypothesis, evidence)
                updates[hypothesis] = update_result

        return updates

    def _get_affected_hypotheses(self, evidence: Evidence) -> List[str]:
        """Determine which hypotheses could be affected by the evidence"""
        if evidence.evidence_type in self.evidence_likelihoods:
            return list(self.evidence_likelihoods[evidence.evidence_type].keys())
        else:
            # If evidence type not recognized, affect all hypotheses
            return list(self.belief_states.keys())

    def _update_belief_state(self, hypothesis: str, evidence: Evidence) -> Dict[str, Any]:
        """Update a single belief state with new evidence"""
        belief_state = self.belief_states[hypothesis]

        # Get likelihood of evidence given hypothesis
        likelihood = self._calculate_likelihood(evidence, hypothesis)

        # Perform Bayesian update
        prior = belief_state.current_probability
        evidence_strength = evidence.strength

        # Bayesian update formula: P(H|E) = P(E|H) * P(H) / P(E)
        # Using simplified form with evidence strength as scaling factor
        likelihood_term = likelihood * evidence_strength

        # Calculate marginal likelihood P(E) = P(E|H) * P(H) + P(E|¬H) * P(¬H)
        # Assume P(E|¬H) = 0.5 for unknown complementary hypothesis
        marginal_likelihood = (likelihood_term * prior) + (0.5 * (1 - prior))

        if marginal_likelihood > 0:
            posterior = (likelihood_term * prior) / marginal_likelihood
        else:
            posterior = prior

        # Ensure posterior is within valid range
        posterior = max(0.0, min(1.0, posterior))

        # Update uncertainty (reduce uncertainty with more evidence)
        evidence_count = len(belief_state.evidence_history) + 1
        new_uncertainty = belief_state.uncertainty * (1 / np.sqrt(evidence_count))

        # Update belief state
        belief_state.current_probability = posterior
        belief_state.uncertainty = new_uncertainty
        belief_state.last_updated = datetime.now()
        belief_state.evidence_history.append(evidence)

        # Calculate confidence score based on evidence consistency
        belief_state.confidence_score = self._calculate_confidence_score(belief_state)

        update_result = {
            'hypothesis': hypothesis,
            'prior_probability': prior,
            'posterior_probability': posterior,
            'probability_change': posterior - prior,
            'new_uncertainty': new_uncertainty,
            'confidence_score': belief_state.confidence_score,
            'evidence_used': evidence.evidence_id
        }

        return update_result

    def _calculate_likelihood(self, evidence: Evidence, hypothesis: str) -> float:
        """Calculate likelihood of evidence given hypothesis"""
        if evidence.evidence_type in self.evidence_likelihoods:
            likelihood_table = self.evidence_likelihoods[evidence.evidence_type]
            return likelihood_table.get(hypothesis, 0.5)  # Default to 0.5 if not specified
        else:
            # For unknown evidence types, use neutral likelihood
            return 0.5

    def _calculate_confidence_score(self, belief_state: BeliefState) -> float:
        """Calculate confidence score based on evidence consistency and quantity"""
        if not belief_state.evidence_history:
            return 0.0

        evidence_count = len(belief_state.evidence_history)

        # Base confidence on evidence quantity (diminishing returns)
        quantity_confidence = min(evidence_count / 10.0, 1.0)

        # Calculate consistency of evidence
        recent_evidence = belief_state.evidence_history[-min(5, evidence_count):]

        if len(recent_evidence) < 2:
            consistency = 1.0
        else:
            # Check if recent evidence supports similar conclusions
            directions = []
            for ev in recent_evidence:
                likelihood = self._calculate_likelihood(ev, belief_state.hypothesis)
                directions.append(1 if likelihood > 0.5 else -1)

            # Consistency is fraction of evidence pointing in same direction
            majority_direction = 1 if sum(directions) >= 0 else -1
            consistency = sum(1 for d in directions if d == majority_direction) / len(directions)

        # Combine quantity and consistency
        confidence_score = quantity_confidence * consistency

        return confidence_score

    def get_belief_summary(self, min_probability: float = 0.0) -> Dict[str, Any]:
        """Get summary of current belief states"""
        summary = {
            'belief_states': {},
            'most_likely_hypothesis': None,
            'high_confidence_beliefs': [],
            'total_evidence_processed': len(self.evidence_log),
            'timestamp': datetime.now()
        }

        max_probability = 0.0
        most_likely = None

        for hypothesis, belief_state in self.belief_states.items():
            if belief_state.current_probability >= min_probability:
                belief_info = {
                    'probability': belief_state.current_probability,
                    'uncertainty': belief_state.uncertainty,
                    'confidence': belief_state.confidence_score,
                    'evidence_count': len(belief_state.evidence_history),
                    'last_updated': belief_state.last_updated
                }

                summary['belief_states'][hypothesis] = belief_info

                # Track most likely hypothesis
                if belief_state.current_probability > max_probability:
                    max_probability = belief_state.current_probability
                    most_likely = hypothesis

                # Track high confidence beliefs
                if belief_state.confidence_score > 0.7:
                    summary['high_confidence_beliefs'].append({
                        'hypothesis': hypothesis,
                        **belief_info
                    })

        summary['most_likely_hypothesis'] = most_likely

        return summary

    def predict_attack_evolution(self, current_beliefs: Dict[str, float],
                               time_horizon: timedelta) -> Dict[str, Any]:
        """
        Predict how attack probabilities might evolve over time

        Args:
            current_beliefs: Current belief states
            time_horizon: Time period to predict

        Returns:
            predictions: Predicted evolution of beliefs
        """
        predictions = {
            'time_points': [],
            'belief_evolution': {},
            'critical_thresholds': {},
            'recommended_actions': []
        }

        # Define time points for prediction
        hours_ahead = int(time_horizon.total_seconds() / 3600)
        time_points = [i for i in range(0, hours_ahead + 1, max(1, hours_ahead // 10))]

        predictions['time_points'] = time_points

        # Predict evolution for each hypothesis
        for hypothesis, current_prob in current_beliefs.items():
            evolution = self._predict_hypothesis_evolution(hypothesis, current_prob, time_points)
            predictions['belief_evolution'][hypothesis] = evolution

            # Identify critical thresholds
            if hypothesis in ['active_attack', 'data_exfiltration', 'privilege_escalation']:
                threshold = 0.7  # Action threshold
                if any(prob >= threshold for prob in evolution):
                    predictions['critical_thresholds'][hypothesis] = {
                        'threshold': threshold,
                        'predicted_time': next((t for t, p in zip(time_points, evolution) if p >= threshold), None)
                    }

        # Generate recommended actions based on predictions
        predictions['recommended_actions'] = self._generate_predictive_actions(predictions)

        return predictions

    def _predict_hypothesis_evolution(self, hypothesis: str, current_prob: float,
                                    time_points: List[int]) -> List[float]:
        """Predict how a hypothesis probability evolves over time"""
        evolution = [current_prob]

        # Simple exponential decay/growth model based on hypothesis type
        decay_rates = {
            'active_attack': -0.02,  # Slow decay if no new evidence
            'lateral_movement': -0.03,
            'data_exfiltration': -0.04,
            'normal_activity': 0.01,  # Slight increase over time
        }

        decay_rate = decay_rates.get(hypothesis, -0.05)

        for t in time_points[1:]:
            # Exponential evolution with bounds
            new_prob = current_prob * np.exp(decay_rate * t)
            new_prob = max(0.0, min(1.0, new_prob))
            evolution.append(new_prob)

        return evolution

    def _generate_predictive_actions(self, predictions: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate recommended actions based on predictions"""
        actions = []

        # Check for imminent threats
        for hypothesis, threshold_info in predictions['critical_thresholds'].items():
            if threshold_info['predicted_time'] is not None:
                time_to_threshold = threshold_info['predicted_time']

                if time_to_threshold <= 2:  # Within 2 hours
                    actions.append({
                        'priority': 'critical',
                        'action': f"Immediate investigation of potential {hypothesis}",
                        'timeframe': f"Within {time_to_threshold} hours",
                        'reason': f"{hypothesis} predicted to exceed threshold soon"
                    })
                elif time_to_threshold <= 24:  # Within 24 hours
                    actions.append({
                        'priority': 'high',
                        'action': f"Increased monitoring for {hypothesis} indicators",
                        'timeframe': f"Within {time_to_threshold} hours",
                        'reason': f"{hypothesis} trending toward critical threshold"
                    })

        # Check for high-probability hypotheses
        belief_evolution = predictions['belief_evolution']
        for hypothesis, probs in belief_evolution.items():
            final_prob = probs[-1]
            if final_prob > 0.6:
                actions.append({
                    'priority': 'medium',
                    'action': f"Enhanced monitoring for {hypothesis}",
                    'timeframe': "Ongoing",
                    'reason': f"High predicted probability of {hypothesis} ({final_prob:.2f})"
                })

        return actions

    def perform_sensitivity_analysis(self, hypothesis: str,
                                   parameter_ranges: Dict[str, Tuple[float, float]]) -> Dict[str, Any]:
        """
        Perform sensitivity analysis on belief updates

        Args:
            hypothesis: Hypothesis to analyze
            parameter_ranges: Ranges for parameters to test

        Returns:
            sensitivity_results: Results of sensitivity analysis
        """
        results = {
            'hypothesis': hypothesis,
            'parameter_sensitivity': {},
            'robustness_score': 0.0
        }

        if hypothesis not in self.belief_states:
            return results

        base_probability = self.belief_states[hypothesis].current_probability

        # Test sensitivity to different parameters
        for param, (min_val, max_val) in parameter_ranges.items():
            param_sensitivities = []

            # Test multiple values within range
            test_values = np.linspace(min_val, max_val, 10)

            for test_val in test_values:
                # Create modified evidence with test parameter
                test_evidence = Evidence(
                    evidence_id=f"sensitivity_test_{param}_{test_val}",
                    evidence_type="sensitivity_test",
                    description=f"Testing sensitivity to {param} = {test_val}",
                    strength=test_val,
                    timestamp=datetime.now(),
                    source="sensitivity_analysis"
                )

                # Calculate what probability would be with this evidence
                likelihood = self._calculate_likelihood(test_evidence, hypothesis)
                test_prob = self._bayesian_update_formula(base_probability, likelihood, test_val)

                param_sensitivities.append(test_prob)

            # Calculate sensitivity metrics
            sensitivity_range = max(param_sensitivities) - min(param_sensitivities)
            results['parameter_sensitivity'][param] = {
                'range': sensitivity_range,
                'min_probability': min(param_sensitivities),
                'max_probability': max(param_sensitivities),
                'relative_sensitivity': sensitivity_range / base_probability if base_probability > 0 else 0
            }

        # Calculate overall robustness score
        sensitivities = [info['relative_sensitivity'] for info in results['parameter_sensitivity'].values()]
        results['robustness_score'] = 1.0 / (1.0 + np.mean(sensitivities))  # Lower sensitivity = higher robustness

        return results

    def _bayesian_update_formula(self, prior: float, likelihood: float, evidence_strength: float) -> float:
        """Simplified Bayesian update formula for sensitivity analysis"""
        likelihood_term = likelihood * evidence_strength
        marginal = (likelihood_term * prior) + (0.5 * (1 - prior))

        if marginal > 0:
            return (likelihood_term * prior) / marginal
        else:
            return prior

    def export_belief_states(self, format: str = 'json') -> Union[str, Dict[str, Any]]:
        """Export current belief states"""
        export_data = {
            'belief_states': {},
            'evidence_log': [],
            'export_timestamp': datetime.now().isoformat()
        }

        for hypothesis, belief_state in self.belief_states.items():
            export_data['belief_states'][hypothesis] = {
                'prior_probability': belief_state.prior_probability,
                'current_probability': belief_state.current_probability,
                'uncertainty': belief_state.uncertainty,
                'confidence_score': belief_state.confidence_score,
                'last_updated': belief_state.last_updated.isoformat(),
                'evidence_count': len(belief_state.evidence_history)
            }

        for evidence in self.evidence_log[-100:]:  # Last 100 evidence items
            export_data['evidence_log'].append({
                'evidence_id': evidence.evidence_id,
                'evidence_type': evidence.evidence_type,
                'description': evidence.description,
                'strength': evidence.strength,
                'timestamp': evidence.timestamp.isoformat(),
                'source': evidence.source
            })

        if format == 'json':
            return json.dumps(export_data, indent=2)
        else:
            return export_data

# Example usage and testing
if __name__ == "__main__":
    engine = BayesianUpdateEngine()

    # Add some evidence
    evidence1 = Evidence(
        evidence_id="ev001",
        evidence_type="failed_login",
        description="Multiple failed login attempts from external IP",
        strength=0.8,
        timestamp=datetime.now(),
        source="authentication_system"
    )

    updates1 = engine.add_evidence(evidence1)
    print("Evidence 1 updates:")
    for hypothesis, update in updates1.items():
        print(f"  {hypothesis}: {update['prior_probability']:.3f} -> {update['posterior_probability']:.3f}")

    # Add more evidence
    evidence2 = Evidence(
        evidence_id="ev002",
        evidence_type="anomalous_network_traffic",
        description="Unusual outbound traffic to external host",
        strength=0.7,
        timestamp=datetime.now(),
        source="network_monitor"
    )

    updates2 = engine.add_evidence(evidence2)
    print("\nEvidence 2 updates:")
    for hypothesis, update in updates2.items():
        print(f"  {hypothesis}: {update['prior_probability']:.3f} -> {update['posterior_probability']:.3f}")

    # Get belief summary
    summary = engine.get_belief_summary(min_probability=0.01)
    print(f"\nMost likely hypothesis: {summary['most_likely_hypothesis']}")
    print(f"High confidence beliefs: {len(summary['high_confidence_beliefs'])}")

    # Predict evolution
    current_beliefs = {h: bs.current_probability for h, bs in engine.belief_states.items()}
    predictions = engine.predict_attack_evolution(current_beliefs, timedelta(hours=24))

    print(f"\nCritical thresholds detected: {len(predictions['critical_thresholds'])}")
    print(f"Recommended actions: {len(predictions['recommended_actions'])}")
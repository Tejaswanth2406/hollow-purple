"""
Probability Engine for Attack Graph Analysis

This module provides probabilistic computation capabilities for attack graphs,
including Bayesian inference, uncertainty quantification, and risk assessment.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from scipy.stats import beta, norm, gamma
from collections import defaultdict
import pandas as pd

logger = logging.getLogger(__name__)

@dataclass
class ProbabilityDistribution:
    """Represents a probability distribution for uncertainty modeling"""
    distribution_type: str  # 'beta', 'normal', 'gamma', etc.
    parameters: Dict[str, float]
    confidence_interval: Tuple[float, float] = (0.0, 1.0)

    def sample(self, n_samples: int = 1) -> Union[float, np.ndarray]:
        """Sample from the distribution"""
        if self.distribution_type == 'beta':
            a, b = self.parameters.get('a', 1), self.parameters.get('b', 1)
            return beta.rvs(a, b, size=n_samples)
        elif self.distribution_type == 'normal':
            mu, sigma = self.parameters.get('mu', 0), self.parameters.get('sigma', 1)
            return norm.rvs(mu, sigma, size=n_samples)
        elif self.distribution_type == 'gamma':
            shape, scale = self.parameters.get('shape', 1), self.parameters.get('scale', 1)
            return gamma.rvs(shape, scale=scale, size=n_samples)
        else:
            return np.random.random(n_samples)

    def mean(self) -> float:
        """Get the mean of the distribution"""
        if self.distribution_type == 'beta':
            a, b = self.parameters.get('a', 1), self.parameters.get('b', 1)
            return a / (a + b)
        elif self.distribution_type == 'normal':
            return self.parameters.get('mu', 0)
        elif self.distribution_type == 'gamma':
            return self.parameters.get('shape', 1) * self.parameters.get('scale', 1)
        else:
            return 0.5

    def update_from_observations(self, observations: List[float]):
        """Update distribution parameters from observations"""
        if not observations:
            return

        if self.distribution_type == 'beta':
            # Use observations to update beta distribution
            successes = sum(1 for obs in observations if obs > 0.5)
            failures = len(observations) - successes

            self.parameters['a'] = self.parameters.get('a', 1) + successes
            self.parameters['b'] = self.parameters.get('b', 1) + failures

        elif self.distribution_type == 'normal':
            # Update normal distribution
            mean_obs = np.mean(observations)
            var_obs = np.var(observations)

            prior_mu = self.parameters.get('mu', 0)
            prior_sigma = self.parameters.get('sigma', 1)
            n = len(observations)

            # Bayesian update for normal distribution
            new_mu = (prior_mu / prior_sigma**2 + n * mean_obs / var_obs) / (1/prior_sigma**2 + n/var_obs)
            new_sigma = np.sqrt(1 / (1/prior_sigma**2 + n/var_obs))

            self.parameters['mu'] = new_mu
            self.parameters['sigma'] = new_sigma

@dataclass
class BayesianUpdate:
    """Represents a Bayesian update to a probability"""
    prior_probability: float
    likelihood: float
    evidence_strength: float
    posterior_probability: float
    confidence: float
    timestamp: datetime

class ProbabilityEngine:
    """
    Core engine for probabilistic computations in attack graphs
    """

    def __init__(self):
        self.distributions: Dict[str, ProbabilityDistribution] = {}
        self.bayesian_updates: List[BayesianUpdate] = []

        # Default distributions for common scenarios
        self._initialize_default_distributions()

    def _initialize_default_distributions(self):
        """Initialize default probability distributions"""
        # Vulnerability exploitation success rates
        self.distributions['remote_code_execution'] = ProbabilityDistribution(
            'beta', {'a': 2, 'b': 8}  # Mean ~0.2
        )

        self.distributions['privilege_escalation'] = ProbabilityDistribution(
            'beta', {'a': 1, 'b': 9}  # Mean ~0.1
        )

        self.distributions['lateral_movement'] = ProbabilityDistribution(
            'beta', {'a': 3, 'b': 7}  # Mean ~0.3
        )

        # Detection probabilities
        self.distributions['ids_detection'] = ProbabilityDistribution(
            'beta', {'a': 7, 'b': 3}  # Mean ~0.7
        )

        self.distributions['endpoint_detection'] = ProbabilityDistribution(
            'beta', {'a': 8, 'b': 2}  # Mean ~0.8
        )

        # Attacker skill levels
        self.distributions['skilled_attacker'] = ProbabilityDistribution(
            'beta', {'a': 6, 'b': 4}  # Mean ~0.6
        )

        self.distributions['advanced_attacker'] = ProbabilityDistribution(
            'beta', {'a': 8, 'b': 2}  # Mean ~0.8
        )

    def calculate_conditional_probability(self, event: str, conditions: Dict[str, Any]) -> float:
        """
        Calculate conditional probability P(event | conditions)

        Args:
            event: The event to calculate probability for
            conditions: Dictionary of conditioning variables

        Returns:
            conditional_probability: Probability of event given conditions
        """
        base_prob = self.distributions.get(event, ProbabilityDistribution('beta', {'a': 1, 'b': 1})).mean()

        # Apply conditional modifiers
        modifiers = []

        # Attacker skill modifier
        attacker_skill = conditions.get('attacker_skill', 'average')
        if attacker_skill == 'skilled':
            skill_dist = self.distributions.get('skilled_attacker', ProbabilityDistribution('beta', {'a': 1, 'b': 1}))
            modifiers.append(skill_dist.mean())
        elif attacker_skill == 'advanced':
            skill_dist = self.distributions.get('advanced_attacker', ProbabilityDistribution('beta', {'a': 1, 'b': 1}))
            modifiers.append(skill_dist.mean())

        # Defense strength modifier
        defense_level = conditions.get('defense_level', 'basic')
        if defense_level == 'advanced':
            modifiers.append(0.3)  # Reduce probability due to strong defenses
        elif defense_level == 'basic':
            modifiers.append(0.8)  # Slightly reduce probability

        # Time pressure modifier
        time_pressure = conditions.get('time_pressure', 'normal')
        if time_pressure == 'high':
            modifiers.append(0.5)  # Reduce success probability under time pressure

        # Detection risk modifier
        detection_risk = conditions.get('detection_risk', 'medium')
        if detection_risk == 'high':
            detection_dist = self.distributions.get('ids_detection', ProbabilityDistribution('beta', {'a': 1, 'b': 1}))
            detection_prob = detection_dist.mean()
            modifiers.append(1 - detection_prob)  # Reduce by detection probability

        # Combine modifiers (geometric mean for multiplicative effects)
        if modifiers:
            combined_modifier = np.exp(np.mean(np.log(modifiers)))
            conditional_prob = base_prob * combined_modifier
        else:
            conditional_prob = base_prob

        return max(0.0, min(1.0, conditional_prob))

    def perform_bayesian_update(self, hypothesis: str, evidence: Dict[str, Any]) -> BayesianUpdate:
        """
        Perform Bayesian update on a hypothesis given evidence

        Args:
            hypothesis: The hypothesis to update
            evidence: Evidence dictionary

        Returns:
            update: BayesianUpdate object with results
        """
        # Get prior probability
        prior = self.distributions.get(hypothesis, ProbabilityDistribution('beta', {'a': 1, 'b': 1})).mean()

        # Calculate likelihood of evidence given hypothesis
        likelihood = self._calculate_evidence_likelihood(evidence, hypothesis)

        # Calculate posterior probability
        evidence_strength = evidence.get('confidence', 1.0)
        posterior = (prior * likelihood * evidence_strength) / (
            (prior * likelihood * evidence_strength) + ((1 - prior) * (1 - likelihood) * evidence_strength)
        )

        # Calculate confidence in the update
        confidence = min(1.0, evidence_strength * abs(posterior - prior))

        update = BayesianUpdate(
            prior_probability=prior,
            likelihood=likelihood,
            evidence_strength=evidence_strength,
            posterior_probability=posterior,
            confidence=confidence,
            timestamp=datetime.now()
        )

        self.bayesian_updates.append(update)

        return update

    def _calculate_evidence_likelihood(self, evidence: Dict[str, Any], hypothesis: str) -> float:
        """Calculate likelihood of evidence given hypothesis"""
        evidence_type = evidence.get('type', '')

        # Likelihood mappings based on evidence type and hypothesis
        likelihood_map = {
            'compromise_detected': {
                'attack_in_progress': 0.9,
                'normal_activity': 0.1
            },
            'anomaly_detected': {
                'attack_in_progress': 0.7,
                'normal_activity': 0.2
            },
            'failed_login': {
                'brute_force_attack': 0.8,
                'normal_activity': 0.3
            },
            'successful_login': {
                'credential_theft': 0.6,
                'normal_activity': 0.9
            },
            'data_access': {
                'data_exfiltration': 0.8,
                'normal_activity': 0.4
            }
        }

        type_likelihoods = likelihood_map.get(evidence_type, {})
        return type_likelihoods.get(hypothesis, 0.5)

    def monte_carlo_simulation(self, attack_graph: Any, n_simulations: int = 1000) -> Dict[str, Any]:
        """
        Perform Monte Carlo simulation of attack scenarios

        Args:
            attack_graph: The attack graph to simulate
            n_simulations: Number of simulation runs

        Returns:
            results: Simulation results and statistics
        """
        simulation_results = []

        for sim in range(n_simulations):
            result = self._run_single_simulation(attack_graph)
            simulation_results.append(result)

        # Analyze results
        success_rates = [r['success'] for r in simulation_results]
        compromise_times = [r['time_to_compromise'] for r in simulation_results if r['success']]
        compromised_assets = [r['compromised_assets'] for r in simulation_results]

        # Calculate statistics
        stats = {
            'total_simulations': n_simulations,
            'success_rate': np.mean(success_rates),
            'mean_compromise_time': np.mean(compromise_times) if compromise_times else None,
            'median_compromise_time': np.median(compromise_times) if compromise_times else None,
            'successful_simulations': sum(success_rates),
            'most_compromised_assets': self._find_most_compromised_assets(compromised_assets),
            'simulation_results': simulation_results[:100]  # Keep first 100 for analysis
        }

        return stats

    def _run_single_simulation(self, attack_graph: Any) -> Dict[str, Any]:
        """Run a single attack simulation"""
        # This is a simplified simulation - in practice, would use the actual attack graph
        simulation_result = {
            'success': False,
            'time_to_compromise': None,
            'compromised_assets': [],
            'attack_path': [],
            'detection_events': []
        }

        # Simulate attack progression
        current_time = 0
        compromised_nodes = set()
        attack_path = []

        # Start from external entry point (simplified)
        entry_points = ['external_ip_1', 'external_ip_2']  # Would come from graph

        for entry_point in entry_points:
            if np.random.random() < 0.3:  # 30% chance of successful initial access
                compromised_nodes.add(entry_point)
                attack_path.append(entry_point)
                simulation_result['success'] = True
                current_time += np.random.exponential(30)  # Minutes

                # Simulate lateral movement
                potential_targets = ['web_server', 'app_server', 'database']
                for target in potential_targets:
                    if np.random.random() < 0.4:  # 40% chance of successful movement
                        compromised_nodes.add(target)
                        attack_path.append(target)
                        current_time += np.random.exponential(45)

                        # Check for detection
                        if np.random.random() < 0.2:  # 20% chance of detection
                            simulation_result['detection_events'].append({
                                'time': current_time,
                                'node': target
                            })

                break

        simulation_result.update({
            'time_to_compromise': current_time if simulation_result['success'] else None,
            'compromised_assets': list(compromised_nodes),
            'attack_path': attack_path
        })

        return simulation_result

    def _find_most_compromised_assets(self, compromised_lists: List[List[str]]) -> List[Tuple[str, int]]:
        """Find assets most frequently compromised across simulations"""
        asset_counts = defaultdict(int)

        for asset_list in compromised_lists:
            for asset in asset_list:
                asset_counts[asset] += 1

        # Sort by frequency
        sorted_assets = sorted(asset_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_assets

    def uncertainty_quantification(self, probabilities: Dict[str, float],
                                 confidence_levels: List[float] = None) -> Dict[str, Any]:
        """
        Quantify uncertainty in probability estimates

        Args:
            probabilities: Dictionary of probability estimates
            confidence_levels: Confidence levels to compute intervals for

        Returns:
            uncertainty_analysis: Uncertainty quantification results
        """
        if confidence_levels is None:
            confidence_levels = [0.95, 0.99]

        uncertainty_results = {}

        for prob_name, prob_value in probabilities.items():
            # Assume beta distribution for uncertainty modeling
            # Use probability value to estimate distribution parameters
            # This is a simplification - in practice, use actual distribution data

            # Estimate alpha and beta from mean and assumed variance
            mean = prob_value
            variance = min(mean * (1 - mean) / 10, 0.1)  # Conservative variance estimate

            alpha = mean * (mean * (1 - mean) / variance - 1)
            beta_param = (1 - mean) * (mean * (1 - mean) / variance - 1)

            alpha = max(alpha, 1.0)
            beta_param = max(beta_param, 1.0)

            # Calculate confidence intervals
            intervals = {}
            for conf_level in confidence_levels:
                lower = beta.ppf((1 - conf_level) / 2, alpha, beta_param)
                upper = beta.ppf((1 + conf_level) / 2, alpha, beta_param)
                intervals[f"{int(conf_level*100)}%"] = (lower, upper)

            uncertainty_results[prob_name] = {
                'mean': mean,
                'variance': variance,
                'alpha': alpha,
                'beta': beta_param,
                'confidence_intervals': intervals,
                'uncertainty_range': intervals[f"{int(confidence_levels[0]*100)}%"][1] -
                                   intervals[f"{int(confidence_levels[0]*100)}%"][0]
            }

        return uncertainty_results

    def risk_assessment(self, threat_model: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform comprehensive risk assessment

        Args:
            threat_model: Threat model containing assets, threats, and vulnerabilities

        Returns:
            risk_assessment: Comprehensive risk assessment
        """
        assessment = {
            'asset_risks': {},
            'threat_risks': {},
            'overall_risk_score': 0.0,
            'risk_breakdown': {},
            'mitigation_priorities': [],
            'timestamp': datetime.now()
        }

        # Assess asset-level risks
        assets = threat_model.get('assets', [])
        for asset in assets:
            asset_risk = self._assess_asset_risk(asset, threat_model)
            assessment['asset_risks'][asset['id']] = asset_risk

        # Assess threat-level risks
        threats = threat_model.get('threats', [])
        for threat in threats:
            threat_risk = self._assess_threat_risk(threat, threat_model)
            assessment['threat_risks'][threat['id']] = threat_risk

        # Calculate overall risk
        asset_risks = [r['total_risk'] for r in assessment['asset_risks'].values()]
        threat_risks = [r['probability'] * r['impact'] for r in assessment['threat_risks'].values()]

        assessment['overall_risk_score'] = np.mean(asset_risks + threat_risks)

        # Risk breakdown by category
        assessment['risk_breakdown'] = self._categorize_risks(assessment)

        # Prioritize mitigations
        assessment['mitigation_priorities'] = self._prioritize_mitigations(assessment)

        return assessment

    def _assess_asset_risk(self, asset: Dict[str, Any], threat_model: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk for a single asset"""
        asset_risk = {
            'asset_id': asset['id'],
            'asset_type': asset.get('type', 'unknown'),
            'vulnerability_score': 0.0,
            'threat_exposure': 0.0,
            'impact_score': asset.get('business_value', 1.0),
            'total_risk': 0.0
        }

        # Calculate vulnerability score
        vulnerabilities = asset.get('vulnerabilities', [])
        if vulnerabilities:
            vuln_scores = [v.get('severity', 0.5) for v in vulnerabilities]
            asset_risk['vulnerability_score'] = np.mean(vuln_scores)

        # Calculate threat exposure
        threats = threat_model.get('threats', [])
        exposure_scores = []
        for threat in threats:
            # Check if threat can target this asset type
            if asset['type'] in threat.get('target_types', []):
                exposure_scores.append(threat.get('likelihood', 0.5))

        asset_risk['threat_exposure'] = np.mean(exposure_scores) if exposure_scores else 0.0

        # Calculate total risk
        asset_risk['total_risk'] = (
            asset_risk['vulnerability_score'] *
            asset_risk['threat_exposure'] *
            asset_risk['impact_score']
        )

        return asset_risk

    def _assess_threat_risk(self, threat: Dict[str, Any], threat_model: Dict[str, Any]) -> Dict[str, Any]:
        """Assess risk for a single threat"""
        threat_risk = {
            'threat_id': threat['id'],
            'threat_type': threat.get('type', 'unknown'),
            'probability': threat.get('likelihood', 0.5),
            'impact': threat.get('potential_impact', 1.0),
            'detectability': threat.get('detectability', 0.5),
            'total_risk': 0.0
        }

        # Adjust probability based on defenses
        defenses = threat_model.get('defenses', [])
        defense_effectiveness = np.mean([d.get('effectiveness', 0.5) for d in defenses])
        threat_risk['adjusted_probability'] = threat_risk['probability'] * (1 - defense_effectiveness)

        # Calculate total risk
        threat_risk['total_risk'] = threat_risk['adjusted_probability'] * threat_risk['impact']

        return threat_risk

    def _categorize_risks(self, assessment: Dict[str, Any]) -> Dict[str, Any]:
        """Categorize risks by type and severity"""
        categories = {
            'critical': {'count': 0, 'assets': [], 'avg_risk': 0.0},
            'high': {'count': 0, 'assets': [], 'avg_risk': 0.0},
            'medium': {'count': 0, 'assets': [], 'avg_risk': 0.0},
            'low': {'count': 0, 'assets': [], 'avg_risk': 0.0}
        }

        for asset_id, risk in assessment['asset_risks'].items():
            risk_score = risk['total_risk']

            if risk_score >= 0.8:
                category = 'critical'
            elif risk_score >= 0.6:
                category = 'high'
            elif risk_score >= 0.3:
                category = 'medium'
            else:
                category = 'low'

            categories[category]['count'] += 1
            categories[category]['assets'].append(asset_id)

        # Calculate average risks
        for category, data in categories.items():
            if data['assets']:
                asset_risks = [assessment['asset_risks'][asset]['total_risk'] for asset in data['assets']]
                data['avg_risk'] = np.mean(asset_risks)

        return categories

    def _prioritize_mitigations(self, assessment: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize mitigation actions based on risk assessment"""
        mitigations = []

        # Sort assets by risk
        risky_assets = sorted(
            assessment['asset_risks'].items(),
            key=lambda x: x[1]['total_risk'],
            reverse=True
        )

        for asset_id, risk in risky_assets[:10]:  # Top 10 riskiest assets
            mitigation = {
                'asset_id': asset_id,
                'risk_score': risk['total_risk'],
                'priority': 'high' if risk['total_risk'] > 0.7 else 'medium',
                'recommended_actions': self._suggest_mitigations(risk),
                'expected_risk_reduction': min(risk['total_risk'] * 0.6, risk['total_risk'])
            }
            mitigations.append(mitigation)

        return mitigations

    def _suggest_mitigations(self, asset_risk: Dict[str, Any]) -> List[str]:
        """Suggest mitigation actions for an asset"""
        suggestions = []

        vuln_score = asset_risk.get('vulnerability_score', 0)
        exposure_score = asset_risk.get('threat_exposure', 0)

        if vuln_score > 0.7:
            suggestions.append("Apply security patches and updates")
            suggestions.append("Implement vulnerability scanning")

        if exposure_score > 0.7:
            suggestions.append("Implement network segmentation")
            suggestions.append("Deploy intrusion detection systems")

        if asset_risk.get('impact_score', 0) > 0.8:
            suggestions.append("Implement additional monitoring")
            suggestions.append("Create incident response procedures")

        if not suggestions:
            suggestions.append("Regular security assessments")
            suggestions.append("Employee security training")

        return suggestions

# Example usage
if __name__ == "__main__":
    engine = ProbabilityEngine()

    # Test conditional probability calculation
    conditions = {
        'attacker_skill': 'skilled',
        'defense_level': 'basic',
        'detection_risk': 'medium'
    }

    prob = engine.calculate_conditional_probability('remote_code_execution', conditions)
    print(f"Conditional probability of RCE: {prob:.3f}")

    # Test Bayesian update
    evidence = {
        'type': 'compromise_detected',
        'confidence': 0.8
    }

    update = engine.perform_bayesian_update('attack_in_progress', evidence)
    print(f"Bayesian update: {update.prior_probability:.3f} -> {update.posterior_probability:.3f}")

    # Test uncertainty quantification
    probabilities = {
        'asset_compromise': 0.3,
        'data_breach': 0.1,
        'lateral_movement': 0.5
    }

    uncertainty = engine.uncertainty_quantification(probabilities)
    print("Uncertainty analysis:")
    for prob_name, analysis in uncertainty.items():
        ci_95 = analysis['confidence_intervals']['95%']
        print(f"  {prob_name}: {analysis['mean']:.3f} ± {analysis['uncertainty_range']:.3f} (95% CI: {ci_95[0]:.3f}-{ci_95[1]:.3f})")
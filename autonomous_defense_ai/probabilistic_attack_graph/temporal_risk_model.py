"""
Temporal Risk Modeling for Attack Graphs

This module implements temporal risk evolution models for cyber attack graphs,
including time-series analysis, risk forecasting, and temporal pattern recognition
for predicting attack progression over time.
"""

import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import logging
from collections import defaultdict, deque
import pandas as pd
from scipy import stats
from scipy.optimize import curve_fit
import warnings

logger = logging.getLogger(__name__)

@dataclass
class TemporalRiskPoint:
    """A single point in temporal risk evolution"""
    timestamp: datetime
    risk_vector: 'RiskVector'  # Forward reference to avoid circular import
    confidence: float
    contributing_factors: Dict[str, float]
    prediction_horizon: Optional[timedelta] = None

@dataclass
class RiskTimeSeries:
    """Time series of risk evolution"""
    node_id: str
    risk_values: List[float]
    timestamps: List[datetime]
    confidence_intervals: List[Tuple[float, float]]
    trend_parameters: Dict[str, Any]
    seasonality_patterns: Dict[str, Any]
    anomaly_scores: List[float]

@dataclass
class TemporalRiskForecast:
    """Forecast of future risk evolution"""
    node_id: str
    forecast_horizon: timedelta
    predicted_risks: List[float]
    forecast_timestamps: List[datetime]
    confidence_intervals: List[Tuple[float, float]]
    forecast_method: str
    model_parameters: Dict[str, Any]
    accuracy_metrics: Dict[str, float]

class TemporalRiskModel:
    """
    Advanced temporal modeling for risk evolution in attack graphs
    """

    def __init__(self, time_window: timedelta = timedelta(hours=24),
                 forecast_horizon: timedelta = timedelta(hours=6),
                 min_data_points: int = 10):
        self.time_window = time_window
        self.forecast_horizon = forecast_horizon
        self.min_data_points = min_data_points

        # Temporal modeling parameters
        self.smoothing_alpha = 0.3
        self.trend_detection_threshold = 0.1
        self.seasonality_periods = [timedelta(hours=1), timedelta(hours=6),
                                   timedelta(hours=24), timedelta(days=7)]

        # Forecasting models
        self.forecasting_methods = {
            'exponential_smoothing': self._exponential_smoothing_forecast,
            'linear_regression': self._linear_regression_forecast,
            'arima': self._arima_forecast,
            'prophet_like': self._prophet_like_forecast
        }

    def build_temporal_risk_series(self, risk_history: List[TemporalRiskPoint],
                                 node_id: str) -> RiskTimeSeries:
        """
        Build a temporal risk time series from historical data

        Args:
            risk_history: Historical risk points
            node_id: Node identifier

        Returns:
            risk_series: Complete time series analysis
        """
        if len(risk_history) < self.min_data_points:
            logger.warning(f"Insufficient data points for {node_id}: {len(risk_history)}")
            return self._create_minimal_series(node_id, risk_history)

        # Extract time series data
        timestamps = [point.timestamp for point in risk_history]
        risk_values = [point.risk_vector.magnitude() for point in risk_history]
        confidence_values = [point.confidence for point in risk_history]

        # Sort by timestamp
        sorted_indices = np.argsort(timestamps)
        timestamps = [timestamps[i] for i in sorted_indices]
        risk_values = [risk_values[i] for i in sorted_indices]
        confidence_values = [confidence_values[i] for i in sorted_indices]

        # Calculate confidence intervals
        confidence_intervals = self._calculate_confidence_intervals(
            risk_values, confidence_values
        )

        # Detect trends
        trend_parameters = self._detect_trends(risk_values, timestamps)

        # Analyze seasonality
        seasonality_patterns = self._analyze_seasonality(risk_values, timestamps)

        # Calculate anomaly scores
        anomaly_scores = self._calculate_anomaly_scores(risk_values)

        return RiskTimeSeries(
            node_id=node_id,
            risk_values=risk_values,
            timestamps=timestamps,
            confidence_intervals=confidence_intervals,
            trend_parameters=trend_parameters,
            seasonality_patterns=seasonality_patterns,
            anomaly_scores=anomaly_scores
        )

    def forecast_risk_evolution(self, risk_series: RiskTimeSeries,
                              forecast_method: str = 'exponential_smoothing') -> TemporalRiskForecast:
        """
        Forecast future risk evolution

        Args:
            risk_series: Historical risk time series
            forecast_method: Forecasting method to use

        Returns:
            forecast: Risk forecast for the specified horizon
        """
        if forecast_method not in self.forecasting_methods:
            raise ValueError(f"Unknown forecasting method: {forecast_method}")

        forecast_function = self.forecasting_methods[forecast_method]
        return forecast_function(risk_series)

    def detect_risk_acceleration(self, risk_series: RiskTimeSeries,
                               acceleration_threshold: float = 0.2) -> Dict[str, Any]:
        """
        Detect risk acceleration patterns that may indicate imminent attacks

        Args:
            risk_series: Risk time series
            acceleration_threshold: Threshold for acceleration detection

        Returns:
            acceleration_analysis: Analysis of risk acceleration
        """
        if len(risk_series.risk_values) < 5:
            return {'acceleration_detected': False, 'reason': 'insufficient_data'}

        # Calculate second derivative (acceleration)
        risk_values = np.array(risk_series.risk_values)
        acceleration = np.gradient(np.gradient(risk_values))

        # Calculate recent acceleration trend
        recent_acceleration = acceleration[-5:]  # Last 5 points
        avg_acceleration = np.mean(recent_acceleration)

        # Detect acceleration patterns
        acceleration_detected = avg_acceleration > acceleration_threshold

        # Calculate acceleration confidence
        acceleration_std = np.std(recent_acceleration)
        acceleration_confidence = min(1.0, avg_acceleration / max(acceleration_std, 1e-6))

        # Identify acceleration periods
        acceleration_periods = []
        for i, acc in enumerate(acceleration):
            if acc > acceleration_threshold:
                acceleration_periods.append({
                    'timestamp': risk_series.timestamps[i],
                    'acceleration_value': acc,
                    'risk_value': risk_series.risk_values[i]
                })

        return {
            'acceleration_detected': acceleration_detected,
            'average_acceleration': avg_acceleration,
            'acceleration_confidence': acceleration_confidence,
            'acceleration_periods': acceleration_periods,
            'risk_trend': 'accelerating' if acceleration_detected else 'stable',
            'alert_level': 'high' if acceleration_detected and acceleration_confidence > 0.8 else 'medium'
        }

    def analyze_risk_patterns(self, risk_series: RiskTimeSeries) -> Dict[str, Any]:
        """
        Analyze temporal patterns in risk evolution

        Args:
            risk_series: Risk time series

        Returns:
            pattern_analysis: Comprehensive pattern analysis
        """
        patterns = {
            'trend_analysis': {},
            'seasonality_analysis': {},
            'cyclical_patterns': {},
            'anomaly_analysis': {},
            'predictability_metrics': {}
        }

        # Trend analysis
        patterns['trend_analysis'] = self._analyze_trend_patterns(risk_series)

        # Seasonality analysis
        patterns['seasonality_analysis'] = self._analyze_seasonal_patterns(risk_series)

        # Cyclical patterns
        patterns['cyclical_patterns'] = self._detect_cyclical_patterns(risk_series)

        # Anomaly analysis
        patterns['anomaly_analysis'] = self._analyze_anomalies(risk_series)

        # Predictability metrics
        patterns['predictability_metrics'] = self._calculate_predictability_metrics(risk_series)

        return patterns

    def _create_minimal_series(self, node_id: str,
                             risk_history: List[TemporalRiskPoint]) -> RiskTimeSeries:
        """Create a minimal time series when data is insufficient"""
        timestamps = [point.timestamp for point in risk_history] if risk_history else [datetime.now()]
        risk_values = [point.risk_vector.magnitude() for point in risk_history] if risk_history else [0.0]

        return RiskTimeSeries(
            node_id=node_id,
            risk_values=risk_values,
            timestamps=timestamps,
            confidence_intervals=[(0.0, 0.0)] * len(risk_values),
            trend_parameters={'trend': 'unknown', 'slope': 0.0},
            seasonality_patterns={'detected': False},
            anomaly_scores=[0.0] * len(risk_values)
        )

    def _calculate_confidence_intervals(self, risk_values: List[float],
                                      confidence_values: List[float]) -> List[Tuple[float, float]]:
        """Calculate confidence intervals for risk values"""
        intervals = []

        for risk, confidence in zip(risk_values, confidence_values):
            # Use confidence to determine interval width
            interval_width = (1 - confidence) * risk * 0.5  # Conservative estimate
            lower = max(0.0, risk - interval_width)
            upper = min(1.0, risk + interval_width)
            intervals.append((lower, upper))

        return intervals

    def _detect_trends(self, risk_values: List[float],
                      timestamps: List[datetime]) -> Dict[str, Any]:
        """Detect trends in risk evolution"""
        if len(risk_values) < 3:
            return {'trend': 'insufficient_data', 'slope': 0.0}

        # Convert timestamps to numeric values
        time_numeric = [(t - timestamps[0]).total_seconds() for t in timestamps]

        # Linear regression for trend
        slope, intercept, r_value, p_value, std_err = stats.linregress(time_numeric, risk_values)

        # Determine trend direction
        if abs(slope) < self.trend_detection_threshold:
            trend = 'stable'
        elif slope > 0:
            trend = 'increasing'
        else:
            trend = 'decreasing'

        # Calculate trend strength
        trend_strength = abs(r_value)

        return {
            'trend': trend,
            'slope': slope,
            'intercept': intercept,
            'r_squared': r_value ** 2,
            'p_value': p_value,
            'trend_strength': trend_strength,
            'trend_category': 'strong' if trend_strength > 0.7 else 'moderate' if trend_strength > 0.4 else 'weak'
        }

    def _analyze_seasonality(self, risk_values: List[float],
                           timestamps: List[datetime]) -> Dict[str, Any]:
        """Analyze seasonal patterns in risk data"""
        if len(risk_values) < 24:  # Need at least a day of data
            return {'detected': False, 'reason': 'insufficient_data'}

        # Convert to pandas for easier analysis
        df = pd.DataFrame({
            'timestamp': timestamps,
            'risk': risk_values
        })
        df.set_index('timestamp', inplace=True)

        seasonality_results = {}

        # Test different seasonal periods
        for period in self.seasonality_periods:
            try:
                # Resample data to the period
                resampled = df.resample(period).mean()

                if len(resampled) >= 3:  # Need at least 3 periods
                    # Calculate autocorrelation
                    autocorr = pd.Series(resampled['risk']).autocorr(lag=1)

                    if abs(autocorr) > 0.3:  # Significant autocorrelation
                        seasonality_results[str(period)] = {
                            'autocorrelation': autocorr,
                            'strength': abs(autocorr),
                            'detected': True
                        }
            except Exception as e:
                logger.debug(f"Could not analyze seasonality for period {period}: {e}")

        detected = len(seasonality_results) > 0

        return {
            'detected': detected,
            'periods': seasonality_results,
            'dominant_period': max(seasonality_results.keys(),
                                 key=lambda k: seasonality_results[k]['strength']) if detected else None
        }

    def _calculate_anomaly_scores(self, risk_values: List[float]) -> List[float]:
        """Calculate anomaly scores using statistical methods"""
        if len(risk_values) < 5:
            return [0.0] * len(risk_values)

        # Use Z-score for anomaly detection
        mean_val = np.mean(risk_values)
        std_val = np.std(risk_values)

        if std_val == 0:
            return [0.0] * len(risk_values)

        anomaly_scores = []
        for value in risk_values:
            z_score = abs(value - mean_val) / std_val
            # Convert to 0-1 scale (higher = more anomalous)
            anomaly_score = min(1.0, z_score / 3.0)  # 3-sigma rule
            anomaly_scores.append(anomaly_score)

        return anomaly_scores

    def _exponential_smoothing_forecast(self, risk_series: RiskTimeSeries) -> TemporalRiskForecast:
        """Forecast using exponential smoothing"""
        risk_values = risk_series.risk_values

        if len(risk_values) < 3:
            return self._create_empty_forecast(risk_series.node_id)

        # Simple exponential smoothing
        smoothed = [risk_values[0]]
        for value in risk_values[1:]:
            smoothed_value = self.smoothing_alpha * value + (1 - self.smoothing_alpha) * smoothed[-1]
            smoothed.append(smoothed_value)

        # Forecast future values
        last_smoothed = smoothed[-1]
        forecast_steps = int(self.forecast_horizon.total_seconds() / 3600)  # Hourly steps

        predicted_risks = []
        forecast_timestamps = []

        current_time = risk_series.timestamps[-1]
        for i in range(1, forecast_steps + 1):
            # Simple continuation of trend
            trend = (smoothed[-1] - smoothed[-2]) if len(smoothed) > 1 else 0.0
            predicted_risk = last_smoothed + trend * i
            predicted_risk = max(0.0, min(1.0, predicted_risk))  # Bound to [0,1]

            predicted_risks.append(predicted_risk)
            forecast_timestamps.append(current_time + timedelta(hours=i))

        # Simple confidence intervals
        confidence_intervals = [(max(0.0, r - 0.1), min(1.0, r + 0.1)) for r in predicted_risks]

        return TemporalRiskForecast(
            node_id=risk_series.node_id,
            forecast_horizon=self.forecast_horizon,
            predicted_risks=predicted_risks,
            forecast_timestamps=forecast_timestamps,
            confidence_intervals=confidence_intervals,
            forecast_method='exponential_smoothing',
            model_parameters={'alpha': self.smoothing_alpha},
            accuracy_metrics=self._calculate_forecast_accuracy(risk_series, predicted_risks[:len(risk_values)])
        )

    def _linear_regression_forecast(self, risk_series: RiskTimeSeries) -> TemporalRiskForecast:
        """Forecast using linear regression"""
        timestamps = risk_series.timestamps
        risk_values = risk_series.risk_values

        if len(risk_values) < 3:
            return self._create_empty_forecast(risk_series.node_id)

        # Convert timestamps to numeric
        time_numeric = np.array([(t - timestamps[0]).total_seconds() for t in timestamps])

        # Linear regression
        slope, intercept = np.polyfit(time_numeric, risk_values, 1)

        # Forecast future values
        forecast_steps = int(self.forecast_horizon.total_seconds() / 3600)
        predicted_risks = []
        forecast_timestamps = []

        current_time = timestamps[-1]
        for i in range(1, forecast_steps + 1):
            future_time = (current_time + timedelta(hours=i) - timestamps[0]).total_seconds()
            predicted_risk = slope * future_time + intercept
            predicted_risk = max(0.0, min(1.0, predicted_risk))

            predicted_risks.append(predicted_risk)
            forecast_timestamps.append(current_time + timedelta(hours=i))

        # Confidence intervals based on regression
        residuals = np.array(risk_values) - (slope * time_numeric + intercept)
        std_error = np.std(residuals)

        confidence_intervals = []
        for pred in predicted_risks:
            lower = max(0.0, pred - 1.96 * std_error)
            upper = min(1.0, pred + 1.96 * std_error)
            confidence_intervals.append((lower, upper))

        return TemporalRiskForecast(
            node_id=risk_series.node_id,
            forecast_horizon=self.forecast_horizon,
            predicted_risks=predicted_risks,
            forecast_timestamps=forecast_timestamps,
            confidence_intervals=confidence_intervals,
            forecast_method='linear_regression',
            model_parameters={'slope': slope, 'intercept': intercept},
            accuracy_metrics=self._calculate_forecast_accuracy(risk_series, predicted_risks[:len(risk_values)])
        )

    def _arima_forecast(self, risk_series: RiskTimeSeries) -> TemporalRiskForecast:
        """Forecast using ARIMA-like model (simplified)"""
        # Simplified ARIMA implementation
        risk_values = risk_series.risk_values

        if len(risk_values) < 5:
            return self._create_empty_forecast(risk_series.node_id)

        # Simple AR(1) model
        ar_coef = 0.7  # Simplified
        forecast_steps = int(self.forecast_horizon.total_seconds() / 3600)

        predicted_risks = []
        forecast_timestamps = []

        current_time = risk_series.timestamps[-1]
        current_value = risk_values[-1]

        for i in range(1, forecast_steps + 1):
            # AR(1) prediction
            predicted_risk = ar_coef * current_value
            predicted_risk = max(0.0, min(1.0, predicted_risk))

            predicted_risks.append(predicted_risk)
            forecast_timestamps.append(current_time + timedelta(hours=i))

            current_value = predicted_risk  # Update for next prediction

        # Simple confidence intervals
        confidence_intervals = [(max(0.0, r - 0.15), min(1.0, r + 0.15)) for r in predicted_risks]

        return TemporalRiskForecast(
            node_id=risk_series.node_id,
            forecast_horizon=self.forecast_horizon,
            predicted_risks=predicted_risks,
            forecast_timestamps=forecast_timestamps,
            confidence_intervals=confidence_intervals,
            forecast_method='arima',
            model_parameters={'ar_coefficient': ar_coef},
            accuracy_metrics=self._calculate_forecast_accuracy(risk_series, predicted_risks[:len(risk_values)])
        )

    def _prophet_like_forecast(self, risk_series: RiskTimeSeries) -> TemporalRiskForecast:
        """Forecast using Prophet-like decomposition (simplified)"""
        # Simplified Prophet-like model
        risk_values = risk_series.risk_values
        timestamps = risk_series.timestamps

        if len(risk_values) < 7:  # Need at least a week
            return self._create_empty_forecast(risk_series.node_id)

        # Extract trend component (simple moving average)
        window_size = min(7, len(risk_values) // 2)
        trend = pd.Series(risk_values).rolling(window=window_size, center=True).mean().fillna(method='bfill').fillna(method='ffill')

        # Simple seasonal component (daily pattern)
        if len(risk_values) >= 24:
            seasonal = []
            for i in range(len(risk_values)):
                hour_of_day = timestamps[i].hour
                # Simplified: assume higher risk during business hours
                if 9 <= hour_of_day <= 17:
                    seasonal_factor = 1.1
                else:
                    seasonal_factor = 0.9
                seasonal.append(seasonal_factor)
        else:
            seasonal = [1.0] * len(risk_values)

        # Forecast
        forecast_steps = int(self.forecast_horizon.total_seconds() / 3600)
        predicted_risks = []
        forecast_timestamps = []

        current_time = timestamps[-1]
        last_trend = trend.iloc[-1]

        for i in range(1, forecast_steps + 1):
            future_time = current_time + timedelta(hours=i)
            hour_of_day = future_time.hour

            # Seasonal factor
            seasonal_factor = 1.1 if 9 <= hour_of_day <= 17 else 0.9

            # Trend continuation with slight decay
            trend_factor = last_trend * (0.99 ** i)

            predicted_risk = trend_factor * seasonal_factor
            predicted_risk = max(0.0, min(1.0, predicted_risk))

            predicted_risks.append(predicted_risk)
            forecast_timestamps.append(future_time)

        # Confidence intervals
        confidence_intervals = [(max(0.0, r - 0.2), min(1.0, r + 0.2)) for r in predicted_risks]

        return TemporalRiskForecast(
            node_id=risk_series.node_id,
            forecast_horizon=self.forecast_horizon,
            predicted_risks=predicted_risks,
            forecast_timestamps=forecast_timestamps,
            confidence_intervals=confidence_intervals,
            forecast_method='prophet_like',
            model_parameters={'trend_decay': 0.99, 'seasonal_business_hours': True},
            accuracy_metrics=self._calculate_forecast_accuracy(risk_series, predicted_risks[:len(risk_values)])
        )

    def _create_empty_forecast(self, node_id: str) -> TemporalRiskForecast:
        """Create an empty forecast when data is insufficient"""
        return TemporalRiskForecast(
            node_id=node_id,
            forecast_horizon=self.forecast_horizon,
            predicted_risks=[],
            forecast_timestamps=[],
            confidence_intervals=[],
            forecast_method='none',
            model_parameters={},
            accuracy_metrics={'mae': 0.0, 'rmse': 0.0}
        )

    def _calculate_forecast_accuracy(self, risk_series: RiskTimeSeries,
                                   predicted_values: List[float]) -> Dict[str, float]:
        """Calculate forecast accuracy metrics"""
        if not predicted_values or len(predicted_values) != len(risk_series.risk_values):
            return {'mae': 0.0, 'rmse': 0.0, 'mape': 0.0}

        actual = np.array(risk_series.risk_values)
        predicted = np.array(predicted_values)

        # Mean Absolute Error
        mae = np.mean(np.abs(actual - predicted))

        # Root Mean Square Error
        rmse = np.sqrt(np.mean((actual - predicted) ** 2))

        # Mean Absolute Percentage Error
        mape = np.mean(np.abs((actual - predicted) / np.maximum(actual, 1e-6))) * 100

        return {
            'mae': mae,
            'rmse': rmse,
            'mape': mape
        }

    def _analyze_trend_patterns(self, risk_series: RiskTimeSeries) -> Dict[str, Any]:
        """Analyze trend patterns in risk series"""
        trends = risk_series.trend_parameters

        # Classify trend patterns
        if trends.get('trend') == 'increasing':
            if trends.get('trend_strength', 0) > 0.7:
                pattern = 'strong_increase'
            else:
                pattern = 'moderate_increase'
        elif trends.get('trend') == 'decreasing':
            if trends.get('trend_strength', 0) > 0.7:
                pattern = 'strong_decrease'
            else:
                pattern = 'moderate_decrease'
        else:
            pattern = 'stable'

        # Detect acceleration/deceleration
        acceleration = self.detect_risk_acceleration(risk_series)

        return {
            'primary_pattern': pattern,
            'trend_strength': trends.get('trend_strength', 0),
            'acceleration_pattern': acceleration['risk_trend'],
            'volatility': np.std(risk_series.risk_values) if risk_series.risk_values else 0.0
        }

    def _analyze_seasonal_patterns(self, risk_series: RiskTimeSeries) -> Dict[str, Any]:
        """Analyze seasonal patterns"""
        seasonality = risk_series.seasonality_patterns

        if not seasonality.get('detected', False):
            return {'has_seasonality': False, 'patterns': []}

        patterns = []
        for period, data in seasonality.get('periods', {}).items():
            if data.get('detected', False):
                patterns.append({
                    'period': period,
                    'strength': data.get('strength', 0),
                    'autocorrelation': data.get('autocorrelation', 0)
                })

        return {
            'has_seasonality': True,
            'patterns': patterns,
            'dominant_period': seasonality.get('dominant_period')
        }

    def _detect_cyclical_patterns(self, risk_series: RiskTimeSeries) -> Dict[str, Any]:
        """Detect cyclical patterns in risk evolution"""
        risk_values = risk_series.risk_values

        if len(risk_values) < 10:
            return {'detected': False, 'cycles': []}

        # Simple cycle detection using autocorrelation
        autocorr = []
        max_lag = min(len(risk_values) // 2, 24)  # Up to 24 lags

        for lag in range(1, max_lag + 1):
            corr = np.corrcoef(risk_values[:-lag], risk_values[lag:])[0, 1]
            autocorr.append((lag, corr))

        # Find significant cycles
        significant_cycles = [
            {'lag': lag, 'correlation': corr}
            for lag, corr in autocorr
            if abs(corr) > 0.5
        ]

        return {
            'detected': len(significant_cycles) > 0,
            'cycles': significant_cycles,
            'dominant_cycle': max(significant_cycles, key=lambda x: abs(x['correlation'])) if significant_cycles else None
        }

    def _analyze_anomalies(self, risk_series: RiskTimeSeries) -> Dict[str, Any]:
        """Analyze anomalies in risk series"""
        anomaly_scores = risk_series.anomaly_scores

        if not anomaly_scores:
            return {'anomaly_count': 0, 'anomaly_percentage': 0.0}

        # Count significant anomalies (score > 0.5)
        significant_anomalies = [score for score in anomaly_scores if score > 0.5]
        anomaly_count = len(significant_anomalies)
        anomaly_percentage = anomaly_count / len(anomaly_scores) if anomaly_scores else 0.0

        # Find anomaly clusters
        anomaly_indices = [i for i, score in enumerate(anomaly_scores) if score > 0.5]

        clusters = []
        if anomaly_indices:
            current_cluster = [anomaly_indices[0]]
            for i in range(1, len(anomaly_indices)):
                if anomaly_indices[i] - anomaly_indices[i-1] <= 2:  # Adjacent or close
                    current_cluster.append(anomaly_indices[i])
                else:
                    if len(current_cluster) > 1:
                        clusters.append(current_cluster)
                    current_cluster = [anomaly_indices[i]]
            if len(current_cluster) > 1:
                clusters.append(current_cluster)

        return {
            'anomaly_count': anomaly_count,
            'anomaly_percentage': anomaly_percentage,
            'anomaly_clusters': clusters,
            'max_anomaly_score': max(anomaly_scores) if anomaly_scores else 0.0
        }

    def _calculate_predictability_metrics(self, risk_series: RiskTimeSeries) -> Dict[str, float]:
        """Calculate predictability metrics for the risk series"""
        risk_values = risk_series.risk_values

        if len(risk_values) < 5:
            return {'predictability': 0.0, 'stability': 0.0}

        # Calculate autocorrelation (predictability measure)
        autocorr_values = []
        for lag in range(1, min(5, len(risk_values) // 2)):
            corr = np.corrcoef(risk_values[:-lag], risk_values[lag:])[0, 1]
            autocorr_values.append(corr)

        avg_autocorr = np.mean([abs(c) for c in autocorr_values if not np.isnan(c)])

        # Calculate stability (inverse of variance)
        stability = 1.0 / (1.0 + np.var(risk_values))

        # Overall predictability
        predictability = (avg_autocorr + stability) / 2.0

        return {
            'predictability': predictability,
            'autocorrelation': avg_autocorr,
            'stability': stability,
            'variance': np.var(risk_values)
        }

# Example usage
if __name__ == "__main__":
    from .risk_propagation import RiskVector

    # Create sample temporal risk data
    base_time = datetime.now() - timedelta(hours=24)
    risk_history = []

    for i in range(24):
        timestamp = base_time + timedelta(hours=i)

        # Simulate increasing risk with some noise
        base_risk = 0.1 + (i / 24) * 0.6
        noise = np.random.normal(0, 0.1)
        risk_value = max(0.0, min(1.0, base_risk + noise))

        risk_vector = RiskVector(
            confidentiality=risk_value * 0.8,
            integrity=risk_value * 0.9,
            availability=risk_value * 0.7,
            financial=risk_value * 0.6,
            operational=risk_value * 0.5,
            reputational=risk_value * 0.4
        )

        risk_point = TemporalRiskPoint(
            timestamp=timestamp,
            risk_vector=risk_vector,
            confidence=0.8,
            contributing_factors={'network_access': 0.3, 'user_behavior': 0.2}
        )

        risk_history.append(risk_point)

    # Initialize temporal model
    temporal_model = TemporalRiskModel()

    # Build risk time series
    risk_series = temporal_model.build_temporal_risk_series(risk_history, "sample_node")

    print("Temporal Risk Analysis:")
    print(f"Trend: {risk_series.trend_parameters['trend']}")
    print(f"Seasonality detected: {risk_series.seasonality_patterns['detected']}")
    print(f"Max anomaly score: {max(risk_series.anomaly_scores):.3f}")

    # Forecast risk evolution
    forecast = temporal_model.forecast_risk_evolution(risk_series, 'exponential_smoothing')

    print(f"\nRisk Forecast ({forecast.forecast_method}):")
    print(f"Forecast horizon: {forecast.forecast_horizon}")
    print(f"Predicted risks: {forecast.predicted_risks[:5]}...")

    # Detect risk acceleration
    acceleration = temporal_model.detect_risk_acceleration(risk_series)

    print(f"\nRisk Acceleration Analysis:")
    print(f"Acceleration detected: {acceleration['acceleration_detected']}")
    print(f"Average acceleration: {acceleration['average_acceleration']:.3f}")

    # Analyze patterns
    patterns = temporal_model.analyze_risk_patterns(risk_series)

    print(f"\nPattern Analysis:")
    print(f"Primary trend pattern: {patterns['trend_analysis']['primary_pattern']}")
    print(f"Predictability: {patterns['predictability_metrics']['predictability']:.3f}")
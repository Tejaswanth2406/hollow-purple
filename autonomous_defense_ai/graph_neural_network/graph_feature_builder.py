"""
Graph Feature Builder for Cyber Defense Graph

This module builds sophisticated features for nodes and edges in the cyber defense graph,
incorporating temporal patterns, behavioral analysis, and contextual information.
"""

import numpy as np
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import hashlib
from collections import defaultdict
import logging

logger = logging.getLogger(__name__)

class AdvancedGraphFeatureBuilder:
    """
    Advanced feature builder for cyber defense graphs with temporal and behavioral features
    """

    def __init__(self):
        self.node_type_embeddings = self._initialize_node_embeddings()
        self.edge_type_embeddings = self._initialize_edge_embeddings()

        # Historical data for temporal features
        self.node_history = defaultdict(list)
        self.edge_history = defaultdict(list)

        # Behavioral patterns
        self.behavioral_patterns = self._load_behavioral_patterns()

    def _initialize_node_embeddings(self) -> Dict[str, np.ndarray]:
        """Initialize embeddings for different node types"""
        embeddings = {}

        node_types = [
            'user', 'service_account', 'admin_user', 'regular_user',
            'server', 'workstation', 'container', 'database',
            'api_gateway', 'load_balancer', 'storage_bucket',
            'identity_provider', 'secret', 'certificate',
            'network_device', 'firewall', 'kubernetes_cluster',
            'aws_lambda', 'gcp_function', 'azure_function'
        ]

        for node_type in node_types:
            # Create deterministic embedding based on node type
            hash_val = int(hashlib.md5(node_type.encode()).hexdigest(), 16)
            np.random.seed(hash_val % 2**32)
            embeddings[node_type] = np.random.normal(0, 1, 64)

        return embeddings

    def _initialize_edge_embeddings(self) -> Dict[str, np.ndarray]:
        """Initialize embeddings for different edge types"""
        embeddings = {}

        edge_types = [
            'user_login', 'service_authentication', 'api_call',
            'database_query', 'file_access', 'network_connection',
            'privilege_escalation', 'data_transfer', 'command_execution',
            'container_spawn', 'secret_access', 'certificate_usage',
            'dns_resolution', 'http_request', 'ssh_connection',
            'rdp_connection', 'kubernetes_api_call', 'cloud_api_call'
        ]

        for edge_type in edge_types:
            hash_val = int(hashlib.md5(edge_type.encode()).hexdigest(), 16)
            np.random.seed(hash_val % 2**32)
            embeddings[edge_type] = np.random.normal(0, 1, 32)

        return embeddings

    def _load_behavioral_patterns(self) -> Dict[str, Any]:
        """Load predefined behavioral patterns for anomaly detection"""
        return {
            'normal_login_hours': (9, 17),  # 9 AM to 5 PM
            'normal_api_call_frequency': 100,  # calls per hour
            'normal_data_transfer_size': 1024 * 1024,  # 1MB
            'suspicious_countries': ['RU', 'CN', 'KP', 'IR'],
            'high_privilege_actions': ['sudo', 'admin_access', 'root_login']
        }

    def build_node_features(self, node_data: Dict[str, Any],
                           historical_events: List[Dict[str, Any]] = None) -> np.ndarray:
        """
        Build comprehensive feature vector for a graph node

        Args:
            node_data: Node data dictionary
            historical_events: Historical events for this node

        Returns:
            features: Feature vector (256 dimensions)
        """
        features = []

        # 1. Basic node type embedding (64 dims)
        node_type = node_data.get('type', 'unknown')
        if node_type in self.node_type_embeddings:
            features.extend(self.node_type_embeddings[node_type])
        else:
            features.extend(np.zeros(64))

        # 2. Temporal features (8 dims)
        temporal_features = self._extract_temporal_features(node_data, historical_events)
        features.extend(temporal_features)

        # 3. Behavioral features (32 dims)
        behavioral_features = self._extract_behavioral_features(node_data, historical_events)
        features.extend(behavioral_features)

        # 4. Risk and anomaly features (16 dims)
        risk_features = self._extract_risk_features(node_data, historical_events)
        features.extend(risk_features)

        # 5. Network and connectivity features (32 dims)
        network_features = self._extract_network_features(node_data, historical_events)
        features.extend(network_features)

        # 6. Domain-specific features (64 dims)
        domain_features = self._extract_domain_features(node_data)
        features.extend(domain_features)

        # 7. Contextual features (32 dims)
        context_features = self._extract_contextual_features(node_data, historical_events)
        features.extend(context_features)

        # 8. Statistical features (8 dims)
        stat_features = self._extract_statistical_features(historical_events)
        features.extend(stat_features)

        return np.array(features, dtype=np.float32)

    def _extract_temporal_features(self, node_data: Dict[str, Any],
                                 historical_events: List[Dict[str, Any]] = None) -> List[float]:
        """Extract temporal patterns and features"""
        features = []

        now = datetime.now()

        # Current time features
        features.append(now.hour / 24.0)  # Hour of day
        features.append(now.weekday() / 7.0)  # Day of week
        features.append(now.month / 12.0)  # Month of year

        # Node creation/update time features
        if 'created_at' in node_data:
            created_at = node_data['created_at']
            if isinstance(created_at, str):
                created_at = datetime.fromisoformat(created_at.replace('Z', '+00:00'))

            age_hours = (now - created_at).total_seconds() / 3600
            features.append(min(age_hours / (24 * 365), 1.0))  # Age in years (normalized)

        # Activity patterns from historical events
        if historical_events:
            hours = [self._parse_timestamp(e.get('timestamp', now)).hour for e in historical_events]
            if hours:
                features.append(np.mean(hours) / 24.0)  # Mean activity hour
                features.append(np.std(hours) / 12.0)   # Activity hour variance
            else:
                features.extend([0.5, 0.0])  # Default values

        # Pad to 8 dimensions
        while len(features) < 8:
            features.append(0.0)

        return features[:8]

    def _extract_behavioral_features(self, node_data: Dict[str, Any],
                                   historical_events: List[Dict[str, Any]] = None) -> List[float]:
        """Extract behavioral patterns and anomalies"""
        features = []

        if not historical_events:
            return [0.0] * 32

        # Event frequency patterns
        event_counts = defaultdict(int)
        for event in historical_events:
            event_type = event.get('type', 'unknown')
            event_counts[event_type] += 1

        # Normalize by total events
        total_events = len(historical_events)
        for event_type in ['login', 'api_call', 'data_access', 'privilege_escalation']:
            count = event_counts.get(event_type, 0)
            features.append(count / max(total_events, 1))

        # Time-based patterns
        timestamps = [self._parse_timestamp(e.get('timestamp', datetime.now()))
                     for e in historical_events]

        if len(timestamps) > 1:
            # Inter-event time statistics
            intervals = [(timestamps[i+1] - timestamps[i]).total_seconds()
                        for i in range(len(timestamps)-1)]

            if intervals:
                features.append(np.mean(intervals) / 3600)  # Mean interval in hours
                features.append(np.std(intervals) / 3600)   # Std deviation
                features.append(np.min(intervals) / 3600)   # Min interval
                features.append(np.max(intervals) / 3600)   # Max interval
            else:
                features.extend([0.0, 0.0, 0.0, 0.0])

        # Behavioral anomaly scores
        anomaly_score = self._calculate_behavioral_anomaly(node_data, historical_events)
        features.append(anomaly_score)

        # Privilege escalation patterns
        priv_escalations = sum(1 for e in historical_events
                             if e.get('type') == 'privilege_escalation')
        features.append(priv_escalations / max(total_events, 1))

        # Pad to 32 dimensions
        while len(features) < 32:
            features.append(0.0)

        return features[:32]

    def _extract_risk_features(self, node_data: Dict[str, Any],
                             historical_events: List[Dict[str, Any]] = None) -> List[float]:
        """Extract risk and security-related features"""
        features = []

        # Base risk score
        base_risk = node_data.get('risk_score', 0.0)
        features.append(base_risk)

        # Authentication failures
        if historical_events:
            auth_failures = sum(1 for e in historical_events
                              if e.get('type') == 'auth_failure')
            features.append(auth_failures / max(len(historical_events), 1))

        # Suspicious activities
        suspicious_count = 0
        if historical_events:
            for event in historical_events:
                if self._is_suspicious_event(event):
                    suspicious_count += 1
            features.append(suspicious_count / max(len(historical_events), 1))

        # Geographic anomalies
        geo_anomalies = self._detect_geographic_anomalies(historical_events or [])
        features.append(geo_anomalies)

        # Time-based anomalies
        time_anomalies = self._detect_temporal_anomalies(historical_events or [])
        features.append(time_anomalies)

        # Pad to 16 dimensions
        while len(features) < 16:
            features.append(0.0)

        return features[:16]

    def _extract_network_features(self, node_data: Dict[str, Any],
                                historical_events: List[Dict[str, Any]] = None) -> List[float]:
        """Extract network connectivity and communication features"""
        features = []

        if not historical_events:
            return [0.0] * 32

        # Connection patterns
        connections = defaultdict(int)
        for event in historical_events:
            if event.get('type') in ['network_connection', 'api_call']:
                target = event.get('target', event.get('destination', 'unknown'))
                connections[target] += 1

        # Network centrality measures
        unique_connections = len(connections)
        total_connections = sum(connections.values())

        features.append(unique_connections / 100.0)  # Normalized unique connections
        features.append(total_connections / 1000.0)  # Normalized total connections

        # Most frequent connection
        if connections:
            max_freq = max(connections.values())
            features.append(max_freq / max(total_connections, 1))
        else:
            features.append(0.0)

        # Connection diversity (entropy)
        if connections:
            probs = np.array(list(connections.values())) / total_connections
            entropy = -np.sum(probs * np.log(probs + 1e-10))
            features.append(entropy / np.log(len(connections) + 1))
        else:
            features.append(0.0)

        # Protocol distribution
        protocols = defaultdict(int)
        for event in historical_events:
            protocol = event.get('protocol', 'unknown')
            protocols[protocol] += 1

        for protocol in ['http', 'https', 'ssh', 'rdp', 'database']:
            count = protocols.get(protocol, 0)
            features.append(count / max(len(historical_events), 1))

        # Pad to 32 dimensions
        while len(features) < 32:
            features.append(0.0)

        return features[:32]

    def _extract_domain_features(self, node_data: Dict[str, Any]) -> List[float]:
        """Extract domain-specific features based on node type"""
        features = []

        node_type = node_data.get('type', 'unknown')

        if node_type == 'user':
            # User-specific features
            features.extend(self._extract_user_features(node_data))
        elif node_type in ['server', 'workstation', 'container']:
            # System-specific features
            features.extend(self._extract_system_features(node_data))
        elif node_type == 'database':
            # Database-specific features
            features.extend(self._extract_database_features(node_data))
        elif node_type in ['aws_lambda', 'gcp_function', 'azure_function']:
            # Serverless-specific features
            features.extend(self._extract_serverless_features(node_data))
        else:
            features.extend([0.0] * 64)

        # Ensure exactly 64 dimensions
        if len(features) < 64:
            features.extend([0.0] * (64 - len(features)))
        elif len(features) > 64:
            features = features[:64]

        return features

    def _extract_user_features(self, node_data: Dict[str, Any]) -> List[float]:
        """Extract features specific to user nodes"""
        features = []

        # Role encoding
        role = node_data.get('role', 'unknown')
        role_encoding = {
            'admin': 1.0, 'user': 0.5, 'service': 0.3, 'guest': 0.1
        }.get(role, 0.0)
        features.append(role_encoding)

        # Department encoding (simplified)
        department = node_data.get('department', 'unknown')
        dept_hash = int(hashlib.md5(department.encode()).hexdigest(), 16) % 100
        features.append(dept_hash / 100.0)

        # Account status
        status = node_data.get('status', 'active')
        features.append(1.0 if status == 'active' else 0.0)

        # MFA enabled
        mfa = node_data.get('mfa_enabled', False)
        features.append(1.0 if mfa else 0.0)

        # Pad to 64 dimensions
        while len(features) < 64:
            features.append(0.0)

        return features[:64]

    def _extract_system_features(self, node_data: Dict[str, Any]) -> List[float]:
        """Extract features specific to system nodes"""
        features = []

        # OS type encoding
        os_type = node_data.get('os', 'unknown')
        os_encoding = {
            'linux': 0.3, 'windows': 0.5, 'macos': 0.2, 'unknown': 0.0
        }.get(os_type.lower(), 0.0)
        features.append(os_encoding)

        # Environment encoding
        environment = node_data.get('environment', 'unknown')
        env_encoding = {
            'production': 1.0, 'staging': 0.7, 'development': 0.3, 'unknown': 0.0
        }.get(environment.lower(), 0.0)
        features.append(env_encoding)

        # Resource utilization (if available)
        cpu_usage = node_data.get('cpu_usage', 0.0)
        memory_usage = node_data.get('memory_usage', 0.0)
        features.extend([cpu_usage, memory_usage])

        # Security posture
        patches_up_to_date = node_data.get('patches_up_to_date', True)
        features.append(1.0 if patches_up_to_date else 0.0)

        # Pad to 64 dimensions
        while len(features) < 64:
            features.append(0.0)

        return features[:64]

    def _extract_database_features(self, node_data: Dict[str, Any]) -> List[float]:
        """Extract features specific to database nodes"""
        features = []

        # Database type encoding
        db_type = node_data.get('db_type', 'unknown')
        db_encoding = {
            'postgresql': 0.2, 'mysql': 0.3, 'mongodb': 0.4,
            'redis': 0.5, 'elasticsearch': 0.6, 'unknown': 0.0
        }.get(db_type.lower(), 0.0)
        features.append(db_encoding)

        # Data classification
        data_class = node_data.get('data_classification', 'unknown')
        class_encoding = {
            'public': 0.1, 'internal': 0.3, 'confidential': 0.7, 'restricted': 1.0
        }.get(data_class.lower(), 0.0)
        features.append(class_encoding)

        # Encryption status
        encrypted = node_data.get('encrypted', False)
        features.append(1.0 if encrypted else 0.0)

        # Backup status
        backed_up = node_data.get('backed_up', True)
        features.append(1.0 if backed_up else 0.0)

        # Pad to 64 dimensions
        while len(features) < 64:
            features.append(0.0)

        return features[:64]

    def _extract_serverless_features(self, node_data: Dict[str, Any]) -> List[float]:
        """Extract features specific to serverless function nodes"""
        features = []

        # Runtime encoding
        runtime = node_data.get('runtime', 'unknown')
        runtime_encoding = {
            'python': 0.2, 'node': 0.3, 'java': 0.4, 'go': 0.5, 'unknown': 0.0
        }.get(runtime.lower(), 0.0)
        features.append(runtime_encoding)

        # Memory allocation
        memory_mb = node_data.get('memory_mb', 128)
        features.append(memory_mb / 3008.0)  # Normalize by Lambda max

        # Timeout setting
        timeout_sec = node_data.get('timeout_sec', 900)
        features.append(timeout_sec / 900.0)  # Normalize by Lambda max

        # Invocation frequency (if available)
        invocations_per_hour = node_data.get('invocations_per_hour', 0)
        features.append(min(invocations_per_hour / 1000.0, 1.0))

        # Pad to 64 dimensions
        while len(features) < 64:
            features.append(0.0)

        return features[:64]

    def _extract_contextual_features(self, node_data: Dict[str, Any],
                                   historical_events: List[Dict[str, Any]] = None) -> List[float]:
        """Extract contextual and environmental features"""
        features = []

        # Cloud provider encoding
        cloud_provider = node_data.get('cloud_provider', 'unknown')
        cloud_encoding = {
            'aws': 0.3, 'gcp': 0.4, 'azure': 0.5, 'onprem': 0.1, 'unknown': 0.0
        }.get(cloud_provider.lower(), 0.0)
        features.append(cloud_encoding)

        # Region/Zone encoding
        region = node_data.get('region', 'unknown')
        region_hash = int(hashlib.md5(region.encode()).hexdigest(), 16) % 100
        features.append(region_hash / 100.0)

        # Business criticality
        criticality = node_data.get('criticality', 'low')
        crit_encoding = {
            'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 1.0
        }.get(criticality.lower(), 0.0)
        features.append(crit_encoding)

        # Compliance requirements
        compliance = node_data.get('compliance', [])
        has_pci = 'pci' in [c.lower() for c in compliance]
        has_hipaa = 'hipaa' in [c.lower() for c in compliance]
        has_gdpr = 'gdpr' in [c.lower() for c in compliance]
        features.extend([1.0 if has_pci else 0.0,
                        1.0 if has_hipaa else 0.0,
                        1.0 if has_gdpr else 0.0])

        # Pad to 32 dimensions
        while len(features) < 32:
            features.append(0.0)

        return features[:32]

    def _extract_statistical_features(self, historical_events: List[Dict[str, Any]] = None) -> List[float]:
        """Extract statistical features from historical events"""
        if not historical_events:
            return [0.0] * 8

        features = []

        # Event count statistics
        event_counts = len(historical_events)
        features.append(min(event_counts / 1000.0, 1.0))  # Normalized event count

        # Event type diversity
        event_types = set(e.get('type', 'unknown') for e in historical_events)
        features.append(len(event_types) / 20.0)  # Normalized diversity

        # Time span
        if historical_events:
            timestamps = [self._parse_timestamp(e.get('timestamp', datetime.now()))
                         for e in historical_events]
            time_span = (max(timestamps) - min(timestamps)).total_seconds() / 3600  # Hours
            features.append(min(time_span / (24 * 30), 1.0))  # Normalized to 30 days

        # Error rate
        error_count = sum(1 for e in historical_events if e.get('status') == 'error')
        features.append(error_count / max(len(historical_events), 1))

        # Pad to 8 dimensions
        while len(features) < 8:
            features.append(0.0)

        return features[:8]

    def _calculate_behavioral_anomaly(self, node_data: Dict[str, Any],
                                    historical_events: List[Dict[str, Any]]) -> float:
        """Calculate behavioral anomaly score"""
        if not historical_events:
            return 0.0

        anomaly_score = 0.0

        # Check for unusual login times
        for event in historical_events:
            if event.get('type') == 'login':
                timestamp = self._parse_timestamp(event.get('timestamp', datetime.now()))
                hour = timestamp.hour

                # Check if login is outside normal hours
                if not (self.behavioral_patterns['normal_login_hours'][0] <=
                       hour <= self.behavioral_patterns['normal_login_hours'][1]):
                    anomaly_score += 0.2

        # Check for high-frequency API calls
        api_calls = sum(1 for e in historical_events if e.get('type') == 'api_call')
        if api_calls > self.behavioral_patterns['normal_api_call_frequency'] * 2:
            anomaly_score += 0.3

        # Check for large data transfers
        for event in historical_events:
            if event.get('type') == 'data_transfer':
                size = event.get('size', 0)
                if size > self.behavioral_patterns['normal_data_transfer_size'] * 10:
                    anomaly_score += 0.4

        return min(anomaly_score, 1.0)

    def _is_suspicious_event(self, event: Dict[str, Any]) -> bool:
        """Determine if an event is suspicious"""
        event_type = event.get('type', '')

        # High-risk event types
        high_risk_types = [
            'privilege_escalation', 'root_login', 'sudo_command',
            'unauthorized_access', 'data_exfiltration'
        ]

        if event_type in high_risk_types:
            return True

        # Check for suspicious countries
        country = event.get('country', '').upper()
        if country in self.behavioral_patterns['suspicious_countries']:
            return True

        # Check for unusual times
        timestamp = self._parse_timestamp(event.get('timestamp', datetime.now()))
        hour = timestamp.hour

        if event_type == 'login' and not (6 <= hour <= 22):  # Outside 6 AM - 10 PM
            return True

        return False

    def _detect_geographic_anomalies(self, historical_events: List[Dict[str, Any]]) -> float:
        """Detect geographic anomalies in events"""
        if not historical_events:
            return 0.0

        countries = [e.get('country', 'unknown') for e in historical_events]
        unique_countries = set(countries)

        # Check for suspicious countries
        suspicious_countries = set(self.behavioral_patterns['suspicious_countries'])
        suspicious_count = len(unique_countries.intersection(suspicious_countries))

        return min(suspicious_count / len(unique_countries), 1.0) if unique_countries else 0.0

    def _detect_temporal_anomalies(self, historical_events: List[Dict[str, Any]]) -> float:
        """Detect temporal anomalies in events"""
        if len(historical_events) < 2:
            return 0.0

        timestamps = [self._parse_timestamp(e.get('timestamp', datetime.now()))
                     for e in historical_events]

        # Check for events at unusual hours
        unusual_hour_count = 0
        for ts in timestamps:
            if ts.hour < 6 or ts.hour > 22:  # Outside 6 AM - 10 PM
                unusual_hour_count += 1

        return unusual_hour_count / len(timestamps)

    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp from various formats"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            try:
                return datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                return datetime.now()
        else:
            return datetime.now()

    def build_edge_features(self, edge_data: Dict[str, Any],
                           source_node: Dict[str, Any] = None,
                           target_node: Dict[str, Any] = None) -> np.ndarray:
        """
        Build comprehensive feature vector for a graph edge

        Args:
            edge_data: Edge data dictionary
            source_node: Source node data
            target_node: Target node data

        Returns:
            features: Feature vector (128 dimensions)
        """
        features = []

        # 1. Edge type embedding (32 dims)
        edge_type = edge_data.get('type', 'unknown')
        if edge_type in self.edge_type_embeddings:
            features.extend(self.edge_type_embeddings[edge_type])
        else:
            features.extend(np.zeros(32))

        # 2. Edge weight and strength (4 dims)
        weight = edge_data.get('weight', 1.0)
        strength = edge_data.get('strength', 1.0)
        frequency = edge_data.get('frequency', 1.0)
        recency = edge_data.get('recency', 1.0)

        features.extend([weight, strength, frequency, recency])

        # 3. Temporal features (8 dims)
        temporal_features = self._extract_edge_temporal_features(edge_data)
        features.extend(temporal_features)

        # 4. Security features (16 dims)
        security_features = self._extract_edge_security_features(edge_data, source_node, target_node)
        features.extend(security_features)

        # 5. Protocol and transport features (16 dims)
        protocol_features = self._extract_edge_protocol_features(edge_data)
        features.extend(protocol_features)

        # 6. Contextual features (16 dims)
        context_features = self._extract_edge_contextual_features(edge_data, source_node, target_node)
        features.extend(context_features)

        # 7. Statistical features (8 dims)
        stat_features = self._extract_edge_statistical_features(edge_data)
        features.extend(stat_features)

        # 8. Anomaly features (8 dims)
        anomaly_features = self._extract_edge_anomaly_features(edge_data, source_node, target_node)
        features.extend(anomaly_features)

        return np.array(features, dtype=np.float32)

    def _extract_edge_temporal_features(self, edge_data: Dict[str, Any]) -> List[float]:
        """Extract temporal features for edges"""
        features = []

        now = datetime.now()

        # Edge creation time
        if 'created_at' in edge_data:
            created_at = self._parse_timestamp(edge_data['created_at'])
            age_hours = (now - created_at).total_seconds() / 3600
            features.append(min(age_hours / (24 * 365), 1.0))  # Age in years

        # Last seen time
        if 'last_seen' in edge_data:
            last_seen = self._parse_timestamp(edge_data['last_seen'])
            hours_since_last_seen = (now - last_seen).total_seconds() / 3600
            features.append(min(hours_since_last_seen / 24, 1.0))  # Days since last seen

        # Duration
        if 'duration' in edge_data:
            duration_sec = edge_data['duration']
            features.append(min(duration_sec / 3600, 1.0))  # Hours

        # Frequency patterns
        if 'hourly_frequency' in edge_data:
            freq = edge_data['hourly_frequency']
            features.append(min(freq / 100.0, 1.0))

        # Pad to 8 dimensions
        while len(features) < 8:
            features.append(0.0)

        return features[:8]

    def _extract_edge_security_features(self, edge_data: Dict[str, Any],
                                      source_node: Dict[str, Any] = None,
                                      target_node: Dict[str, Any] = None) -> List[float]:
        """Extract security-related features for edges"""
        features = []

        # Authentication status
        authenticated = edge_data.get('authenticated', False)
        features.append(1.0 if authenticated else 0.0)

        # Encryption status
        encrypted = edge_data.get('encrypted', False)
        features.append(1.0 if encrypted else 0.0)

        # Authorization level
        auth_level = edge_data.get('auth_level', 'none')
        auth_encoding = {
            'none': 0.0, 'basic': 0.3, 'oauth': 0.6, 'certificate': 0.8, 'kerberos': 1.0
        }.get(auth_level.lower(), 0.0)
        features.append(auth_encoding)

        # Privilege level
        privilege = edge_data.get('privilege', 'user')
        priv_encoding = {
            'user': 0.2, 'admin': 0.6, 'root': 1.0, 'service': 0.4
        }.get(privilege.lower(), 0.0)
        features.append(priv_encoding)

        # Cross-domain access
        if source_node and target_node:
            source_domain = source_node.get('domain', 'unknown')
            target_domain = target_node.get('domain', 'unknown')
            cross_domain = 1.0 if source_domain != target_domain else 0.0
            features.append(cross_domain)

        # Sensitive data access
        sensitive_access = edge_data.get('sensitive_data', False)
        features.append(1.0 if sensitive_access else 0.0)

        # Pad to 16 dimensions
        while len(features) < 16:
            features.append(0.0)

        return features[:16]

    def _extract_edge_protocol_features(self, edge_data: Dict[str, Any]) -> List[float]:
        """Extract protocol and transport features for edges"""
        features = []

        # Protocol encoding
        protocol = edge_data.get('protocol', 'unknown')
        protocol_encoding = {
            'http': 0.1, 'https': 0.2, 'ssh': 0.7, 'rdp': 0.6,
            'database': 0.8, 'api': 0.3, 'dns': 0.1, 'icmp': 0.2,
            'tcp': 0.4, 'udp': 0.3, 'unknown': 0.0
        }.get(protocol.lower(), 0.0)
        features.append(protocol_encoding)

        # Port number (normalized)
        port = edge_data.get('port', 0)
        features.append(port / 65535.0)

        # Connection type
        conn_type = edge_data.get('connection_type', 'unknown')
        conn_encoding = {
            'persistent': 0.8, 'ephemeral': 0.3, 'long_polling': 0.5, 'unknown': 0.0
        }.get(conn_type.lower(), 0.0)
        features.append(conn_encoding)

        # Data transfer size
        size = edge_data.get('size', 0)
        features.append(min(size / (1024 * 1024 * 1024), 1.0))  # GB

        # Pad to 16 dimensions
        while len(features) < 16:
            features.append(0.0)

        return features[:16]

    def _extract_edge_contextual_features(self, edge_data: Dict[str, Any],
                                        source_node: Dict[str, Any] = None,
                                        target_node: Dict[str, Any] = None) -> List[float]:
        """Extract contextual features for edges"""
        features = []

        # Business context
        business_critical = edge_data.get('business_critical', False)
        features.append(1.0 if business_critical else 0.0)

        # Environment context
        environment = edge_data.get('environment', 'unknown')
        env_encoding = {
            'production': 1.0, 'staging': 0.7, 'development': 0.3, 'unknown': 0.0
        }.get(environment.lower(), 0.0)
        features.append(env_encoding)

        # Geographic context
        if source_node and target_node:
            source_region = source_node.get('region', 'unknown')
            target_region = target_node.get('region', 'unknown')
            same_region = 1.0 if source_region == target_region else 0.0
            features.append(same_region)

        # Service mesh context
        in_mesh = edge_data.get('in_service_mesh', False)
        features.append(1.0 if in_mesh else 0.0)

        # Pad to 16 dimensions
        while len(features) < 16:
            features.append(0.0)

        return features[:16]

    def _extract_edge_statistical_features(self, edge_data: Dict[str, Any]) -> List[float]:
        """Extract statistical features for edges"""
        features = []

        # Usage statistics
        usage_count = edge_data.get('usage_count', 0)
        features.append(min(usage_count / 10000.0, 1.0))

        # Success rate
        success_rate = edge_data.get('success_rate', 1.0)
        features.append(success_rate)

        # Latency statistics
        avg_latency = edge_data.get('avg_latency_ms', 0)
        features.append(min(avg_latency / 10000.0, 1.0))  # 10 seconds max

        # Error rate
        error_rate = edge_data.get('error_rate', 0.0)
        features.append(error_rate)

        # Pad to 8 dimensions
        while len(features) < 8:
            features.append(0.0)

        return features[:8]

    def _extract_edge_anomaly_features(self, edge_data: Dict[str, Any],
                                     source_node: Dict[str, Any] = None,
                                     target_node: Dict[str, Any] = None) -> List[float]:
        """Extract anomaly features for edges"""
        features = []

        # Unusual timing
        is_unusual_time = edge_data.get('unusual_timing', False)
        features.append(1.0 if is_unusual_time else 0.0)

        # Unusual frequency
        is_unusual_freq = edge_data.get('unusual_frequency', False)
        features.append(1.0 if is_unusual_freq else 0.0)

        # Unusual size
        is_unusual_size = edge_data.get('unusual_size', False)
        features.append(1.0 if is_unusual_size else 0.0)

        # Unusual source/target
        is_unusual_endpoint = edge_data.get('unusual_endpoint', False)
        features.append(1.0 if is_unusual_endpoint else 0.0)

        # Pad to 8 dimensions
        while len(features) < 8:
            features.append(0.0)

        return features[:8]
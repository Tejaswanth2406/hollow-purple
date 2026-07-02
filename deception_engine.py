"""
Deception Engine

The Deception Engine creates and manages deceptive environments to safely
redirect attackers away from real systems while gathering intelligence.

Instead of trapping attackers, the system redirects them to controlled
fake environments where all interactions are monitored and analyzed.

This engine:
1. Creates realistic decoy systems and data
2. Routes suspicious traffic to deception environments
3. Monitors attacker behavior in safe isolation
4. Gathers intelligence for defense improvement
5. Maintains legal and ethical boundaries
"""

import asyncio
import logging
from typing import Dict, List, Tuple, Optional, Any, Union, Set
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import uuid
from enum import Enum
import random
import ipaddress
import hashlib

logger = logging.getLogger(__name__)

class DeceptionType(Enum):
    """Types of deception environments"""
    HONEYNET = "honeynet"          # Fake network of systems
    HONEYPOT = "honeypot"          # Single fake system
    DECOY_DATA = "decoy_data"      # Fake sensitive data
    FAKE_SERVICE = "fake_service"  # Fake API/service endpoints
    PHISHING_SITE = "phishing_site" # Fake login pages
    MALWARE_SANDBOX = "malware_sandbox" # Isolated malware execution

class DeceptionTrigger(Enum):
    """Triggers for activating deception"""
    SUSPICIOUS_IP = "suspicious_ip"
    UNUSUAL_TRAFFIC = "unusual_traffic"
    FAILED_AUTH = "failed_auth"
    MALICIOUS_PATTERN = "malicious_pattern"
    LATERAL_MOVEMENT = "lateral_movement"
    RECONNAISSANCE = "reconnaissance"

@dataclass
class DeceptionEnvironment:
    """A deception environment configuration"""
    env_id: str
    name: str
    deception_type: DeceptionType
    trigger_conditions: Dict[str, Any]
    fake_resources: List[Dict[str, Any]]
    monitoring_config: Dict[str, Any]
    intelligence_gathering: List[str]
    risk_level: str
    active: bool
    created_at: datetime
    last_accessed: Optional[datetime]

@dataclass
class AttackerSession:
    """An attacker interaction session in deception environment"""
    session_id: str
    env_id: str
    attacker_ip: str
    start_time: datetime
    end_time: Optional[datetime]
    actions: List[Dict[str, Any]]
    intelligence_gathered: Dict[str, Any]
    risk_assessment: str
    active: bool

@dataclass
class DeceptionIntelligence:
    """Intelligence gathered from deception interactions"""
    intelligence_id: str
    session_id: str
    attacker_profile: Dict[str, Any]
    techniques_used: List[str]
    tools_detected: List[str]
    objectives_inferred: List[str]
    indicators_extracted: List[Dict[str, Any]]
    timestamp: datetime

class DeceptionEngine:
    """
    Deception Engine

    Creates safe, controlled environments to redirect attackers while gathering
    intelligence for defense improvement.

    Key principles:
    1. Never expose real systems or data
    2. Gather maximum intelligence safely
    3. Maintain legal and ethical boundaries
    4. Continuously improve deception effectiveness
    """

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or self._default_config()

        # Deception environments
        self.environments: Dict[str, DeceptionEnvironment] = {}
        self.active_sessions: Dict[str, AttackerSession] = {}

        # Intelligence gathering
        self.intelligence_log: List[DeceptionIntelligence] = []
        self.attacker_profiles: Dict[str, Dict[str, Any]] = {}

        # Performance metrics
        self.metrics = {
            'total_sessions': 0,
            'intelligence_gathered': 0,
            'attackers_redirected': 0,
            'false_positives': 0,
            'deception_effectiveness': 0.0
        }

        # Load default deception environments
        self._load_default_environments()

        logger.info("Deception Engine initialized")

    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'deception_enabled': True,
            'auto_deployment': True,
            'intelligence_sharing': True,
            'ethical_boundaries': True,
            'max_concurrent_sessions': 50,
            'session_timeout': 3600,  # 1 hour
            'intelligence_retention_days': 90,
            'risk_threshold': 0.7,  # Trigger deception above this risk
            'false_positive_tolerance': 0.1
        }

    def _load_default_environments(self):
        """Load default deception environments"""
        default_environments = [
            DeceptionEnvironment(
                env_id="corporate_honeynet",
                name="Corporate Honeynet",
                deception_type=DeceptionType.HONEYNET,
                trigger_conditions={
                    'risk_score': {'operator': '>', 'value': 0.7},
                    'traffic_type': 'internal_recon'
                },
                fake_resources=[
                    {
                        'type': 'server',
                        'os': 'windows_server',
                        'services': ['rdp', 'smb', 'sql_server'],
                        'data': ['fake_employee_records', 'fake_financial_data']
                    },
                    {
                        'type': 'workstation',
                        'os': 'windows_10',
                        'services': ['rdp', 'file_share'],
                        'data': ['fake_documents', 'fake_credentials']
                    }
                ],
                monitoring_config={
                    'log_all_commands': True,
                    'capture_screenshots': True,
                    'record_network_traffic': True,
                    'analyze_tools': True
                },
                intelligence_gathering=[
                    'command_patterns',
                    'tool_signatures',
                    'data_targets',
                    'persistence_methods'
                ],
                risk_level="medium",
                active=True,
                created_at=datetime.now(),
                last_accessed=None
            ),
            DeceptionEnvironment(
                env_id="database_decoy",
                name="Database Decoy",
                deception_type=DeceptionType.DECOY_DATA,
                trigger_conditions={
                    'query_pattern': 'sensitive_data_access',
                    'user_privilege': 'low'
                },
                fake_resources=[
                    {
                        'type': 'database',
                        'schema': 'fake_customer_data',
                        'tables': ['credit_cards', 'ssn', 'medical_records'],
                        'data_volume': 'large'
                    }
                ],
                monitoring_config={
                    'log_queries': True,
                    'track_data_access': True,
                    'alert_on_exfiltration': True
                },
                intelligence_gathering=[
                    'data_interests',
                    'query_techniques',
                    'exfiltration_methods'
                ],
                risk_level="high",
                active=True,
                created_at=datetime.now(),
                last_accessed=None
            ),
            DeceptionEnvironment(
                env_id="api_honeypot",
                name="API Honeypot",
                deception_type=DeceptionType.FAKE_SERVICE,
                trigger_conditions={
                    'endpoint': 'unknown_api_call',
                    'frequency': 'unusual'
                },
                fake_resources=[
                    {
                        'type': 'api_endpoint',
                        'methods': ['GET', 'POST', 'PUT', 'DELETE'],
                        'responses': ['fake_user_data', 'fake_system_info', 'fake_logs'],
                        'authentication': 'fake_jwt'
                    }
                ],
                monitoring_config={
                    'log_requests': True,
                    'analyze_payloads': True,
                    'track_auth_attempts': True
                },
                intelligence_gathering=[
                    'api_abuse_patterns',
                    'authentication_bypass_attempts',
                    'data_enumeration'
                ],
                risk_level="low",
                active=True,
                created_at=datetime.now(),
                last_accessed=None
            )
        ]

        for env in default_environments:
            self.environments[env.env_id] = env

    async def evaluate_traffic(self, traffic_context: Dict[str, Any]) -> Optional[str]:
        """
        Evaluate incoming traffic and determine if deception should be triggered

        Args:
            traffic_context: Context about the traffic (IP, behavior, risk score, etc.)

        Returns:
            env_id: ID of deception environment to redirect to, or None
        """
        if not self.config['deception_enabled']:
            return None

        # Calculate deception trigger score
        trigger_score = self._calculate_trigger_score(traffic_context)

        if trigger_score >= self.config['risk_threshold']:
            # Find appropriate deception environment
            env_id = self._select_deception_environment(traffic_context)

            if env_id:
                # Create attacker session
                session_id = await self._create_attacker_session(env_id, traffic_context)
                logger.info(f"Deception triggered: redirecting traffic to environment {env_id}, session {session_id}")

                self.metrics['attackers_redirected'] += 1
                return env_id

        return None

    def _calculate_trigger_score(self, traffic_context: Dict[str, Any]) -> float:
        """Calculate score indicating if deception should be triggered"""
        score = 0.0

        # Risk score contribution
        risk_score = traffic_context.get('risk_score', 0.0)
        score += risk_score * 0.4

        # Behavioral indicators
        if traffic_context.get('failed_auth_attempts', 0) > 3:
            score += 0.3
        if traffic_context.get('reconnaissance_activity', False):
            score += 0.2
        if traffic_context.get('lateral_movement_indicators', False):
            score += 0.4

        # Traffic pattern anomalies
        if traffic_context.get('unusual_timing', False):
            score += 0.1
        if traffic_context.get('suspicious_ip', False):
            score += 0.2

        # Known attacker indicators
        attacker_ip = traffic_context.get('source_ip')
        if attacker_ip and self._is_known_attacker(attacker_ip):
            score += 0.5

        return min(1.0, score)

    def _select_deception_environment(self, traffic_context: Dict[str, Any]) -> Optional[str]:
        """Select the most appropriate deception environment"""
        candidates = []

        for env in self.environments.values():
            if not env.active:
                continue

            # Check if trigger conditions match
            if self._check_trigger_conditions(env.trigger_conditions, traffic_context):
                # Calculate environment suitability score
                suitability = self._calculate_environment_suitability(env, traffic_context)
                candidates.append((env.env_id, suitability))

        if candidates:
            # Return environment with highest suitability
            candidates.sort(key=lambda x: x[1], reverse=True)
            return candidates[0][0]

        return None

    def _check_trigger_conditions(self, conditions: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if trigger conditions are met"""
        for condition_key, condition_config in conditions.items():
            if condition_key not in context:
                continue

            context_value = context[condition_key]
            operator = condition_config.get('operator', '==')
            expected_value = condition_config.get('value')

            if not self._evaluate_condition(context_value, operator, expected_value):
                return False

        return True

    def _calculate_environment_suitability(self, env: DeceptionEnvironment,
                                         traffic_context: Dict[str, Any]) -> float:
        """Calculate how suitable an environment is for the given traffic"""
        suitability = 0.0

        # Risk level alignment
        traffic_risk = traffic_context.get('risk_score', 0.5)
        env_risk_map = {'low': 0.3, 'medium': 0.6, 'high': 0.9}
        env_risk = env_risk_map.get(env.risk_level, 0.5)

        # Closer risk levels are more suitable
        risk_alignment = 1.0 - abs(traffic_risk - env_risk)
        suitability += risk_alignment * 0.5

        # Resource availability
        if env.fake_resources:
            suitability += 0.3

        # Intelligence gathering capability
        if env.intelligence_gathering:
            suitability += 0.2

        return suitability

    async def _create_attacker_session(self, env_id: str, traffic_context: Dict[str, Any]) -> str:
        """Create a new attacker session"""
        session_id = str(uuid.uuid4())

        session = AttackerSession(
            session_id=session_id,
            env_id=env_id,
            attacker_ip=traffic_context.get('source_ip', 'unknown'),
            start_time=datetime.now(),
            end_time=None,
            actions=[],
            intelligence_gathered={},
            risk_assessment=traffic_context.get('risk_level', 'unknown'),
            active=True
        )

        self.active_sessions[session_id] = session
        self.metrics['total_sessions'] += 1

        # Set session timeout
        asyncio.create_task(self._monitor_session_timeout(session))

        return session_id

    async def _monitor_session_timeout(self, session: AttackerSession):
        """Monitor session for timeout"""
        await asyncio.sleep(self.config['session_timeout'])

        if session.session_id in self.active_sessions and session.active:
            await self._end_attacker_session(session.session_id, "timeout")

    async def record_attacker_action(self, session_id: str, action: Dict[str, Any]):
        """Record an action taken by an attacker in the deception environment"""
        if session_id not in self.active_sessions:
            return

        session = self.active_sessions[session_id]
        session.actions.append({
            **action,
            'timestamp': datetime.now()
        })

        # Analyze action for intelligence
        intelligence = self._extract_intelligence_from_action(action, session)
        if intelligence:
            session.intelligence_gathered.update(intelligence)

        # Check for session termination conditions
        if self._should_terminate_session(session, action):
            await self._end_attacker_session(session_id, "termination_condition")

    def _extract_intelligence_from_action(self, action: Dict[str, Any],
                                        session: AttackerSession) -> Dict[str, Any]:
        """Extract intelligence from attacker action"""
        intelligence = {}

        action_type = action.get('type')

        if action_type == 'command_execution':
            command = action.get('command', '')
            intelligence.update(self._analyze_command(command))

        elif action_type == 'file_access':
            file_path = action.get('file_path', '')
            intelligence.update(self._analyze_file_access(file_path))

        elif action_type == 'network_connection':
            destination = action.get('destination', '')
            intelligence.update(self._analyze_network_activity(destination))

        elif action_type == 'data_exfiltration':
            data_type = action.get('data_type', '')
            intelligence['data_interests'] = intelligence.get('data_interests', [])
            intelligence['data_interests'].append(data_type)

        return intelligence

    def _analyze_command(self, command: str) -> Dict[str, Any]:
        """Analyze executed command for intelligence"""
        intelligence = {}

        # Detect tools and techniques
        tool_signatures = {
            'mimikatz': ['lsadump', 'sekurlsa', 'kerberos'],
            'powershell_empire': ['Empire', 'stager'],
            'metasploit': ['meterpreter', 'payload'],
            'cobalt_strike': ['beacon', 'c2']
        }

        for tool, signatures in tool_signatures.items():
            if any(sig.lower() in command.lower() for sig in signatures):
                intelligence['tools_detected'] = intelligence.get('tools_detected', [])
                intelligence['tools_detected'].append(tool)

        # Detect techniques
        techniques = []
        if 'net user' in command.lower() or 'whoami' in command.lower():
            techniques.append('reconnaissance')
        if 'psexec' in command.lower() or 'wmiexec' in command.lower():
            techniques.append('lateral_movement')
        if 'hashdump' in command.lower():
            techniques.append('credential_access')

        if techniques:
            intelligence['techniques_used'] = techniques

        return intelligence

    def _analyze_file_access(self, file_path: str) -> Dict[str, Any]:
        """Analyze file access patterns"""
        intelligence = {}

        sensitive_files = [
            'password', 'credential', 'secret', 'key', 'token',
            'financial', 'medical', 'personal', 'classified'
        ]

        if any(sensitive in file_path.lower() for sensitive in sensitive_files):
            intelligence['data_targets'] = intelligence.get('data_targets', [])
            intelligence['data_targets'].append('sensitive_files')

        return intelligence

    def _analyze_network_activity(self, destination: str) -> Dict[str, Any]:
        """Analyze network activity"""
        intelligence = {}

        # Check for C2 servers, data exfiltration, etc.
        try:
            ip = ipaddress.ip_address(destination.split(':')[0])
            if ip.is_private:
                intelligence['internal_network_activity'] = True
            else:
                intelligence['external_communication'] = True
        except:
            pass

        return intelligence

    def _should_terminate_session(self, session: AttackerSession, action: Dict[str, Any]) -> bool:
        """Check if session should be terminated"""
        # Terminate on high-risk actions
        high_risk_actions = ['privilege_escalation', 'data_exfiltration', 'ransomware_deployment']

        if action.get('type') in high_risk_actions:
            return True

        # Terminate after too many actions (potential DoS)
        if len(session.actions) > 100:
            return True

        # Terminate on critical system impact
        if action.get('system_impact') == 'critical':
            return True

        return False

    async def _end_attacker_session(self, session_id: str, reason: str):
        """End an attacker session and extract final intelligence"""
        if session_id not in self.active_sessions:
            return

        session = self.active_sessions[session_id]
        session.active = False
        session.end_time = datetime.now()

        # Extract final intelligence
        final_intelligence = self._extract_final_intelligence(session)

        intelligence_record = DeceptionIntelligence(
            intelligence_id=str(uuid.uuid4()),
            session_id=session_id,
            attacker_profile=self._build_attacker_profile(session),
            techniques_used=final_intelligence.get('techniques_used', []),
            tools_detected=final_intelligence.get('tools_detected', []),
            objectives_inferred=final_intelligence.get('objectives_inferred', []),
            indicators_extracted=self._extract_indicators(session),
            timestamp=datetime.now()
        )

        self.intelligence_log.append(intelligence_record)
        self.metrics['intelligence_gathered'] += 1

        # Update attacker profiles
        self._update_attacker_profiles(session.attacker_ip, intelligence_record)

        # Clean up session
        del self.active_sessions[session_id]

        logger.info(f"Attacker session {session_id} ended: {reason}")

    def _extract_final_intelligence(self, session: AttackerSession) -> Dict[str, Any]:
        """Extract final intelligence from completed session"""
        intelligence = {}

        # Aggregate techniques used
        all_techniques = set()
        all_tools = set()

        for action in session.actions:
            action_intel = self._extract_intelligence_from_action(action, session)
            all_techniques.update(action_intel.get('techniques_used', []))
            all_tools.update(action_intel.get('tools_detected', []))

        intelligence['techniques_used'] = list(all_techniques)
        intelligence['tools_detected'] = list(all_tools)

        # Infer objectives
        intelligence['objectives_inferred'] = self._infer_attacker_objectives(session)

        return intelligence

    def _infer_attacker_objectives(self, session: AttackerSession) -> List[str]:
        """Infer attacker objectives from session behavior"""
        objectives = []

        action_types = [action.get('type') for action in session.actions]

        if 'credential_access' in action_types:
            objectives.append('credential_theft')
        if 'lateral_movement' in action_types:
            objectives.append('network_compromise')
        if 'data_exfiltration' in action_types:
            objectives.append('data_theft')
        if 'ransomware_deployment' in action_types:
            objectives.append('ransomware')
        if 'reconnaissance' in action_types and len(session.actions) < 5:
            objectives.append('information_gathering')

        return objectives

    def _extract_indicators(self, session: AttackerSession) -> List[Dict[str, Any]]:
        """Extract IOCs and indicators from session"""
        indicators = []

        # IP addresses
        indicators.append({
            'type': 'ip',
            'value': session.attacker_ip,
            'context': 'attacker_source'
        })

        # Commands used
        for action in session.actions:
            if action.get('type') == 'command_execution':
                indicators.append({
                    'type': 'command',
                    'value': action.get('command'),
                    'context': 'attacker_tooling'
                })

        # Files accessed
        for action in session.actions:
            if action.get('type') == 'file_access':
                indicators.append({
                    'type': 'file',
                    'value': action.get('file_path'),
                    'context': 'targeted_data'
                })

        return indicators

    def _build_attacker_profile(self, session: AttackerSession) -> Dict[str, Any]:
        """Build attacker profile from session data"""
        profile = {
            'ip_address': session.attacker_ip,
            'session_duration': (session.end_time - session.start_time).total_seconds() if session.end_time else 0,
            'risk_level': session.risk_assessment,
            'actions_performed': len(session.actions),
            'first_seen': session.start_time,
            'last_seen': session.end_time or session.start_time
        }

        return profile

    def _update_attacker_profiles(self, ip_address: str, intelligence: DeceptionIntelligence):
        """Update attacker profiles with new intelligence"""
        if ip_address not in self.attacker_profiles:
            self.attacker_profiles[ip_address] = {
                'first_seen': intelligence.timestamp,
                'total_sessions': 0,
                'techniques_observed': set(),
                'tools_observed': set(),
                'objectives_observed': set()
            }

        profile = self.attacker_profiles[ip_address]
        profile['last_seen'] = intelligence.timestamp
        profile['total_sessions'] += 1
        profile['techniques_observed'].update(intelligence.techniques_used)
        profile['tools_observed'].update(intelligence.tools_detected)
        profile['objectives_observed'].update(intelligence.objectives_inferred)

    def _is_known_attacker(self, ip_address: str) -> bool:
        """Check if IP is known attacker"""
        return ip_address in self.attacker_profiles

    def _evaluate_condition(self, value: Any, operator: str, expected: Any) -> bool:
        """Evaluate a condition"""
        if operator == '==' or operator == 'equals':
            return value == expected
        elif operator == '!=' or operator == 'not_equals':
            return value != expected
        elif operator == '>' or operator == 'greater_than':
            return float(value) > float(expected)
        elif operator == '<' or operator == 'less_than':
            return float(value) < float(expected)
        elif operator == '>=':
            return float(value) >= float(expected)
        elif operator == '<=':
            return float(value) <= float(expected)
        elif operator == 'in':
            return value in expected
        elif operator == 'contains':
            return expected in str(value)
        else:
            return False

    def get_deception_metrics(self) -> Dict[str, Any]:
        """Get deception engine metrics"""
        active_sessions = len(self.active_sessions)
        total_environments = len(self.environments)
        active_environments = sum(1 for env in self.environments.values() if env.active)

        return {
            'total_sessions': self.metrics['total_sessions'],
            'active_sessions': active_sessions,
            'attackers_redirected': self.metrics['attackers_redirected'],
            'intelligence_gathered': self.metrics['intelligence_gathered'],
            'total_environments': total_environments,
            'active_environments': active_environments,
            'deception_effectiveness': self.metrics['deception_effectiveness'],
            'false_positives': self.metrics['false_positives'],
            'attacker_profiles': len(self.attacker_profiles)
        }

    def get_attacker_intelligence(self, ip_address: str = None) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
        """Get intelligence on attackers"""
        if ip_address:
            return self.attacker_profiles.get(ip_address, {})
        else:
            return list(self.attacker_profiles.values())

    def create_custom_environment(self, name: str, deception_type: DeceptionType,
                                trigger_conditions: Dict[str, Any],
                                fake_resources: List[Dict[str, Any]]) -> str:
        """Create a custom deception environment"""
        env_id = str(uuid.uuid4())

        environment = DeceptionEnvironment(
            env_id=env_id,
            name=name,
            deception_type=deception_type,
            trigger_conditions=trigger_conditions,
            fake_resources=fake_resources,
            monitoring_config={
                'log_all_commands': True,
                'capture_screenshots': False,
                'record_network_traffic': True,
                'analyze_tools': True
            },
            intelligence_gathering=[
                'command_patterns',
                'tool_signatures',
                'behavior_analysis'
            ],
            risk_level="medium",
            active=True,
            created_at=datetime.now(),
            last_accessed=None
        )

        self.environments[env_id] = environment
        logger.info(f"Custom deception environment created: {name} ({env_id})")

        return env_id

# Global deception engine instance
deception_engine = DeceptionEngine()

# Convenience functions
async def evaluate_for_deception(traffic_context: Dict[str, Any]) -> Optional[str]:
    """Evaluate traffic for deception redirection"""
    return await deception_engine.evaluate_traffic(traffic_context)

def record_deception_action(session_id: str, action: Dict[str, Any]):
    """Record an action in a deception session"""
    asyncio.create_task(deception_engine.record_attacker_action(session_id, action))
const now = () => new Date().toISOString();

const sampleThreats = [
  {
    id: 'TH-9821',
    severity: 'critical',
    title: 'Anomalous privilege escalation detected',
    source: 'uid-oracle',
    target: 'vault-secrets',
    timestamp: now(),
  },
  {
    id: 'TH-9834',
    severity: 'high',
    title: 'Suspicious API token reuse',
    source: 'uid-vector',
    target: 'api-gateway',
    timestamp: now(),
  },
  {
    id: 'TH-9848',
    severity: 'medium',
    title: 'Unusual data access pattern',
    source: 'uid-phantom',
    target: 'db-prod-01',
    timestamp: now(),
  },
];

const sampleIncidents = [
  {
    id: 'IN-4520',
    status: 'investigating',
    summary: 'Credential drift detected for service account',
    owner: 'SOC Analyst',
    opened_at: now(),
  },
  {
    id: 'IN-4521',
    status: 'mitigated',
    summary: 'Policy violation on critical storage bucket',
    owner: 'Threat Ops',
    opened_at: now(),
  },
];

const sampleMetrics = {
  health: 96,
  activeThreats: sampleThreats.length,
  incidentsOpen: sampleIncidents.filter((i) => i.status !== 'mitigated').length,
  averageLatencyMs: 42,
  eventRatePerMinute: 248,
  driftScore: 0.61,
};

module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.status(405).json({ error: 'method_not_allowed', message: 'Only GET is supported.' });
    return;
  }

  res.status(200).json({
    status: 'online',
    platform: 'Hollow Purple Demo Engine',
    version: '2.0.0-demo',
    timestamp: now(),
    metrics: sampleMetrics,
    threats: sampleThreats,
    incidents: sampleIncidents,
    downloadUrl: '/api/download',
  });
};

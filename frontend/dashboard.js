// dashboard.js placeholder\nconsole.log('Loaded dashboard.js');\n
/**
 * dashboard.js
 * ============
 * Hollow Purple — Main Dashboard Controller
 *
 * Orchestrates all dashboard modules: system metrics, alerts, graph, and
 * activity feed.  Manages periodic refresh cycles, API integration, and
 * cross-module event coordination.
 *
 * Architecture:
 *  - All API calls go through `apiFetch()` which handles auth, errors, retries.
 *  - Metrics are polled on independent intervals to avoid thundering-herd.
 *  - A simple pub/sub EventBus decouples modules from each other.
 *  - All DOM manipulation is batched inside `requestAnimationFrame` where possible.
 */

'use strict';

// ─── Configuration ────────────────────────────────────────────────────────────

const CONFIG = Object.freeze({
  API_BASE:           '/api',
  METRICS_INTERVAL_MS: 8_000,
  ALERTS_INTERVAL_MS:  5_000,
  GRAPH_INTERVAL_MS:  15_000,
  ACTIVITY_INTERVAL_MS: 3_000,
  RETRY_ATTEMPTS:     3,
  RETRY_DELAY_MS:     1_500,
  MAX_ACTIVITY_ITEMS: 80,
  MOCK_DATA:          true,   // ← flip to false when backend is live
});

// ─── EventBus ─────────────────────────────────────────────────────────────────

const EventBus = (() => {
  /** @type {Map<string, Set<Function>>} */
  const listeners = new Map();

  return {
    /**
     * Subscribe to an event channel.
     * @param {string} channel
     * @param {Function} handler
     * @returns {Function} Unsubscribe function
     */
    on(channel, handler) {
      if (!listeners.has(channel)) listeners.set(channel, new Set());
      listeners.get(channel).add(handler);
      return () => listeners.get(channel)?.delete(handler);
    },

    /**
     * Emit an event on a channel.
     * @param {string} channel
     * @param {*} payload
     */
    emit(channel, payload) {
      listeners.get(channel)?.forEach(h => {
        try { h(payload); } catch (err) { console.error(`[EventBus:${channel}]`, err); }
      });
    },
  };
})();

// ─── API Layer ─────────────────────────────────────────────────────────────────

/**
 * Fetch JSON from a relative API endpoint with retry logic.
 * @param {string} endpoint  e.g. '/system/status'
 * @param {number} [attempt]
 * @returns {Promise<any>}
 */
async function apiFetch(endpoint, attempt = 1) {
  const url = `${CONFIG.API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json', 'X-Client': 'hp-soc-dashboard/1.0' },
      signal: AbortSignal.timeout(6_000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return await res.json();
  } catch (err) {
    if (attempt < CONFIG.RETRY_ATTEMPTS) {
      await sleep(CONFIG.RETRY_DELAY_MS * attempt);
      return apiFetch(endpoint, attempt + 1);
    }
    console.warn(`[apiFetch] ${endpoint} failed after ${attempt} attempts:`, err.message);
    throw err;
  }
}

/** @param {number} ms */
const sleep = ms => new Promise(r => setTimeout(r, ms));

// ─── Mock Data Generator ───────────────────────────────────────────────────────

const MockData = (() => {
  let _criticalCount = 0;
  let _evalCount     = 4812;
  let _driftScore    = 0.42;
  let _epsBase       = 238;

  const IDENTITIES = ['uid-aurora', 'uid-cipher', 'uid-phantom', 'uid-nexus', 'uid-vector',
                      'uid-oracle', 'uid-spectre', 'uid-argon', 'uid-cobalt', 'uid-ferrite'];
  const RESOURCES  = ['bucket-pii', 'db-prod-01', 'kms-master', 'api-gateway', 'vault-secrets',
                      'queue-events', 'cache-redis', 'logs-audit', 'storage-hot', 'registry-img'];
  const ACTIONS    = ['GetObject','PutObject','DeleteItem','InvokeAPI','AdminAccess',
                      'ListBuckets','CreateToken','RevokeSession','ExportData','ModifyPolicy'];
  const REGIONS    = ['us-east-1','eu-west-2','ap-south-1','us-west-2'];

  const rand    = (a, b) => Math.random() * (b - a) + a;
  const randInt = (a, b) => Math.floor(rand(a, b + 1));
  const pick    = arr => arr[randInt(0, arr.length - 1)];
  const hex6    = () => Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(6, '0').toUpperCase();

  function systemStatus() {
    _evalCount  += randInt(60, 200);
    _driftScore  = Math.max(0.05, Math.min(0.99, _driftScore + (Math.random() - 0.49) * 0.04));
    _epsBase    += randInt(-15, 20);
    _criticalCount = randInt(0, 8);

    return {
      identities:   randInt(380, 420),
      critical:     _criticalCount,
      drift:        parseFloat(_driftScore.toFixed(2)),
      evaluations:  _evalCount,
      resources:    randInt(142, 156),
      mitigations:  randInt(18, 34),
      uptime:       '14d 06h 33m',
      eps:          Math.max(80, _epsBase),
      policyHash:   'a3f9' + hex6().toLowerCase(),
      engineVersion:'v2.4.1',
    };
  }

  function alerts(count = 12) {
    const severities = ['critical','critical','high','high','medium','medium','medium','low','low','info'];
    const titles = [
      'Behavioral drift threshold exceeded',
      'Unusual data export detected',
      'Identity accessing restricted resource',
      'Multiple failed policy evaluations',
      'Session anomaly: geolocation mismatch',
      'Privilege escalation attempt blocked',
      'High-velocity API calls from identity',
      'Resource accessed outside business hours',
      'MFA challenge failed — identity flagged',
      'Consecutive anomaly score exceeded 0.85',
      'Policy rule DENY triggered on critical asset',
      'New identity accessing PII bucket',
      'Suspicious lateral movement pattern',
      'Drift velocity spike detected',
    ];
    const now = Date.now();
    return Array.from({ length: count }, (_, i) => ({
      id:       `ALT-${(9000 + i).toString()}`,
      severity: pick(severities),
      title:    titles[i % titles.length],
      source:   pick(IDENTITIES),
      resource: pick(RESOURCES),
      region:   pick(REGIONS),
      action:   pick(ACTIONS),
      ts:       new Date(now - randInt(0, 3_600_000)).toISOString(),
      driftScore: parseFloat(rand(0.3, 0.99).toFixed(2)),
      ruleId:   `rule-${hex6().slice(0,4)}`,
    }));
  }

  function graphData() {
    const idNodes = IDENTITIES.slice(0, 7).map(id => ({
      id,
      type: 'identity',
      label: id.replace('uid-', ''),
      trust: parseFloat(rand(0.2, 0.99).toFixed(2)),
      flagged: Math.random() > 0.8,
      drifting: Math.random() > 0.7,
    }));
    const resNodes = RESOURCES.slice(0, 6).map(id => ({
      id,
      type: 'resource',
      label: id,
      sensitivity: pick(['low','medium','high','critical']),
      status: pick(['active','active','active','suspended']),
    }));
    const allNodes = [...idNodes, ...resNodes];
    const edges = [];
    idNodes.forEach(id => {
      const numConnections = randInt(1, 3);
      const shuffled = [...resNodes].sort(() => Math.random() - 0.5);
      shuffled.slice(0, numConnections).forEach(res => {
        edges.push({
          id:     `${id.id}->${res.id}`,
          source: id.id,
          target: res.id,
          action: pick(ACTIONS),
          count:  randInt(1, 120),
          denied: Math.random() > 0.75,
        });
      });
    });
    return { nodes: allNodes, edges };
  }

  function activityEvent() {
    const types = [
      () => ({ tag:'identity', text: `<strong>${pick(IDENTITIES)}</strong> authenticated from ${pick(REGIONS)}` }),
      () => ({ tag:'drift',    text: `Drift score for <strong>${pick(IDENTITIES)}</strong> updated to <strong>${rand(0.3,0.9).toFixed(2)}</strong>` }),
      () => ({ tag:'resource', text: `<strong>${pick(RESOURCES)}</strong> accessed by ${pick(IDENTITIES)}` }),
      () => ({ tag:'policy',   text: `Policy rule <strong>rule-${hex6().slice(0,4)}</strong> evaluated — DENY` }),
      () => ({ tag:'alert',    text: `Alert raised: ${pick(['drift breach','access anomaly','velocity spike','geo mismatch'])}` }),
    ];
    const ev = pick(types)();
    return { ...ev, ts: new Date().toISOString() };
  }

  return { systemStatus, alerts, graphData, activityEvent };
})();

// ─── State ─────────────────────────────────────────────────────────────────────

const State = {
  connected:     false,
  lastMetrics:   null,
  activityItems: [],
  intervals:     [],
};

// ─── DOM helpers ──────────────────────────────────────────────────────────────

/**
 * Set text content of an element by id, with optional class toggle.
 * @param {string} id
 * @param {string|number} text
 * @param {string} [className]
 */
function setText(id, text, className) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = text;
  if (className) el.className = className;
}

/**
 * Show a toast notification.
 * @param {string} message
 * @param {'green'|'red'|'amber'} [color]
 * @param {number} [duration]
 */
function showToast(message, color = 'green', duration = 3000) {
  const container = document.getElementById('toast-container');
  if (!container) return;
  const colorMap = { green:'var(--accent-green)', red:'var(--accent-red)', amber:'var(--accent-amber)' };
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.style.setProperty('--toast-color', colorMap[color] || colorMap.green);
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transition = 'opacity 0.3s';
    setTimeout(() => toast.remove(), 300);
  }, duration);
}

// ─── Clock ────────────────────────────────────────────────────────────────────

function startClock() {
  const el = document.getElementById('nav-clock');
  if (!el) return;
  const update = () => {
    const now = new Date();
    const hh = now.getUTCHours().toString().padStart(2, '0');
    const mm = now.getUTCMinutes().toString().padStart(2, '0');
    const ss = now.getUTCSeconds().toString().padStart(2, '0');
    el.textContent = `${hh}:${mm}:${ss} UTC`;
  };
  update();
  setInterval(update, 1000);
}

// ─── Connection status ────────────────────────────────────────────────────────

function setConnectionStatus(status) {
  const dot   = document.getElementById('conn-dot');
  const label = document.getElementById('conn-label');
  if (!dot || !label) return;
  const map = {
    connecting: { color: 'var(--accent-amber)', text: 'CONNECTING' },
    live:       { color: 'var(--accent-green)', text: 'LIVE' },
    error:      { color: 'var(--accent-red)',   text: 'OFFLINE' },
  };
  const cfg = map[status] || map.error;
  dot.style.background = cfg.color;
  label.textContent    = cfg.text;
  label.style.color    = cfg.color;
}

// ─── System metrics ───────────────────────────────────────────────────────────

/**
 * Fetch and render system-level status metrics.
 * @returns {Promise<void>}
 */
async function loadSystemMetrics() {
  let data;
  try {
    data = CONFIG.MOCK_DATA ? MockData.systemStatus() : await apiFetch('/system/status');
    setConnectionStatus('live');
    State.connected = true;
  } catch {
    setConnectionStatus('error');
    State.connected = false;
    return;
  }

  State.lastMetrics = data;
  requestAnimationFrame(() => updateMetricsView(data));
  EventBus.emit('metrics:updated', data);
}

/**
 * Update all metric card DOM elements from a metrics payload.
 * @param {object} data
 */
function updateMetricsView(data) {
  if (!data) return;

  const fmt = n => n >= 1000 ? `${(n/1000).toFixed(1)}k` : String(n);

  setText('m-identities',   fmt(data.identities));
  setText('m-identities-d', `${data.identities} total monitored`);

  const critEl = document.getElementById('m-critical');
  if (critEl) {
    critEl.textContent = data.critical;
    critEl.style.color = data.critical > 0 ? 'var(--accent-red)' : 'var(--accent-green)';
    critEl.style.textShadow = data.critical > 0
      ? '0 0 20px rgba(255,45,85,0.5)' : '0 0 20px rgba(0,255,136,0.3)';
  }
  setText('m-critical-d', data.critical > 0 ? `⚠ Requires attention` : '✓ No critical issues');

  const driftEl = document.getElementById('m-drift');
  if (driftEl) {
    driftEl.textContent = data.drift.toFixed(2);
    const driftColor = data.drift > 0.7 ? 'var(--accent-red)'
                     : data.drift > 0.4 ? 'var(--accent-amber)'
                     : 'var(--accent-green)';
    driftEl.style.color = driftColor;
  }
  setText('m-drift-d', `System drift index`);

  setText('m-evals',       fmt(data.evaluations));
  setText('m-evals-d',     `cumulative policy evals`);
  setText('m-resources',   fmt(data.resources));
  setText('m-resources-d', `across all regions`);
  setText('m-mitigations', fmt(data.mitigations));
  setText('m-mitigations-d', `actions today`);

  // Footer
  setText('f-engine', data.engineVersion || 'v2.4.1');
  setText('f-hash', data.policyHash ? data.policyHash.slice(0, 12) + '…' : '—');
  setText('f-uptime', data.uptime || '—');
  setText('f-eps', `${data.eps || 0}/s`);

  // Health badge
  const badge = document.getElementById('health-badge');
  const label = document.getElementById('health-label');
  if (badge && label) {
    if (data.critical > 5) {
      badge.style.borderColor = 'rgba(255,45,85,0.4)';
      badge.style.background  = 'rgba(255,45,85,0.1)';
      badge.style.color       = 'var(--accent-red)';
      label.textContent = 'CRITICAL';
    } else if (data.critical > 0 || data.drift > 0.65) {
      badge.style.borderColor = 'rgba(255,179,0,0.4)';
      badge.style.background  = 'rgba(255,179,0,0.1)';
      badge.style.color       = 'var(--accent-amber)';
      label.textContent = 'ELEVATED';
    } else {
      badge.style.borderColor = 'rgba(0,255,136,0.3)';
      badge.style.background  = 'rgba(0,255,136,0.07)';
      badge.style.color       = 'var(--accent-green)';
      label.textContent = 'NOMINAL';
    }
  }
}

// ─── Alerts loader ────────────────────────────────────────────────────────────

/**
 * Fetch and pass alerts to the alerts view module.
 * @returns {Promise<void>}
 */
async function loadAlerts() {
  let data;
  try {
    data = CONFIG.MOCK_DATA ? MockData.alerts() : await apiFetch('/alerts');
  } catch {
    return;
  }
  if (typeof AlertsView !== 'undefined') {
    AlertsView.renderAlerts(data);
  }
  EventBus.emit('alerts:updated', data);
}

// ─── Drift loader ─────────────────────────────────────────────────────────────

async function loadDriftData() {
  let data;
  try {
    data = CONFIG.MOCK_DATA
      ? { score: State.lastMetrics?.drift ?? 0.42, trend: 'stable' }
      : await apiFetch('/drift');
  } catch {
    return;
  }
  updateDriftBar(data.score);
  EventBus.emit('drift:updated', data);
}

/**
 * Animate the drift indicator bar.
 * @param {number} score  0–1
 */
function updateDriftBar(score) {
  const bar   = document.getElementById('drift-bar');
  const label = document.getElementById('drift-value-label');
  if (!bar || !label) return;
  const pct = Math.round(score * 100);
  bar.style.width = `${pct}%`;
  bar.style.setProperty('--pct', String(pct));
  label.textContent = score.toFixed(2);
  label.style.color = score > 0.7 ? 'var(--accent-red)'
                    : score > 0.4 ? 'var(--accent-amber)'
                    : 'var(--accent-green)';
}

// ─── Graph loader ─────────────────────────────────────────────────────────────

async function loadGraphData() {
  let data;
  try {
    data = CONFIG.MOCK_DATA ? MockData.graphData() : await apiFetch('/graph');
  } catch {
    return;
  }
  if (typeof GraphView !== 'undefined') {
    GraphView.updateGraph(data);
  }
  EventBus.emit('graph:updated', data);
}

// ─── Activity feed ────────────────────────────────────────────────────────────

function pushActivityEvent() {
  if (typeof AlertsView !== 'undefined') {
    const ev = MockData.activityEvent();
    AlertsView.addActivityItem(ev);
  }
}

// ─── Nav tabs ─────────────────────────────────────────────────────────────────

function initNavTabs() {
  document.querySelectorAll('.nav-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      // In a multi-view app, we'd swap content here.
      // For this dashboard we keep the single overview.
    });
  });
}

// ─── Periodic refresh ─────────────────────────────────────────────────────────

/**
 * Start all polling intervals and register cleanup.
 */
function startRefreshCycles() {
  const intervals = [
    setInterval(loadSystemMetrics, CONFIG.METRICS_INTERVAL_MS),
    setInterval(loadAlerts,        CONFIG.ALERTS_INTERVAL_MS),
    setInterval(loadGraphData,     CONFIG.GRAPH_INTERVAL_MS),
    setInterval(loadDriftData,     CONFIG.ALERTS_INTERVAL_MS),
    setInterval(pushActivityEvent, CONFIG.ACTIVITY_INTERVAL_MS),
  ];
  State.intervals.push(...intervals);
}

/**
 * Cancel all polling intervals.
 */
function stopRefreshCycles() {
  State.intervals.forEach(clearInterval);
  State.intervals.length = 0;
}

// ─── Visibility handling ──────────────────────────────────────────────────────

function handleVisibilityChange() {
  if (document.hidden) {
    stopRefreshCycles();
  } else {
    refreshDashboard();
    startRefreshCycles();
  }
}

// ─── Main init & refresh ──────────────────────────────────────────────────────

/**
 * Perform a full one-shot data refresh across all panels.
 * @returns {Promise<void>}
 */
async function refreshDashboard() {
  await Promise.allSettled([
    loadSystemMetrics(),
    loadAlerts(),
    loadDriftData(),
    loadGraphData(),
  ]);
}

/**
 * Initialize the dashboard.
 * Called once on DOMContentLoaded.
 */
async function initDashboard() {
  startClock();
  initNavTabs();
  setConnectionStatus('connecting');

  // Init sub-modules
  if (typeof GraphView !== 'undefined')  GraphView.init();
  if (typeof AlertsView !== 'undefined') AlertsView.init();

  // Initial data load
  await refreshDashboard();

  // Seed activity feed
  for (let i = 0; i < 8; i++) pushActivityEvent();

  // Start background polling
  startRefreshCycles();

  // Pause polling when tab is hidden
  document.addEventListener('visibilitychange', handleVisibilityChange);

  showToast('HOLLOW PURPLE SOC dashboard initialized', 'green', 3000);

  // Expose internal bus for module use
  window._HP_EventBus = EventBus;
}

// Boot when DOM is ready
document.addEventListener('DOMContentLoaded', initDashboard);
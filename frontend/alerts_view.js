// alerts_view.js placeholder\nconsole.log('Loaded alerts_view.js');\n
/**
 * alerts_view.js
 * ==============
 * Hollow Purple — Alert Stream & Activity Feed
 *
 * Renders the alert list with severity indicators, manages drift overlays,
 * handles filter interactions, and maintains the activity feed.
 *
 * Public interface (window.AlertsView):
 *   init()
 *   renderAlerts(alerts)
 *   addAlert(alert)
 *   filterAlerts(level)
 *   clearAlerts()
 *   addActivityItem(item)
 *
 * Design decisions:
 *  - Alert DOM nodes are keyed by alert.id so live updates don't re-render
 *    existing alerts, only prepend genuinely new ones.
 *  - Severity filtering is done by CSS class toggling (no DOM removal) for
 *    O(1) filter performance on large lists.
 *  - The activity feed uses a circular buffer capped at MAX_ACTIVITY_ITEMS to
 *    avoid unbounded DOM growth.
 *  - All timestamps display relative time ("2m ago") updated lazily on render.
 */

'use strict';

const AlertsView = (() => {

  // ── Constants ────────────────────────────────────────────────────────────────

  const MAX_ALERTS_DOM     = 200;  // Hard cap on rendered alert elements
  const MAX_ACTIVITY_ITEMS = 80;

  const SEVERITY_META = Object.freeze({
    critical: { label: 'C!', weight: 5, cssClass: 'sev-critical' },
    high:     { label: 'H',  weight: 4, cssClass: 'sev-high'     },
    medium:   { label: 'M',  weight: 3, cssClass: 'sev-medium'   },
    low:      { label: 'L',  weight: 2, cssClass: 'sev-low'      },
    info:     { label: 'I',  weight: 1, cssClass: 'sev-info'     },
  });

  const TAG_CLASSES = Object.freeze({
    identity: 'tag-identity',
    resource: 'tag-resource',
    drift:    'tag-drift',
    policy:   'tag-policy',
    alert:    'tag-alert',
  });

  // ── State ────────────────────────────────────────────────────────────────────

  /** @type {Map<string, HTMLElement>} */
  const alertElements = new Map();

  /** @type {object[]} */
  const alertData = [];

  let activeFilter = 'all';

  let activityCount  = 0;

  // ── DOM refs (resolved lazily) ───────────────────────────────────────────────

  const dom = {
    alertsList:    () => document.getElementById('alerts-list'),
    alertBadge:    () => document.getElementById('alert-count-badge'),
    activityFeed:  () => document.getElementById('activity-feed'),
    activityBadge: () => document.getElementById('activity-count-badge'),
    filterBar:     () => document.querySelector('.sev-filter'),
  };

  // ── Time helpers ──────────────────────────────────────────────────────────────

  /**
   * Return a human-readable relative time string.
   * @param {string} isoString
   * @returns {string}
   */
  function relativeTime(isoString) {
    const diff = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000);
    if (diff < 5)    return 'just now';
    if (diff < 60)   return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400)return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  }

  /**
   * Return HH:MM time string from ISO timestamp.
   * @param {string} isoString
   * @returns {string}
   */
  function shortTime(isoString) {
    const d = new Date(isoString);
    return `${d.getUTCHours().toString().padStart(2,'0')}:${d.getUTCMinutes().toString().padStart(2,'0')}`;
  }

  // ── Alert DOM builders ────────────────────────────────────────────────────────

  /**
   * Build the DOM element for a single alert.
   * @param {object} alert
   * @returns {HTMLElement}
   */
  function buildAlertElement(alert) {
    const meta = SEVERITY_META[alert.severity] || SEVERITY_META.info;

    const el = document.createElement('div');
    el.className = `alert-item ${meta.cssClass}`;
    el.dataset.severity = alert.severity;
    el.dataset.id       = alert.id;
    el.style.setProperty('--alert-color', getSeverityColor(alert.severity));

    // Determine visibility based on current filter
    if (activeFilter !== 'all' && activeFilter !== alert.severity) {
      el.classList.add('hidden');
    }

    el.innerHTML = `
      <div class="alert-severity-icon ${meta.cssClass}">${meta.label}</div>
      <div class="alert-body">
        <div class="alert-title" title="${escapeHtml(alert.title)}">${escapeHtml(alert.title)}</div>
        <div class="alert-meta">
          <span class="alert-id mono">${escapeHtml(alert.id)}</span>
          <span class="alert-ts" data-ts="${escapeHtml(alert.ts)}">${relativeTime(alert.ts)}</span>
          <span class="alert-source">${escapeHtml(alert.source || '—')}</span>
          ${alert.driftScore !== undefined
            ? `<span class="mono text-amber" style="font-size:9px">Δ${alert.driftScore.toFixed(2)}</span>`
            : ''}
        </div>
      </div>
    `;

    // Click: emit selection event
    el.addEventListener('click', () => {
      const isSelected = el.classList.contains('selected');
      document.querySelectorAll('.alert-item.selected').forEach(e => e.classList.remove('selected'));
      if (!isSelected) {
        el.classList.add('selected');
        el.style.background = 'var(--bg-hover)';
        window._HP_EventBus?.emit('alert:selected', alert);
      } else {
        el.style.background = '';
      }
    });

    return el;
  }

  function getSeverityColor(severity) {
    const map = {
      critical: 'var(--accent-red)',
      high:     '#ff6400',
      medium:   'var(--accent-amber)',
      low:      'var(--accent-blue)',
      info:     'var(--text-dim)',
    };
    return map[severity] || map.info;
  }

  /**
   * Minimal HTML escape.
   * @param {string} str
   * @returns {string}
   */
  function escapeHtml(str) {
    if (typeof str !== 'string') return String(str ?? '');
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // ── Alert badge ───────────────────────────────────────────────────────────────

  function updateAlertBadge() {
    const badge = dom.alertBadge();
    if (!badge) return;
    const visible = alertData.filter(a => activeFilter === 'all' || a.severity === activeFilter);
    const critical = alertData.filter(a => a.severity === 'critical').length;
    badge.textContent = `${visible.length}`;
    badge.style.background = critical > 0 ? 'rgba(255,45,85,0.2)'  : 'var(--bg-elevated)';
    badge.style.color      = critical > 0 ? 'var(--accent-red)'    : 'var(--text-dim)';
    badge.style.borderColor= critical > 0 ? 'rgba(255,45,85,0.4)'  : 'var(--border-normal)';
  }

  // ── Empty state ───────────────────────────────────────────────────────────────

  function showAlertsEmpty() {
    const list = dom.alertsList();
    if (!list) return;
    list.innerHTML = '<div class="empty-state"><span>▸ NO ALERTS MATCH FILTER</span></div>';
  }

  function hideAlertsEmpty() {
    const list = dom.alertsList();
    if (!list) return;
    const empty = list.querySelector('.empty-state');
    if (empty) empty.remove();
  }

  // ── Prune old alerts if DOM cap exceeded ──────────────────────────────────────

  function pruneAlerts() {
    if (alertData.length <= MAX_ALERTS_DOM) return;
    const excess = alertData.length - MAX_ALERTS_DOM;
    const removed = alertData.splice(MAX_ALERTS_DOM, excess);
    removed.forEach(a => {
      const el = alertElements.get(a.id);
      if (el) { el.remove(); alertElements.delete(a.id); }
    });
  }

  // ── Public: renderAlerts ──────────────────────────────────────────────────────

  /**
   * Replace the alert list with a new dataset.
   * Existing alerts that are still present are kept (not re-rendered).
   * New alerts are prepended.
   * @param {object[]} alerts  Array of alert objects
   */
  function renderAlerts(alerts) {
    if (!Array.isArray(alerts)) return;

    const list = dom.alertsList();
    if (!list) return;

    // Sort by severity weight DESC, then timestamp DESC
    const sorted = [...alerts].sort((a, b) => {
      const sw = (SEVERITY_META[b.severity]?.weight ?? 0) - (SEVERITY_META[a.severity]?.weight ?? 0);
      if (sw !== 0) return sw;
      return new Date(b.ts).getTime() - new Date(a.ts).getTime();
    });

    const incomingIds = new Set(sorted.map(a => a.id));

    // Remove stale elements
    alertData.slice().forEach(a => {
      if (!incomingIds.has(a.id)) {
        const el = alertElements.get(a.id);
        if (el) { el.remove(); alertElements.delete(a.id); }
        const idx = alertData.findIndex(x => x.id === a.id);
        if (idx !== -1) alertData.splice(idx, 1);
      }
    });

    // Build fragment for new alerts
    const newAlerts = sorted.filter(a => !alertElements.has(a.id));
    const fragment  = document.createDocumentFragment();
    const newElements = [];

    newAlerts.forEach(a => {
      const el = buildAlertElement(a);
      alertData.unshift(a);
      alertElements.set(a.id, el);
      newElements.push(el);
      fragment.appendChild(el);
    });

    if (fragment.childNodes.length > 0) {
      hideAlertsEmpty();
      list.insertBefore(fragment, list.firstChild);
    }

    pruneAlerts();

    if (alertData.length === 0) showAlertsEmpty();
    updateAlertBadge();

    // Refresh relative timestamps
    refreshTimestamps();
  }

  // ── Public: addAlert ──────────────────────────────────────────────────────────

  /**
   * Prepend a single new alert to the list.
   * @param {object} alert
   */
  function addAlert(alert) {
    if (!alert?.id || alertElements.has(alert.id)) return;

    const list = dom.alertsList();
    if (!list) return;

    hideAlertsEmpty();

    const el = buildAlertElement(alert);
    alertData.unshift(alert);
    alertElements.set(alert.id, el);

    list.insertBefore(el, list.firstChild);
    pruneAlerts();
    updateAlertBadge();

    // Flash border for new critical alert
    if (alert.severity === 'critical') {
      flashCriticalAlert(el);
    }
  }

  function flashCriticalAlert(el) {
    el.style.transition = 'background 0.1s';
    el.style.background = 'rgba(255,45,85,0.12)';
    setTimeout(() => { el.style.background = ''; }, 600);
  }

  // ── Public: filterAlerts ──────────────────────────────────────────────────────

  /**
   * Filter the displayed alerts by severity level.
   * @param {'all'|'critical'|'high'|'medium'|'low'|'info'} level
   */
  function filterAlerts(level) {
    const validLevels = new Set(['all', 'critical', 'high', 'medium', 'low', 'info']);
    if (!validLevels.has(level)) return;

    activeFilter = level;

    alertElements.forEach((el, id) => {
      const alert = alertData.find(a => a.id === id);
      if (!alert) return;
      const visible = level === 'all' || alert.severity === level;
      el.classList.toggle('hidden', !visible);
    });

    const anyVisible = [...alertElements.values()].some(el => !el.classList.contains('hidden'));
    if (!anyVisible) showAlertsEmpty();
    else hideAlertsEmpty();

    updateAlertBadge();
  }

  // ── Public: clearAlerts ───────────────────────────────────────────────────────

  /**
   * Remove all alerts from the panel.
   */
  function clearAlerts() {
    const list = dom.alertsList();
    if (!list) return;
    alertElements.forEach(el => el.remove());
    alertElements.clear();
    alertData.length = 0;
    showAlertsEmpty();
    updateAlertBadge();
  }

  // ── Timestamp refresh ─────────────────────────────────────────────────────────

  function refreshTimestamps() {
    document.querySelectorAll('.alert-ts[data-ts]').forEach(el => {
      el.textContent = relativeTime(el.dataset.ts);
    });
  }

  // ── Activity feed ─────────────────────────────────────────────────────────────

  /**
   * Prepend a single event to the activity feed.
   * @param {{ tag: string, text: string, ts: string }} item
   */
  function addActivityItem(item) {
    const feed = dom.activityFeed();
    if (!feed) return;

    // Remove empty state
    const empty = feed.querySelector('.empty-state');
    if (empty) empty.remove();

    // Prune if over cap
    const existing = feed.querySelectorAll('.activity-item');
    if (existing.length >= MAX_ACTIVITY_ITEMS) {
      existing[existing.length - 1].remove();
    }

    const ts = shortTime(item.ts);
    const tagClass = TAG_CLASSES[item.tag] || 'tag-policy';

    const el = document.createElement('div');
    el.className = 'activity-item';
    el.innerHTML = `
      <div class="activity-time">${ts}</div>
      <div class="activity-content">
        ${item.text}
        <div><span class="activity-tag ${tagClass}">${(item.tag || 'event').toUpperCase()}</span></div>
      </div>
    `;

    feed.insertBefore(el, feed.firstChild);
    activityCount++;

    const badge = dom.activityBadge();
    if (badge) badge.textContent = String(activityCount);
  }

  // ── Filter buttons ────────────────────────────────────────────────────────────

  function initFilterButtons() {
    const bar = dom.filterBar();
    if (!bar) return;

    bar.addEventListener('click', e => {
      const btn = e.target.closest('.sev-btn');
      if (!btn) return;

      bar.querySelectorAll('.sev-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const level = btn.dataset.level || 'all';
      filterAlerts(level);
    });
  }

  // ── Periodic timestamp refresh ────────────────────────────────────────────────

  function startTimestampRefresh() {
    setInterval(refreshTimestamps, 30_000);
  }

  // ── Public: init ─────────────────────────────────────────────────────────────

  /**
   * Initialize the alerts view.
   * Must be called once after the DOM is ready.
   */
  function init() {
    initFilterButtons();
    startTimestampRefresh();

    // Listen for graph node selection to cross-highlight alerts
    window._HP_EventBus?.on('alert:selected', alert => {
      window._HP_EventBus?.emit('highlight:identity', alert.source);
    });
  }

  return {
    init,
    renderAlerts,
    addAlert,
    filterAlerts,
    clearAlerts,
    addActivityItem,
  };

})();

// Expose globally for cross-module access
window.AlertsView = AlertsView;
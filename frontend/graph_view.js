// graph_view.js placeholder\nconsole.log('Loaded graph_view.js');\n
/**
 * graph_view.js
 * =============
 * Hollow Purple — Identity–Resource Interaction Graph
 *
 * Renders a force-directed graph on an HTML Canvas showing identities,
 * resources, and their access relationships.  Layout is deterministic given
 * the same seed data (positions are seeded from node IDs using a linear
 * congruential PRNG).
 *
 * Public interface (window.GraphView):
 *   init()
 *   renderGraph(data)
 *   addNode(node)
 *   addEdge(edge)
 *   highlightNode(nodeId)
 *   updateGraph(data)
 *
 * Rendering pipeline:
 *   1. Physics tick  → update node positions (spring + repulsion)
 *   2. Draw edges    → with directional arrows, colored by denial status
 *   3. Draw nodes    → circles with type-coded color, glow on highlight
 *   4. Draw labels   → clipped mono text beneath each node
 *   5. Draw HUD      → bottom-right stats overlay
 */

'use strict';

const GraphView = (() => {

  // ── Constants ───────────────────────────────────────────────────────────────

  const NODE_RADIUS = {
    identity: 16,
    resource: 20,
  };

  const COLOR = {
    identity: '#00aaff',
    resource: '#9d4edd',
    flagged:  '#ff2d55',
    drifting: '#ffb300',
    denied:   'rgba(255,45,85,0.7)',
    allowed:  'rgba(0,255,136,0.25)',
    bg:       '#0a0f14',
    grid:     'rgba(0,255,136,0.03)',
    label:    'rgba(232,237,242,0.8)',
    hud:      'rgba(0,255,136,0.5)',
  };

  const PHYSICS = {
    repulsion:   4500,
    springLen:   160,
    springK:     0.035,
    damping:     0.78,
    centerForce: 0.018,
    maxVelocity: 6,
    ticksPerFrame: 2,
  };

  // ── State ────────────────────────────────────────────────────────────────────

  let canvas, ctx;
  let nodes    = [];          // { id, type, label, x, y, vx, vy, ... }
  let edges    = [];          // { id, source, target, action, count, denied }
  let nodeMap  = new Map();   // id → node
  let selectedNodeId = null;
  let animFrameId    = null;
  let isDragging     = false;
  let dragNode       = null;
  let hoveredNode    = null;
  let viewOffset     = { x: 0, y: 0 };
  let viewScale      = 1;
  let isPanning      = false;
  let panStart       = { x: 0, y: 0 };
  let lastPanOffset  = { x: 0, y: 0 };
  let tickCount      = 0;
  let physicsActive  = true;

  // ── Deterministic PRNG (LCG seeded from string) ──────────────────────────────

  /**
   * Create a seeded PRNG returning [0, 1).
   * @param {string} seed
   * @returns {() => number}
   */
  function makePRNG(seed) {
    let state = 0;
    const seedStr = String(seed);
    for (let i = 0; i < seedStr.length; i++) {
      state = (state * 31 + seedStr.charCodeAt(i)) >>> 0;
    }
    return function () {
      state = (state * 1664525 + 1013904223) >>> 0;
      return state / 0x100000000;
    };
  }

  /**
   * Assign deterministic initial positions using a seeded PRNG so that
   * reloading with the same data produces the same starting layout.
   * @param {object[]} rawNodes
   */
  function seedPositions(rawNodes) {
    const w = canvas.width / (window.devicePixelRatio || 1);
    const h = canvas.height / (window.devicePixelRatio || 1);
    const cx = w / 2, cy = h / 2;

    rawNodes.forEach(n => {
      const rng = makePRNG(n.id);
      const angle  = rng() * Math.PI * 2;
      const radius = 80 + rng() * Math.min(cx, cy) * 0.55;
      n.x  = cx + Math.cos(angle) * radius;
      n.y  = cy + Math.sin(angle) * radius;
      n.vx = 0;
      n.vy = 0;
    });
  }

  // ── Canvas setup ─────────────────────────────────────────────────────────────

  function setupCanvas() {
    canvas = document.getElementById('graph-canvas');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    attachInteraction();
  }

  function resizeCanvas() {
    if (!canvas) return;
    const container = canvas.parentElement;
    const dpr = window.devicePixelRatio || 1;
    const w   = container.clientWidth;
    const h   = container.clientHeight;
    canvas.width  = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width  = `${w}px`;
    canvas.style.height = `${h}px`;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw(); // immediate redraw after resize
  }

  // ── Physics simulation ───────────────────────────────────────────────────────

  function physicsStep() {
    if (!physicsActive || nodes.length === 0) return;

    const dpr = window.devicePixelRatio || 1;
    const w   = canvas.width / dpr;
    const h   = canvas.height / dpr;
    const cx  = w / 2 + viewOffset.x / viewScale;
    const cy  = h / 2 + viewOffset.y / viewScale;

    for (let step = 0; step < PHYSICS.ticksPerFrame; step++) {
      // Repulsion between all node pairs
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dist2 = dx * dx + dy * dy + 1;
          const dist  = Math.sqrt(dist2);
          const force = PHYSICS.repulsion / dist2;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          a.vx -= fx; a.vy -= fy;
          b.vx += fx; b.vy += fy;
        }
      }

      // Spring attraction along edges
      edges.forEach(e => {
        const src = nodeMap.get(e.source);
        const tgt = nodeMap.get(e.target);
        if (!src || !tgt) return;
        const dx   = tgt.x - src.x;
        const dy   = tgt.y - src.y;
        const dist = Math.sqrt(dx * dx + dy * dy) + 0.01;
        const displacement = dist - PHYSICS.springLen;
        const force = PHYSICS.springK * displacement;
        const fx = (dx / dist) * force;
        const fy = (dy / dist) * force;
        src.vx += fx; src.vy += fy;
        tgt.vx -= fx; tgt.vy -= fy;
      });

      // Center-pull
      nodes.forEach(n => {
        n.vx += (cx - n.x) * PHYSICS.centerForce;
        n.vy += (cy - n.y) * PHYSICS.centerForce;
      });

      // Integrate + damp
      nodes.forEach(n => {
        if (n === dragNode) return;
        n.vx = Math.max(-PHYSICS.maxVelocity, Math.min(PHYSICS.maxVelocity, n.vx * PHYSICS.damping));
        n.vy = Math.max(-PHYSICS.maxVelocity, Math.min(PHYSICS.maxVelocity, n.vy * PHYSICS.damping));
        n.x += n.vx;
        n.y += n.vy;
      });
    }

    tickCount++;
    // Gradually cool physics after initial settlement
    if (tickCount > 300) {
      PHYSICS.damping = Math.min(0.92, PHYSICS.damping + 0.0001);
    }
  }

  // ── Drawing ──────────────────────────────────────────────────────────────────

  function draw() {
    if (!ctx || !canvas) return;
    const dpr = window.devicePixelRatio || 1;
    const w   = canvas.width / dpr;
    const h   = canvas.height / dpr;

    ctx.clearRect(0, 0, w, h);

    // Background
    ctx.fillStyle = COLOR.bg;
    ctx.fillRect(0, 0, w, h);

    // Grid
    drawGrid(w, h);

    // World-space transform
    ctx.save();
    ctx.translate(w / 2 + viewOffset.x, h / 2 + viewOffset.y);
    ctx.scale(viewScale, viewScale);
    ctx.translate(-w / 2, -h / 2);

    drawEdges(w, h);
    drawNodes();

    ctx.restore();

    // HUD (screen-space)
    drawHUD(w, h);
  }

  function drawGrid(w, h) {
    const gridSize = 40;
    ctx.strokeStyle = COLOR.grid;
    ctx.lineWidth   = 1;
    ctx.beginPath();
    for (let x = 0; x < w; x += gridSize) {
      ctx.moveTo(x, 0); ctx.lineTo(x, h);
    }
    for (let y = 0; y < h; y += gridSize) {
      ctx.moveTo(0, y); ctx.lineTo(w, y);
    }
    ctx.stroke();
  }

  function drawEdges(w, h) {
    edges.forEach(e => {
      const src = nodeMap.get(e.source);
      const tgt = nodeMap.get(e.target);
      if (!src || !tgt) return;

      const isHighlighted = selectedNodeId === e.source || selectedNodeId === e.target
                         || hoveredNode?.id === e.source || hoveredNode?.id === e.target;

      const color = e.denied ? COLOR.denied : COLOR.allowed;
      const alpha = isHighlighted ? 1 : 0.45;

      const dx   = tgt.x - src.x;
      const dy   = tgt.y - src.y;
      const len  = Math.sqrt(dx * dx + dy * dy);
      const ux   = dx / len, uy = dy / len;

      const srcR = NODE_RADIUS[src.type] || 14;
      const tgtR = NODE_RADIUS[tgt.type] || 14;

      const x1 = src.x + ux * srcR;
      const y1 = src.y + uy * srcR;
      const x2 = tgt.x - ux * (tgtR + 6);
      const y2 = tgt.y - uy * (tgtR + 6);

      // Edge line
      ctx.beginPath();
      ctx.moveTo(x1, y1);
      ctx.lineTo(x2, y2);
      ctx.strokeStyle = color;
      ctx.lineWidth = isHighlighted ? (e.denied ? 2 : 1.5) : (e.denied ? 1.5 : 1);
      ctx.globalAlpha = alpha;

      if (e.denied) {
        ctx.setLineDash([4, 4]);
      } else {
        ctx.setLineDash([]);
      }
      ctx.stroke();
      ctx.setLineDash([]);

      // Arrowhead
      const arrowLen = 8, arrowAngle = 0.4;
      const angle = Math.atan2(y2 - y1, x2 - x1);
      ctx.beginPath();
      ctx.moveTo(x2, y2);
      ctx.lineTo(x2 - arrowLen * Math.cos(angle - arrowAngle), y2 - arrowLen * Math.sin(angle - arrowAngle));
      ctx.lineTo(x2 - arrowLen * Math.cos(angle + arrowAngle), y2 - arrowLen * Math.sin(angle + arrowAngle));
      ctx.closePath();
      ctx.fillStyle = color;
      ctx.fill();

      // Edge count label (only on highlighted edges)
      if (isHighlighted && e.count > 1) {
        const mx = (x1 + x2) / 2;
        const my = (y1 + y2) / 2;
        ctx.globalAlpha = 0.9;
        ctx.fillStyle = '#0a0f14';
        ctx.fillRect(mx - 12, my - 7, 24, 14);
        ctx.fillStyle = e.denied ? '#ff2d55' : '#00ff88';
        ctx.font = '9px "Share Tech Mono", monospace';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`×${e.count}`, mx, my);
      }

      ctx.globalAlpha = 1;
    });
  }

  function drawNodes() {
    nodes.forEach(n => {
      const r = NODE_RADIUS[n.type] || 14;
      const isSelected = selectedNodeId === n.id;
      const isHovered  = hoveredNode?.id === n.id;

      // Determine node color
      let baseColor;
      if (n.flagged)       baseColor = COLOR.flagged;
      else if (n.drifting) baseColor = COLOR.drifting;
      else                 baseColor = COLOR[n.type] || '#888';

      // Glow (selected or hovered)
      if (isSelected || isHovered) {
        ctx.shadowBlur  = isSelected ? 30 : 16;
        ctx.shadowColor = baseColor;
      }

      // Outer ring
      ctx.beginPath();
      ctx.arc(n.x, n.y, r + 3, 0, Math.PI * 2);
      ctx.strokeStyle = baseColor;
      ctx.lineWidth   = isSelected ? 2.5 : 1;
      ctx.globalAlpha = isSelected ? 0.9 : 0.35;
      ctx.stroke();

      // Fill
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.globalAlpha = 1;

      const gradient = ctx.createRadialGradient(n.x - r*0.3, n.y - r*0.3, 0, n.x, n.y, r);
      gradient.addColorStop(0, hexToRgba(baseColor, 0.5));
      gradient.addColorStop(1, hexToRgba(baseColor, 0.15));
      ctx.fillStyle = gradient;
      ctx.fill();

      // Border
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.strokeStyle = baseColor;
      ctx.lineWidth = isSelected ? 2 : 1;
      ctx.stroke();

      ctx.shadowBlur = 0;

      // Type icon
      ctx.fillStyle = baseColor;
      ctx.font = `${r * 0.75}px "Share Tech Mono"`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const icon = n.type === 'identity' ? '⬡' : '◈';
      ctx.fillText(icon, n.x, n.y);

      // Label
      ctx.font = '9px "Share Tech Mono", monospace';
      ctx.fillStyle = COLOR.label;
      ctx.globalAlpha = isSelected || isHovered ? 1 : 0.7;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'top';
      const nodeLabel = n.label ? String(n.label) : String(n.id);
      const label = nodeLabel.length > 10 ? nodeLabel.slice(0, 9) + '…' : nodeLabel;
      ctx.fillText(label, n.x, n.y + r + 4);

      ctx.globalAlpha = 1;
    });
  }

  function drawHUD(w, h) {
    const stats = [
      `NODES ${nodes.length}`,
      `EDGES ${edges.length}`,
      `TICK ${tickCount}`,
    ];
    ctx.font = '9px "Share Tech Mono", monospace';
    ctx.fillStyle = COLOR.hud;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'bottom';
    stats.forEach((s, i) => {
      ctx.fillText(s, w - 10, h - 10 - i * 14);
    });
  }

  // ── Animation loop ────────────────────────────────────────────────────────────

  function startLoop() {
    if (animFrameId !== null) return;
    const loop = () => {
      physicsStep();
      draw();
      animFrameId = requestAnimationFrame(loop);
    };
    animFrameId = requestAnimationFrame(loop);
  }

  function stopLoop() {
    if (animFrameId !== null) {
      cancelAnimationFrame(animFrameId);
      animFrameId = null;
    }
  }

  // ── Coordinate helpers ────────────────────────────────────────────────────────

  /**
   * Convert a canvas-space mouse event position to world-space coordinates.
   * @param {MouseEvent} e
   * @returns {{ x: number, y: number }}
   */
  function eventToWorld(e) {
    const rect = canvas.getBoundingClientRect();
    const cx   = rect.left + rect.width / 2;
    const cy   = rect.top  + rect.height / 2;
    const sx   = (e.clientX - cx - viewOffset.x) / viewScale + rect.width / 2;
    const sy   = (e.clientY - cy - viewOffset.y) / viewScale + rect.height / 2;
    return { x: sx, y: sy };
  }

  function nodeAtPoint(worldX, worldY) {
    // Reverse order so top-painted nodes are hit first
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const r = (NODE_RADIUS[n.type] || 14) + 4;
      const dx = n.x - worldX, dy = n.y - worldY;
      if (dx * dx + dy * dy <= r * r) return n;
    }
    return null;
  }

  // ── Interaction ───────────────────────────────────────────────────────────────

  function attachInteraction() {
    canvas.addEventListener('mousedown',  onMouseDown);
    canvas.addEventListener('mousemove',  onMouseMove);
    canvas.addEventListener('mouseup',    onMouseUp);
    canvas.addEventListener('mouseleave', onMouseLeave);
    canvas.addEventListener('wheel',      onWheel,      { passive: false });
    canvas.addEventListener('dblclick',   onDblClick);
  }

  function onMouseDown(e) {
    e.preventDefault();
    const world = eventToWorld(e);
    const hit   = nodeAtPoint(world.x, world.y);
    if (hit) {
      isDragging = true;
      dragNode   = hit;
      hit.vx = 0; hit.vy = 0;
    } else {
      isPanning    = true;
      panStart     = { x: e.clientX, y: e.clientY };
      lastPanOffset = { ...viewOffset };
    }
  }

  function onMouseMove(e) {
    const world = eventToWorld(e);

    if (isDragging && dragNode) {
      dragNode.x  = world.x;
      dragNode.y  = world.y;
      dragNode.vx = 0;
      dragNode.vy = 0;
      return;
    }

    if (isPanning) {
      viewOffset.x = lastPanOffset.x + (e.clientX - panStart.x);
      viewOffset.y = lastPanOffset.y + (e.clientY - panStart.y);
      return;
    }

    // Hover detection
    const hit = nodeAtPoint(world.x, world.y);
    if (hit !== hoveredNode) {
      hoveredNode = hit;
      canvas.style.cursor = hit ? 'pointer' : 'grab';
      updateTooltip(hit, e);
    } else if (hit) {
      updateTooltip(hit, e);
    }
  }

  function onMouseUp() {
    isDragging = false;
    dragNode   = null;
    isPanning  = false;
    canvas.style.cursor = 'grab';
  }

  function onMouseLeave() {
    isDragging  = false;
    dragNode    = null;
    isPanning   = false;
    hoveredNode = null;
    hideTooltip();
  }

  function onWheel(e) {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    viewScale = Math.max(0.3, Math.min(3, viewScale * delta));
  }

  function onDblClick(e) {
    const world = eventToWorld(e);
    const hit   = nodeAtPoint(world.x, world.y);
    if (hit) {
      highlightNode(hit.id);
    }
  }

  // ── Tooltip ───────────────────────────────────────────────────────────────────

  function updateTooltip(node, e) {
    const tip = document.getElementById('graph-tooltip');
    if (!tip) return;
    if (!node) { hideTooltip(); return; }

    const rect    = canvas.getBoundingClientRect();
    const relX    = e.clientX - rect.left;
    const relY    = e.clientY - rect.top;
    const offsetX = relX + 16;
    const offsetY = relY - 10;

    // Count edges
    const edgeCount = edges.filter(ed => ed.source === node.id || ed.target === node.id).length;
    const denied    = edges.filter(ed => (ed.source === node.id || ed.target === node.id) && ed.denied).length;

    tip.innerHTML = `
      <div class="tooltip-label">${node.id}</div>
      <div class="tooltip-row"><span>TYPE</span><span>${(node.type || 'unknown').toUpperCase()}</span></div>
      <div class="tooltip-row"><span>CONNECTIONS</span><span>${edgeCount}</span></div>
      <div class="tooltip-row"><span>DENIED EDGES</span><span style="color:var(--accent-red)">${denied}</span></div>
      ${node.trust !== undefined ? `<div class="tooltip-row"><span>TRUST</span><span>${node.trust.toFixed(2)}</span></div>` : ''}
      ${node.sensitivity ? `<div class="tooltip-row"><span>SENSITIVITY</span><span>${node.sensitivity.toUpperCase()}</span></div>` : ''}
      ${node.flagged  ? `<div class="tooltip-row"><span>STATUS</span><span style="color:var(--accent-red)">FLAGGED</span></div>` : ''}
      ${node.drifting ? `<div class="tooltip-row"><span>DRIFT</span><span style="color:var(--accent-amber)">ANOMALOUS</span></div>` : ''}
    `;
    tip.style.left = `${offsetX}px`;
    tip.style.top  = `${offsetY}px`;
    tip.classList.add('visible');
  }

  function hideTooltip() {
    const tip = document.getElementById('graph-tooltip');
    if (tip) tip.classList.remove('visible');
  }

  // ── Toolbar buttons ───────────────────────────────────────────────────────────

  function attachToolbar() {
    document.getElementById('btn-reset-graph')?.addEventListener('click', () => {
      viewOffset = { x: 0, y: 0 };
      viewScale  = 1;
      selectedNodeId = null;
      updateSelectedLabel(null);
    });

    document.getElementById('btn-relayout')?.addEventListener('click', () => {
      tickCount      = 0;
      physicsActive  = true;
      PHYSICS.damping = 0.78;
      seedPositions(nodes);
    });

    document.getElementById('btn-fit-graph')?.addEventListener('click', fitAll);
  }

  function fitAll() {
    if (nodes.length === 0) return;
    const dpr = window.devicePixelRatio || 1;
    const w   = canvas.width / dpr;
    const h   = canvas.height / dpr;

    const xs = nodes.map(n => n.x);
    const ys = nodes.map(n => n.y);
    const minX = Math.min(...xs), maxX = Math.max(...xs);
    const minY = Math.min(...ys), maxY = Math.max(...ys);
    const graphW = maxX - minX + 80;
    const graphH = maxY - minY + 80;

    const scaleX = w / graphW;
    const scaleY = h / graphH;
    viewScale = Math.min(scaleX, scaleY, 1.5) * 0.9;

    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    viewOffset.x = (w / 2 - cx) * viewScale;
    viewOffset.y = (h / 2 - cy) * viewScale;
  }

  function updateSelectedLabel(nodeId) {
    const el = document.getElementById('graph-selected-label');
    if (!el) return;
    el.textContent = nodeId ? `SELECTED: ${nodeId}` : '';
  }

  function updateNodeCount() {
    const el = document.getElementById('graph-node-count');
    if (el) el.textContent = `${nodes.length} nodes · ${edges.length} edges`;
  }

  // ── Utility ───────────────────────────────────────────────────────────────────

  function hexToRgba(hex, alpha) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  // ── Public API ────────────────────────────────────────────────────────────────

  /**
   * Initialize the graph view — must be called once after DOM is ready.
   */
  function init() {
    setupCanvas();
    attachToolbar();
    startLoop();
  }

  /**
   * Replace the current graph with new data and restart the layout.
   * @param {{ nodes: object[], edges: object[] }} data
   */
  function renderGraph(data) {
    if (!data || !Array.isArray(data.nodes) || !Array.isArray(data.edges)) return;

    nodes  = data.nodes.map(n => ({ ...n, vx: 0, vy: 0 }));
    edges  = data.edges;
    nodeMap.clear();
    nodes.forEach(n => nodeMap.set(n.id, n));

    tickCount      = 0;
    physicsActive  = true;
    PHYSICS.damping = 0.78;
    selectedNodeId = null;

    seedPositions(nodes);
    updateNodeCount();
  }

  /**
   * Add a single node to the graph without full re-render.
   * @param {{ id: string, type: 'identity'|'resource', label: string, [key: string]: any }} node
   */
  function addNode(node) {
    if (!node?.id || nodeMap.has(node.id)) return;
    const dpr = window.devicePixelRatio || 1;
    const w   = canvas.width / dpr;
    const h   = canvas.height / dpr;
    const rng = makePRNG(node.id + Date.now());
    const newNode = {
      ...node,
      x:  w * 0.2 + rng() * w * 0.6,
      y:  h * 0.2 + rng() * h * 0.6,
      vx: (rng() - 0.5) * 2,
      vy: (rng() - 0.5) * 2,
    };
    nodes.push(newNode);
    nodeMap.set(newNode.id, newNode);
    updateNodeCount();
  }

  /**
   * Add a single edge to the graph.
   * @param {{ id: string, source: string, target: string, [key: string]: any }} edge
   */
  function addEdge(edge) {
    if (!edge?.id || !nodeMap.has(edge.source) || !nodeMap.has(edge.target)) return;
    if (edges.some(e => e.id === edge.id)) return;
    edges.push(edge);
    updateNodeCount();
  }

  /**
   * Highlight a specific node by ID.
   * @param {string} nodeId
   */
  function highlightNode(nodeId) {
    selectedNodeId = selectedNodeId === nodeId ? null : nodeId;
    updateSelectedLabel(selectedNodeId);
  }

  /**
   * Merge new data into the existing graph, adding/updating as needed.
   * @param {{ nodes: object[], edges: object[] }} data
   */
  function updateGraph(data) {
    if (!data) return;

    if (nodes.length === 0) {
      renderGraph(data);
      return;
    }

    // Update existing nodes, add new ones
    (data.nodes || []).forEach(n => {
      const existing = nodeMap.get(n.id);
      if (existing) {
        // Merge properties without resetting physics position
        Object.assign(existing, { ...n, x: existing.x, y: existing.y, vx: existing.vx, vy: existing.vy });
      } else {
        addNode(n);
      }
    });

    // Replace edges (they are cheap to rebuild)
    edges = (data.edges || []);
    updateNodeCount();
  }

  return { init, renderGraph, addNode, addEdge, highlightNode, updateGraph };

})();

// Expose globally for cross-module access
window.GraphView = GraphView;
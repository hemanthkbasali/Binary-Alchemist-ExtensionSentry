/**
 * ExtensionSentry — Premium SOC Dashboard JS
 * Live telemetry, animated meters, rotating terminals, pulse counters
 */
(function () {
  'use strict';

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  /* ── Utilities ──────────────────────────────────────────── */
  function all(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  function easeOut(t) { return 1 - Math.pow(1 - t, 3); }
  function now() { return performance.now(); }

  function liveTime() {
    var d = new Date();
    return d.toTimeString().slice(0, 8);
  }

  /* ── Nav active state ───────────────────────────────────── */
  function syncNav() {
    var path = window.location.pathname;
    all('.rail-links a').forEach(function (link) {
      var href = link.getAttribute('href') || '';
      var active = href === path ||
        (href === '/dashboard/' && path.indexOf('/results/') === 0) ||
        (href !== '/' && path.startsWith(href) && href.length > 1);
      link.classList.toggle('is-active', active);
    });
  }

  /* ── Marquee duplication ────────────────────────────────── */
  function initMarquees() {
    all('[data-marquee]').forEach(function (track) {
      if (track.dataset.ready === '1') return;
      track.dataset.ready = '1';
      track.innerHTML += track.innerHTML;
    });
  }

  /* ── Reveal on scroll ───────────────────────────────────── */
  function initReveal() {
    var nodes = all('[data-reveal]');
    if (!nodes.length) return;
    if (reduceMotion || !('IntersectionObserver' in window)) {
      nodes.forEach(function (n) { n.classList.add('is-visible'); });
      return;
    }
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting) { e.target.classList.add('is-visible'); obs.unobserve(e.target); }
      });
    }, { threshold: 0.1 });
    nodes.forEach(function (n) { obs.observe(n); });
  }

  /* ── Animated counters ──────────────────────────────────── */
  function animateCounters() {
    var counters = all('[data-counter]');
    if (!counters.length) return;
    function run(node) {
      if (node.dataset.done === '1') return;
      node.dataset.done = '1';
      var target = parseInt(node.getAttribute('data-counter') || '0', 10);
      if (reduceMotion) { node.textContent = target.toLocaleString(); return; }
      var start = now();
      var duration = 1400;
      (function frame(ts) {
        var p = Math.min(1, (ts - start) / duration);
        node.textContent = Math.round(target * easeOut(p)).toLocaleString();
        if (p < 1) requestAnimationFrame(frame);
      })(start);
    }
    if (reduceMotion || !('IntersectionObserver' in window)) {
      counters.forEach(run); return;
    }
    var obs = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { run(e.target); obs.unobserve(e.target); } });
    }, { threshold: 0.3 });
    counters.forEach(function (n) { obs.observe(n); });
  }

  /* ── Progress bar fill ──────────────────────────────────── */
  function animateProgress() {
    all('[data-progress-fill]').forEach(function (bar) {
      var value = parseInt(bar.getAttribute('data-progress-value') || '0', 10);
      bar.style.width = clamp(value, 0, 100) + '%';
    });
  }

  /* ── Circular ring meters ───────────────────────────────── */
  function animateRings() {
    all('[data-score-ring]').forEach(function (ring) {
      var target = clamp(parseInt(ring.getAttribute('data-score-value') || '0', 10), 0, 100);
      // Color class based on value
      var colorClass = target >= 70 ? 'red-gauge' : (target >= 40 ? 'orange-gauge' : 'green-gauge');
      var inner = ring.querySelector('.mini-gauge-inner');
      if (inner) { inner.classList.add(colorClass); }

      if (reduceMotion) { ring.style.setProperty('--score', target); return; }
      var current = 0;
      var timer = setInterval(function () {
        current += Math.ceil((target - current) * 0.15) || 1;
        if (current >= target) { current = target; clearInterval(timer); }
        ring.style.setProperty('--score', current);
        if (inner) inner.style.setProperty('--score', current);
      }, 22);
    });
  }

  /* ── Typed terminal with live rotation ──────────────────── */
  var TERMINAL_POOLS = {
    landing: [
      '> archive uploaded: extension.zip  6.2 MB',
      '> intake verification: OK',
      '> sha256 fingerprinting: active',
      '> manifest.json detected  v3',
      '> permissions indexed: 14 entries',
      '> 25 files discovered  JS: 3',
      '> suspicious API detected: chrome.runtime.sendMessage',
      '> external domain match: tracker detected',
      '> behavior pattern eval() usage found',
      '> IOC extracted: indicators found',
      '> risk score calculated: HIGH',
      '> report generation: started',
      '> PDF synthesis: complete',
      '> scan completed successfully'
    ],
    console: [
      '> intake lane: online  ARMED',
      '> csrf gate: locked  VALID',
      '> results route: bound',
      '> archive validator: ready',
      '> manifest parser: standby',
      '> js engine: armed',
      '> ioc extractor: standby',
      '> pdf synthesizer: ready',
      '> queue position: next',
      '> environment: healthy'
    ],
    processing: [
      '> archive staged: awaiting unpack',
      '> file extraction: running',
      '> manifest.json parsed: OK',
      '> permission sweep: active',
      '> js behavior map: running',
      '> ioc extraction: in progress',
      '> domain analysis: running',
      '> risk convergence: computing',
      '> score synthesis: complete',
      '> pdf packet: building'
    ],
    lab: [
      '> diagnostics engine: nominal',
      '> rule bus scan: active',
      '> queue flush: 0 pending',
      '> threat feed sync: OK',
      '> yara engine: 342 rules loaded',
      '> sandbox container: initialized',
      '> network analysis: complete',
      '> permission matrix: updated',
      '> history_total: computed',
      '> avg_global_score: aggregated'
    ],
    login: [
      '> auth gate validation: active',
      '> csrf session lock: secured',
      '> cockpit shell: ready',
      '> route protection: enabled',
      '> token validation: standby',
      '> identity check: awaiting'
    ]
  };

  function initTerminals() {
    all('[data-terminal]').forEach(function (term) {
      var key = term.getAttribute('data-terminal');
      var pool = TERMINAL_POOLS[key] || TERMINAL_POOLS.landing;
      var containerLines = all('p', term);

      // Seed initial content from existing DOM lines scraped, or fallback
      var backendLines = containerLines.map(function (p) { return p.textContent.trim(); }).filter(Boolean);
      var combined = backendLines.concat(pool);
      var maxVisible = 8;

      // Clear and render
      function render(lines) {
        term.innerHTML = '';
        var slice = lines.slice(-maxVisible);
        slice.forEach(function (txt, idx) {
          var p = document.createElement('p');
          var colorClass = '';
          var lower = txt.toLowerCase();
          if (lower.indexOf('error') > -1 || lower.indexOf('fail') > -1 || lower.indexOf('critical') > -1 || lower.indexOf('alert') > -1) colorClass = 'alert';
          else if (lower.indexOf('warn') > -1 || lower.indexOf('suspicious') > -1 || lower.indexOf('risk') > -1) colorClass = 'warn';
          else if (lower.indexOf('info') > -1 || lower.indexOf('ok') > -1 || lower.indexOf('complete') > -1) colorClass = 'info';
          if (colorClass) p.classList.add(colorClass);
          p.textContent = txt;
          term.appendChild(p);
        });
      }

      // Seed with initial lines
      var current = combined.slice(0, maxVisible);
      render(current);

      if (reduceMotion) return;

      // Rotate every 3.5 seconds
      var nextFrom = 0;
      function rotate() {
        nextFrom = (nextFrom + 1) % combined.length;
        var newLine = combined[nextFrom];
        // Add timestamp prefix if not already
        if (newLine.indexOf(':') < 3) {
          newLine = '> ' + liveTime() + ' ' + newLine.replace(/^>\s*/, '');
        }
        current = current.concat(newLine).slice(-maxVisible);
        render(current);
      }
      setInterval(rotate, 3500);
    });
  }

  /* ── Live timestamp display ─────────────────────────────── */
  function initLiveTimestamp() {
    all('[data-live-time]').forEach(function (el) {
      function tick() { el.textContent = liveTime(); }
      tick();
      setInterval(tick, 1000);
    });
  }

  /* ── Upload preview ─────────────────────────────────────── */
  function formatBytes(size) {
    if (!size) return '0 KB';
    var units = ['B', 'KB', 'MB', 'GB'];
    var u = Math.min(units.length - 1, Math.floor(Math.log(size) / Math.log(1024)));
    var v = size / Math.pow(1024, u);
    return (u === 0 ? Math.round(v) : v.toFixed(v > 10 ? 0 : 1)) + ' ' + units[u];
  }

  function initUploadPreview() {
    var input = document.querySelector('[data-drop-zone] input[type="file"]');
    if (!input) return;
    var nameNode = document.querySelector('[data-file-name]');
    var sizeNode = document.querySelector('[data-file-size]');
    var typeNode = document.querySelector('[data-file-type]');
    var extNode = document.querySelector('[data-file-ext]');
    var stateNode = document.querySelector('[data-file-state]');
    var manifestNode = document.querySelector('[data-file-manifest]');
    var jsCountNode = document.querySelector('[data-file-js-count]');
    var permCountNode = document.querySelector('[data-file-perm-count]');
    var queuePosNode = document.querySelector('[data-file-queue-pos]');
    var readyNode = document.querySelector('[data-ready-item]');
    var stateChip = document.querySelector('[data-scan-state-chip]');
    var readyText = document.querySelector('[data-ready-file-text]');
    var stateText = document.querySelector('[data-scan-state-text]');
    var fileGauges = all('[data-gauge-source="file"]');

    function setFile(file) {
      var has = !!file;
      if (!has) {
        if (nameNode) nameNode.textContent = 'WAITING';
        if (sizeNode) sizeNode.textContent = '0 KB';
        if (typeNode) typeNode.textContent = 'PENDING';
        if (extNode) extNode.textContent = '---';
        if (stateNode) stateNode.textContent = 'STANDBY';
        if (manifestNode) manifestNode.textContent = 'UNKNOWN';
        if (jsCountNode) jsCountNode.textContent = '--';
        if (permCountNode) permCountNode.textContent = '--';
        if (readyNode) { readyNode.classList.remove('is-ready'); if (readyText) readyText.textContent = 'INTAKE FILE: NULL'; }
        if (stateChip && stateText) stateText.textContent = 'SCORING CORE: STANDBY';
      } else {
        var ext = file.name.includes('.') ? file.name.split('.').pop().toUpperCase() : '---';
        var estJs = clamp(Math.round(file.size / (64 * 1024)), 1, 99);
        var estPerms = clamp(Math.round(file.size / (512 * 1024)), 1, 24);
        var mfHint = /(zip|crx)$/i.test(file.name) ? 'LIKELY' : 'UNKNOWN';
        if (nameNode) nameNode.textContent = file.name;
        if (sizeNode) sizeNode.textContent = formatBytes(file.size);
        if (typeNode) typeNode.textContent = file.type ? file.type.replace('application/', '').toUpperCase() : 'ARCHIVE';
        if (extNode) extNode.textContent = ext;
        if (stateNode) stateNode.textContent = 'ARMED';
        if (manifestNode) manifestNode.textContent = mfHint;
        if (jsCountNode) jsCountNode.textContent = estJs;
        if (permCountNode) permCountNode.textContent = estPerms;
        if (readyNode) { readyNode.classList.add('is-ready'); if (readyText) readyText.textContent = 'INTAKE FILE: LOCKED'; }
        if (stateChip && stateText) stateText.textContent = 'SCORING CORE: ARMED';
      }
      fileGauges.forEach(function (g) {
        var v = has ? parseInt(g.getAttribute('data-gauge-filled') || '96', 10) : parseInt(g.getAttribute('data-gauge-empty') || '18', 10);
        g.setAttribute('data-score-value', String(v));
        g.style.setProperty('--score', clamp(v, 0, 100));
        var lbl = g.querySelector('[data-gauge-label]');
        if (lbl) lbl.textContent = String(v);
      });
    }

    setFile(input.files && input.files[0] ? input.files[0] : null);
    input.addEventListener('change', function () { setFile(input.files && input.files[0] ? input.files[0] : null); });
  }

  /* ── Queue metrics ──────────────────────────────────────── */
  function initQueueMetrics() {
    var links = all('[data-scan-risk]');
    var count = links.length;
    var sum = links.reduce(function (a, n) { return a + parseInt(n.getAttribute('data-scan-risk') || '0', 10); }, 0);
    var avg = count ? Math.round(sum / count) : 0;
    all('[data-queue-count], [data-queue-count-strong]').forEach(function (n) { n.textContent = String(count); });
    all('[data-queue-avg]').forEach(function (n) { n.textContent = (count ? avg : 0) + '/100'; });
    all('[data-prelim-risk]').forEach(function (n) { n.textContent = (count ? avg : 0) + '/100'; });
    all('[data-gauge-source="queue"]').forEach(function (g) {
      var base = parseInt(g.getAttribute('data-gauge-base') || '66', 10);
      var target = count ? clamp(base + Math.round(avg * 0.3), 0, 100) : 22;
      g.setAttribute('data-score-value', String(target));
      g.style.setProperty('--score', target);
      var lbl = g.querySelector('[data-gauge-queue]');
      if (lbl) lbl.textContent = String(target);
    });
  }

  /* ── Drop zone UX ───────────────────────────────────────── */
  function wireDropZone() {
    var wrapper = document.querySelector('[data-drop-zone]');
    if (!wrapper) return;
    var zone = wrapper.querySelector('.drop-zone');
    if (!zone) return;
    ['dragover', 'dragenter'].forEach(function (ev) {
      wrapper.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.add('is-dragging'); });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      wrapper.addEventListener(ev, function (e) { e.preventDefault(); zone.classList.remove('is-dragging'); });
    });
  }

  /* ── Processing page animation ──────────────────────────── */
  function runProcessing() {
    var shell = document.querySelector('[data-processing]');
    if (!shell) return;
    var bar = shell.querySelector('[data-progress-bar]');
    var label = shell.querySelector('[data-progress-label]');
    var status = shell.querySelector('[data-processing-status]');
    var steps = all('[data-stage]', shell);
    var nextUrl = shell.getAttribute('data-next-url');
    var target = parseInt(shell.getAttribute('data-processing-target') || '100', 10);
    var msgs = [
      'ARCHIVE: UNPACKING', 'MANIFEST LANE: PARSING',
      'PERMISSIONS: INDEXING', 'JS ENGINE: MAPPING',
      'IOC TRACK: EXTRACTING', 'SCORING CORE: COMPUTING', 'PDF SYNTHESIS: SEALING'
    ];
    var value = 0; var tick = 0;
    var timer = setInterval(function () {
      tick += 1;
      value = Math.min(target, Math.round((tick / 20) * target));
      if (bar) bar.style.width = value + '%';
      if (label) label.textContent = value + '%';
      var idx = Math.min(steps.length - 1, Math.floor(value / (Math.max(target, 1) / Math.max(steps.length, 1))));
      steps.forEach(function (s, i) {
        s.classList.toggle('is-complete', i < idx);
        s.classList.toggle('is-active', i === idx && value < 100);
      });
      if (status) status.textContent = msgs[Math.min(msgs.length - 1, idx)];
      if (value >= target) { clearInterval(timer); setTimeout(function () { window.location.href = nextUrl; }, 700); }
    }, reduceMotion ? 50 : 150);
  }

  /* ── Results scan score coloring ────────────────────────── */
  function colorRiskScore() {
    var risk = parseInt((document.querySelector('.risk-core') || {}).getAttribute && document.querySelector('.risk-core').getAttribute('data-score-value') || '0', 10);
    var core = document.querySelector('.risk-core');
    if (!core) return;
    if (risk >= 70) {
      core.style.setProperty('--gauge-color', '#ff5468');
    } else if (risk >= 40) {
      core.style.setProperty('--gauge-color', '#ffb347');
    } else {
      core.style.setProperty('--gauge-color', '#00ff85');
    }
  }

  /* ── Pulse live indicators ──────────────────────────────── */
  function animatePulseRows() {
    var rows = all('.mini-list a');
    if (!rows.length || reduceMotion) return;
    rows.forEach(function (a, i) {
      var risk = parseInt(a.getAttribute('data-scan-risk') || '0', 10);
      var score = a.querySelector('.list-score');
      if (!score) return;
      if (risk >= 70) score.style.color = 'var(--red)';
      else if (risk >= 40) score.style.color = 'var(--orange)';
      else score.style.color = 'var(--green)';
    });
    all('.lab-case-row').forEach(function (row) {
      var scoreEl = row.querySelector('.list-score');
      if (!scoreEl) return;
      var val = parseInt(scoreEl.textContent || '0', 10);
      if (val >= 70) scoreEl.style.color = 'var(--red)';
      else if (val >= 40) scoreEl.style.color = 'var(--orange)';
      else scoreEl.style.color = 'var(--green)';
    });
  }

  /* ── Pipeline bar color by lane ─────────────────────────── */
  function colorPipelineBars() {
    all('.severity-row').forEach(function (row) {
      var pill = row.querySelector('.severity-pill');
      var bar = row.querySelector('[data-progress-fill]');
      if (!pill || !bar) return;
      var cls = pill.className || '';
      if (cls.indexOf('critical') > -1) bar.style.background = 'linear-gradient(90deg, var(--red), rgba(255,84,104,0.6))';
      else if (cls.indexOf('high') > -1) bar.style.background = 'linear-gradient(90deg, var(--orange), rgba(255,179,71,0.6))';
      else if (cls.indexOf('medium') > -1) bar.style.background = 'linear-gradient(90deg, var(--cyan), rgba(0,229,255,0.6))';
      else if (cls.indexOf('low') > -1) bar.style.background = 'linear-gradient(90deg, var(--green), rgba(0,255,133,0.6))';
    });
  }

  /* ── Last updated stamp ─────────────────────────────────── */
  function stampLastUpdated() {
    all('[data-last-updated]').forEach(function (el) {
      el.textContent = 'Last Updated: ' + new Date().toLocaleString();
    });
  }

  /* ── Gauge value color extraction from value ────────────── */
  function colorMiniGauges() {
    all('[data-score-ring]').forEach(function (ring) {
      var val = parseInt(ring.getAttribute('data-score-value') || '0', 10);
      var color = val >= 70 ? 'var(--red)' : val >= 40 ? 'var(--orange)' : 'var(--cyan)';
      var bg_stop = val >= 70 ? 'rgba(255,84,104,0.08)' : val >= 40 ? 'rgba(255,179,71,0.08)' : 'rgba(0,229,255,0.08)';
      ring.style.background = [
        'radial-gradient(circle at center, rgba(2, 8, 18, 0.98) 0 58%, transparent 59%)',
        'conic-gradient(' + color + ' calc(var(--score, 0) * 1%), ' + bg_stop + ' 0)'
      ].join(', ');
      var span = ring.querySelector('span:first-child, > span');
      if (span && !span.getAttribute('data-gauge-label') && !span.getAttribute('data-gauge-queue')) {
        span.style.color = color;
      }
    });
  }

  /* ── INIT ───────────────────────────────────────────────── */
  document.body.classList.add('ui-live');
  initMarquees();
  initReveal();
  animateCounters();
  animateProgress();
  animateRings();
  colorMiniGauges();
  initTerminals();
  initLiveTimestamp();
  initUploadPreview();
  initQueueMetrics();
  wireDropZone();
  syncNav();
  runProcessing();
  colorRiskScore();
  animatePulseRows();
  colorPipelineBars();
  stampLastUpdated();

})();

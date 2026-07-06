// ── Sensors view ─────────────────────────────────────────────────────
// Site palette: chart-1 #7fe7ff, chart-2 #4ade80, chart-3 #fbbf24, chart-4 #fb7185, chart-5 #60a5fa
const SENSOR_COLORS = {
  ebpf: '#7fe7ff', auditd: '#fb7185', auth_log: '#fbbf24', journald: '#4ade80',
  docker: '#60a5fa', nginx: '#f97316', syslog: '#8b9db8', integrity: '#84cc16', cloudtrail: '#3b82f6',
  fanotify: '#fb7185', syslog_firewall: '#8b9db8', firmware_integrity: '#84cc16',
  macos_log: '#a78bfa',  };
function sensorColor(name) { return SENSOR_COLORS[name] || '#78e5ff'; }

// Mirror of `crates/sensor/src/collector_health.rs::COLLECTOR_MANIFEST`.
// Frontend needs to know which collectors are alarm-style (low count
// = healthy, silence is good) vs telemetry-style (low count = broken).
// Cross-file anchor in `crates/agent/src/dashboard/mod.rs` asserts
// every Rust manifest entry has a JS entry — drift fails CI.
const COLLECTOR_CATEGORY = {
  // Wave 2026-05-18: keys MUST match the wire `source` names emitted
  // by collectors AND the Rust COLLECTOR_MANIFEST entries. Drift here
  // means the dashboard either renders phantom rows or mis-categorises
  // real ones as TELEMETRY 0 (looks broken when it's just silence).
  // The Rust-side `every_js_collector_appears_in_manifest` test fails
  // CI if these two maps drift. Three fixes baked in:
  //
  //   * `osquery_log` and `suricata_eve` removed — those collectors
  //     never shipped, the keys were vestiges from a design that was
  //     abandoned before Wave 8b/8c.
  //   * `ebpf_syscall` and `exec_audit` removed — duplicates that
  //     never matched a real `source` name (`ebpf` and `auditd` cover
  //     their real wire output).
  //   * `fanotify_watch` renamed to `fanotify` — matches the actual
  //     source name written by `crates/sensor/src/collectors/fanotify_watch.rs:163`.
  //
  // Telemetry: always-on, high-volume feeds. Low count → broken.
  auth_log: 'telemetry',
  auditd: 'telemetry',
  cgroup: 'telemetry',
  cloudtrail: 'telemetry',
  dns_capture: 'telemetry',
  ebpf: 'telemetry',
  etw: 'telemetry',
  file_extract: 'telemetry',
  http_capture: 'telemetry',
  journald: 'telemetry',
  kernel_integrity: 'telemetry',
  macos_log: 'telemetry',
  net_snapshot: 'telemetry',
  nginx_access: 'telemetry',
  nginx_error: 'telemetry',
  proc_maps: 'telemetry',
  proto_http: 'telemetry',
  proto_smb: 'telemetry',
  proto_ssh: 'telemetry',
  syslog_firewall: 'telemetry',
  tcp_stream: 'telemetry',
  // Alarm: event-driven detectors. Silence is healthy.
  docker: 'alarm',
  fanotify: 'alarm',
  firmware_integrity: 'alarm',
  integrity: 'alarm',
  sysctl_drift: 'alarm',
  tls_fingerprint: 'alarm',
  usb_monitor: 'alarm',
  // Snapshot: periodic point-in-time inventory.
  suid_inventory: 'snapshot',
  systemd_inventory: 'snapshot',
};

function collectorCategory(name) {
  // Unknown collectors default to 'telemetry' — same fallback as the
  // Rust `category_for()` function. Better to mis-classify as
  // "broken if low" than to silently hide an unknown collector.
  return COLLECTOR_CATEGORY[name] || 'telemetry';
}

function categoryBadge(cat) {
  // Tiny pill that tells the operator at a glance whether a low
  // count is concerning. Hover tooltip explains.
  if (cat === 'alarm') {
    return '<span class="cat-badge cat-alarm" title="Event-driven detector — silence means the system is healthy. Only emits when something interesting happens (malicious TLS handshake, file drift, etc).">ALARM</span>';
  }
  if (cat === 'snapshot') {
    return '<span class="cat-badge cat-snapshot" title="Periodic snapshot collector — count reflects scheduled cycles, not detected items.">SNAPSHOT</span>';
  }
  return '<span class="cat-badge cat-telemetry" title="Always-on telemetry stream — low count signals the collector or its source is broken.">TELEMETRY</span>';
}

// PR29 — index `data.collector_health.statuses` by name for O(1)
// lookup. Returns `{}` (empty map) when the sensor didn't write a
// health file (old sensor binary or non-default deploy).
function indexHealth(healthBlock) {
  const map = {};
  const statuses = (healthBlock && healthBlock.statuses) || [];
  for (const s of statuses) {
    if (s && s.name) map[s.name] = s;
  }
  return map;
}

function healthBadge(status) {
  // PR29 — health pill rendered next to the category badge. Only
  // emits when the sensor reported a non-Active state for this
  // collector. The pill carries the operator-readable reason as a
  // tooltip so they know what to investigate.
  if (!status || !status.health) return '';
  const h = status.health;
  const state = h.state || 'active';
  if (state === 'active') return '';
  let label = state.toUpperCase();
  let cls = 'cat-badge health-warn';
  let title = '';
  if (state === 'source_unavailable') {
    label = 'SOURCE MISSING';
    title = 'Source file does not exist on this host: ' + (h.path || '?') +
            '. Install the upstream service or remove this collector from config.';
  } else if (state === 'source_empty') {
    label = 'SOURCE STALE';
    title = 'Source file exists but has not been written to since ' +
            (h.last_write_iso || 'unknown') + '. Verify the upstream service.';
  } else if (state === 'permission_denied') {
    label = 'NO PERMISSION';
    title = 'Sensor lacks OS-level capability to read this source. Check AmbientCapabilities.';
  } else if (state === 'unsupported') {
    label = 'UNSUPPORTED';
    title = 'Not supported on this host: ' + (h.reason || 'unknown');
  } else if (state === 'disabled') {
    label = 'DISABLED';
    cls = 'cat-badge cat-snapshot';
    title = 'Disabled in config — operator choice.';
  }
  return '<span class="' + cls + '" title="' + title.replace(/"/g, '&quot;') + '">' + label + '</span>';
}

// 2026-05-15 Sensors fold: the standalone Sensors page was deleted —
// its content (per-collector telemetry/alarm/snapshot breakdown + Event
// Timeline) now lives on Home below the AI Intelligence Briefing.
// `renderSensorSourceRows` is the shared helper Home calls. It expects
// the `/api/sensors` payload and a target DOM id for the rows container.
function renderSensorSourceRows(srcElId, data) {
  const srcEl = document.getElementById(srcElId);
  if (!srcEl) return;
  {
      // 2026-05-14 refactor: split source list by CATEGORY, not by
      // count. A `tls_fingerprint` collector with count=0 was being
      // rendered under "ready — not collecting" alongside genuinely
      // broken collectors, when it's actually an alarm-style detector
      // whose silence means the system is healthy. The category
      // mapping mirrors `crates/sensor/src/collector_health.rs`.
      const allSources = data.sources || [];
      const totalAll = allSources.length;
      // PR29 — index per-collector health from the sensor's
      // side-channel JSON (data.collector_health written by the
      // sensor at boot). Used by renderSourceRow to add a health
      // pill when source_unavailable / source_empty / etc.
      const healthByName = indexHealth(data.collector_health);

      // Telemetry with count > 0 = active; telemetry with count = 0
      // is the operator-actionable case (broken / source missing).
      const telActive = allSources.filter(
        (s) => collectorCategory(s.name) === 'telemetry' && s.count > 0,
      );
      const telBroken = allSources.filter(
        (s) => collectorCategory(s.name) === 'telemetry' && s.count === 0,
      );
      // Alarm collectors with count = 0 are HEALTHY (no detection
      // events). With count > 0 they're surfacing real findings.
      const alarmWithFindings = allSources.filter(
        (s) => collectorCategory(s.name) === 'alarm' && s.count > 0,
      );
      const alarmQuiet = allSources.filter(
        (s) => collectorCategory(s.name) === 'alarm' && s.count === 0,
      );
      const snapshots = allSources.filter(
        (s) => collectorCategory(s.name) === 'snapshot',
      );

      const renderSourceRow = (s, color) => {
        return (
          '<div class="hud-source">' +
          '<div class="hud-source-dot" style="background:' +
          color +
          ';box-shadow:0 0 6px ' +
          color +
          ';"></div>' +
          '<span class="hud-source-name">' +
          s.name +
          '</span>' +
          categoryBadge(collectorCategory(s.name)) +
          healthBadge(healthByName[s.name]) +
          '<span class="hud-source-count" style="color:' +
          color +
          ';">' +
          s.count.toLocaleString() +
          '</span></div>'
        );
      };

      let shtml = '<div style="font-size:0.72rem;font-weight:700;color:var(--ok);letter-spacing:0.05em;margin-bottom:6px">' +
        'TELEMETRY STREAMS &mdash; ' +
        telActive.length +
        '/' +
        (telActive.length + telBroken.length) +
        ' active</div>';
      shtml += '<div style="display:flex;flex-wrap:wrap;gap:6px">';
      for (const s of telActive) {
        shtml += renderSourceRow(s, sensorColor(s.name));
      }
      shtml += '</div>';
      if (telBroken.length > 0) {
        // Operator-actionable: telemetry with zero count IS broken.
        // Surface prominently so they investigate.
        shtml +=
          '<div style="font-size:0.65rem;color:var(--danger);margin-top:8px;font-weight:700">' +
          '⚠ ' +
          telBroken.length +
          ' telemetry streams report zero today &mdash; investigate</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;opacity:0.7">';
        for (const s of telBroken) {
          shtml += renderSourceRow(s, 'var(--danger)');
        }
        shtml += '</div>';
      }

      if (alarmWithFindings.length > 0) {
        shtml +=
          '<div style="font-size:0.72rem;font-weight:700;color:var(--orange);letter-spacing:0.05em;margin-top:12px;margin-bottom:6px">' +
          'ALARM DETECTORS &mdash; ' +
          alarmWithFindings.length +
          ' with findings</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px">';
        for (const s of alarmWithFindings) {
          shtml += renderSourceRow(s, 'var(--orange)');
        }
        shtml += '</div>';
      }
      if (alarmQuiet.length > 0) {
        shtml +=
          '<div style="font-size:0.65rem;color:var(--muted);margin-top:8px;cursor:pointer" onclick="var el=document.getElementById(\'alarmQuiet\');el.style.display=el.style.display===\'none\'?\'flex\':\'none\'">' +
          alarmQuiet.length +
          ' alarms quiet &mdash; healthy (silence is good) &#9662;</div>' +
          '<div id="alarmQuiet" style="display:none;flex-wrap:wrap;gap:6px;margin-top:4px;opacity:0.5">';
        for (const s of alarmQuiet) {
          shtml += renderSourceRow(s, 'var(--muted)');
        }
        shtml += '</div>';
      }

      if (snapshots.length > 0) {
        shtml +=
          '<div style="font-size:0.65rem;color:var(--muted);margin-top:8px">' +
          'Snapshot collectors (periodic) &mdash; ' +
          snapshots.length +
          '</div>' +
          '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;opacity:0.7">';
        for (const s of snapshots) {
          shtml += renderSourceRow(s, 'var(--muted)');
        }
        shtml += '</div>';
      }

      srcEl.innerHTML = shtml;
    }
}

// 2026-05-15 Sensors fold: the standalone Sensors page (the entire
// `viewSensors` block, the `Sensors` nav button, `loadSensors`,
// `loadTopAction`, `drawThreatGauge`, `drawDetectorChart`) was deleted.
// What survives is reused on Home: `renderSensorSourceRows` for the
// per-collector breakdown and `drawTimelineChart` for the Event
// Timeline. home.js drives both via `renderHomeSensorsPanel`.

// Chart.js global config - match site design system
let timelineChart = null;
const CJ = typeof Chart !== 'undefined';
if (CJ) {
  Chart.defaults.color = '#8b9db8';
  Chart.defaults.borderColor = '#1a2943';
  Chart.defaults.font.family = "'JetBrains Mono', monospace";
  Chart.defaults.font.size = 11;
  Chart.defaults.animation.duration = 1200;
  Chart.defaults.animation.easing = 'easeOutQuart';
}

// Tooltip config reused across charts
const siteTooltip = {
  backgroundColor: 'rgba(9,17,33,0.95)',
  borderColor: 'rgba(127,231,255,0.25)',
  borderWidth: 1,
  titleFont: { family: "'Space Grotesk', sans-serif", weight: '600', size: 12 },
  bodyFont: { family: "'JetBrains Mono', monospace", size: 11 },
  padding: 12,
  cornerRadius: 12,
  boxPadding: 4,
};

// Create vertical gradient for area fills
function makeGradient(ctx, canvas, color, alpha1, alpha2) {
  const g = ctx.createLinearGradient(0, 0, 0, canvas.height);
  g.addColorStop(0, color.replace(')', ',' + alpha1 + ')').replace('rgb', 'rgba'));
  g.addColorStop(1, color.replace(')', ',' + alpha2 + ')').replace('rgb', 'rgba'));
  return g;
}

// ── 1. AREA CHART - Event Timeline (smooth curves + gradient fills) ──
// 2026-05-15: parameterised so Home can mount the timeline under its
// own canvas id (`homeSensorChart`). The standalone Sensors page is
// gone — see renderHomeSensorsPanel in home.js.
function drawTimelineChart(canvasId, timeline, sources) {
  const canvas = document.getElementById(canvasId);
  if (!canvas || !CJ) return;

  const buckets = Object.keys(timeline).sort();
  const sourceNames = sources.map(s => s.name);
  const ctx = canvas.getContext('2d');

  const datasets = sourceNames.map((name, i) => {
    const color = sensorColor(name);
    const hex2rgba = (h, a) => {
      const r = parseInt(h.slice(1,3),16), g = parseInt(h.slice(3,5),16), b = parseInt(h.slice(5,7),16);
      return 'rgba('+r+','+g+','+b+','+a+')';
    };
    return {
      label: name,
      data: buckets.map(b => (timeline[b] || {})[name] || 0),
      borderColor: color,
      backgroundColor: (context) => {
        const chart = context.chart;
        const {ctx: c, chartArea} = chart;
        if (!chartArea) return hex2rgba(color, 0.3);
        const g = c.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
        g.addColorStop(0, hex2rgba(color, 0.4));
        g.addColorStop(1, hex2rgba(color, 0.02));
        return g;
      },
      borderWidth: 2,
      fill: true,
      tension: 0.4,
      pointRadius: 0,
      pointHoverRadius: 5,
      pointHoverBackgroundColor: color,
      pointHoverBorderColor: '#edf6ff',
      pointHoverBorderWidth: 2,
    };
  });

  if (timelineChart) timelineChart.destroy();
  timelineChart = new Chart(canvas, {
    type: 'line',
    data: { labels: buckets, datasets },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          stacked: true,
          grid: { color: 'rgba(26,41,67,0.5)', lineWidth: 0.5 },
          ticks: { maxTicksLimit: 12, font: { size: 9 } },
        },
        y: {
          stacked: true,
          grid: { color: 'rgba(26,41,67,0.5)', lineWidth: 0.5 },
          beginAtZero: true,
          ticks: { font: { size: 10 } },
        }
      },
      plugins: {
        legend: {
          position: 'top',
          labels: { boxWidth: 8, boxHeight: 8, padding: 14, font: { size: 10, family: "'Space Grotesk', sans-serif" }, usePointStyle: true, pointStyle: 'circle' }
        },
        tooltip: { ...siteTooltip, mode: 'index' },
      },
      interaction: { mode: 'index', intersect: false },
    }
  });
}

// 2026-05-15: `drawThreatGauge` and `drawDetectorChart` were the
// Unresolved Cases gauge + Detector Activity radar from the old
// Sensors HUD. PR #629 had moved them to Home; this PR removes
// them entirely — neither rendering survived the final Sensors
// fold-into-Home redesign (operator: "acho que podemos deletar").

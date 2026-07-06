async function loadStatus() {
  const status = document.getElementById('statusViewStatus');
  const content = document.getElementById('statusContent');
  if (!status || !content) return;
  status.textContent = 'Loading…';
  content.innerHTML = '<div class="empty" style="padding:40px;text-align:center">Loading…</div>';
  try {
    const [s, col] = await Promise.all([
      loadJson('/api/status'),
      loadJson('/api/collectors').catch(() => ({ collectors: [] }))
    ]);
    status.textContent = 'Updated ' + new Date().toLocaleTimeString();
    content.innerHTML = renderStatus(s, col.collectors || [])
      // 2026-05-15: Enforcement section migrated here from the removed
      // Responses tab. Mount point gets populated lazily by
      // renderEnforcementHealthSection (defined in responses.js).
      + '<div id="enforcement-health-mount"></div>'
      // 2026-05-15 PR-C: Baseline section folded in from the Intel tab.
      // `renderBaselineHealthSection` (defined later in this file)
      // hydrates this mount with the three-level Baseline UX
      // (Hero / deviation cards / collapsed learned-baseline).
      + '<div id="baseline-health-mount"></div>';
    loadDeepSecurity();
    // Spec 024: populate the Metrics Drift section after the table
    // skeleton lands in the DOM.
    loadMetricsDrift();
    // 2026-05-15: enforcement stats + orphan diagnostics now live on
    // Health, not on a dedicated Responses tab. Lazy-mount under the
    // existing content so the rest of the Health page stays unchanged.
    if (typeof renderEnforcementHealthSection === 'function') {
      renderEnforcementHealthSection('enforcement-health-mount');
    }
    // 2026-05-15 PR-C: Baseline (anomaly/observability surface) lives
    // here on Health, not as an Intel sub-tab.
    if (typeof renderBaselineHealthSection === 'function') {
      renderBaselineHealthSection('baseline-health-mount');
    }
  } catch(e) {
    status.textContent = 'error';
    content.innerHTML = '<div class="empty" style="padding:40px;color:var(--danger)">Failed: ' + esc(String(e.message)) + '</div>';
  }
}

async function loadDeepSecurity() {
  try {
    const ds = await loadJson('/api/deep-security');
    const fw = document.querySelector('#ds-firmware .deep-value');
    const hv = document.querySelector('#ds-hypervisor .deep-value');
    const kc = document.querySelector('#ds-killchain .deep-value');
    const dn = document.querySelector('#ds-dna .deep-value');
    if (fw) {
      if (ds.firmware_trust_score != null) {
        const pct = (ds.firmware_trust_score*100).toFixed(0);
        fw.innerHTML = '<span style="color:' + (pct >= 85 ? 'var(--ok)' : pct >= 50 ? 'var(--warn)' : 'var(--danger)') + '">' + pct + '% trust</span>';
      } else { fw.innerHTML = '<span style="color:var(--ok)">Active</span>'; }
    }
    if (hv) {
      const env = String(ds.hypervisor_environment || 'Detecting…');
      const col = env.includes('BareMetal') ? 'var(--ok)' : env.includes('Virtual') ? 'var(--accent)' : 'var(--muted)';
      // Strip the structured TOML leak (`{ hypervisor: "Foo" }` style) and
      // escape whatever is left — the previous regex sanitiser only touched a
      // few punctuation chars, leaving `<img onerror=...>` payloads live if
      // they ever leaked into hypervisor detection output.
      const cleaned = env.replace(/[{}"]/g, '').replace(/hypervisor:\s*/gi, '').trim();
      hv.innerHTML = '<span style="color:' + col + '">' + esc(cleaned) + '</span>';
    }
    if (kc) {
      kc.innerHTML = '<span style="color:var(--text)">' + ds.killchain_pids_tracked + ' tracked</span>' +
        (ds.killchain_full_matches > 0 ? ' · <span style="color:var(--danger)">' + ds.killchain_full_matches + ' detected</span>' : '') +
        (ds.killchain_pre_chains > 0 ? ' · <span style="color:var(--warn)">' + ds.killchain_pre_chains + ' pre-chain</span>' : '');
    }
    if (dn) {
      dn.innerHTML = '<span style="color:var(--text)">' + ds.dna_fingerprints + ' fingerprints</span>' +
        (ds.dna_anomaly_alerts > 0 ? ' · <span style="color:var(--warn)">' + ds.dna_anomaly_alerts + ' anomalies</span>' : '') +
        ' · <span style="color:var(--muted)">' + ds.dna_attack_chains + ' chains</span>';
    }
  } catch(e) { console.warn('deep-security:', e); }
}

function renderStatus(s, collectors) {
  const files = s.files || {};
  const resp = s.responder || {};
  const integ = s.integrations || {};
  const fmt = (bytes) => bytes > 1048576 ? (bytes/1048576).toFixed(1)+'MB' : bytes > 1024 ? (bytes/1024).toFixed(1)+'KB' : bytes+'B';

  // Agent liveness
  const tSecs = s.last_telemetry_secs;
  let liveStr = '-';
  if (tSecs != null) {
    if (tSecs < 60)        liveStr = tSecs + 's ago';
    else if (tSecs < 3600) liveStr = Math.floor(tSecs/60) + 'm ago';
    else                   liveStr = Math.floor(tSecs/3600) + 'h ago';
  }
  const isHealthy = tSecs != null && tSecs < 300;

  // ── Section 1: Guard Mode card ─────────────────────────────────────────
  // GUARD = green (good, server protected), WATCH = yellow (caution, not acting), READ-ONLY = gray (passive)
  let guardIcon, guardLabel, guardDesc, guardColor, guardBorderColor, guardBg;
  if (s.mode === 'guard') {
    guardIcon = lucideIcon('shield-check', { size: 32 });
    guardLabel = 'PROTECTED';
    guardDesc = 'Active protection - AI is blocking threats with live firewall rules';
    guardColor = 'var(--ok)';
    guardBorderColor = 'rgba(58,194,126,0.5)';
    guardBg = 'rgba(58,194,126,0.06)';
  } else if (s.mode === 'watch') {
    guardIcon = lucideIcon('eye', { size: 32 });
    guardLabel = 'WATCHING';
    guardDesc = 'Dry-run - AI is analysing threats but actions need manual approval or config change';
    guardColor = 'var(--warn)';
    guardBorderColor = 'rgba(255,184,77,0.4)';
    guardBg = 'rgba(255,184,77,0.04)';
  } else {
    guardIcon = lucideIcon('book-open', { size: 32 });
    guardLabel = 'MONITOR ONLY';
    guardDesc = 'Responder disabled - events are logged and reported, no automated response';
    guardColor = 'var(--muted)';
    guardBorderColor = 'var(--line)';
    guardBg = 'transparent';
  }
  const aiBotIcon = lucideIcon('bot', { size: 12 });
  const aiLabel = s.ai_enabled ? aiBotIcon + ' ' + esc(s.ai_provider || '') + ' / ' + esc(s.ai_model || '') : '- off';

  let html = '<div class="report-section">' +
    '<div class="report-section-title">Protection Status</div>' +
    '<div style="background:' + guardBg + ';border:1px solid ' + guardBorderColor + ';border-radius:12px;padding:16px 20px;display:flex;align-items:center;gap:16px;margin-bottom:4px">' +
    '<div style="font-size:2rem;flex-shrink:0">' + guardIcon + '</div>' +
    '<div>' +
    '<div style="font-size:1.1rem;font-weight:800;color:' + guardColor + '">' + esc(guardLabel) + '</div>' +
    '<div style="font-size:0.75rem;color:var(--muted);margin-top:3px">' + esc(guardDesc) + '</div>' +
    '<div style="margin-top:8px;font-size:0.72rem;color:var(--muted)">AI: <span style="color:var(--' + (s.ai_enabled ? 'ok' : 'muted') + ')">' + aiLabel + '</span> &nbsp;·&nbsp; Agent: <span style="color:var(--' + (isHealthy ? 'ok' : 'warn') + ')">' + liveStr + '</span></div>' +
    '</div></div></div>';

  // ── Section 1b: Deep Security (integrated modules) ────────────────────
  html += '<div class="report-section" id="deepSecuritySection">' +
    '<div class="report-section-title">Deep Security Modules</div>' +
    '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px">' +
    '<div class="deep-card" id="ds-firmware"><div class="deep-icon">' + lucideIcon('wrench', { size: 22 }) + '</div><div class="deep-label">Firmware Layer</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '<div class="deep-card" id="ds-hypervisor"><div class="deep-icon">' + lucideIcon('monitor', { size: 22 }) + '</div><div class="deep-label">Hypervisor Layer</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '<div class="deep-card" id="ds-killchain"><div class="deep-icon">' + lucideIcon('link', { size: 22 }) + '</div><div class="deep-label">Kill Chain</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '<div class="deep-card" id="ds-dna"><div class="deep-icon">' + lucideIcon('dna', { size: 22 }) + '</div><div class="deep-label">Threat DNA</div><div class="deep-value" style="color:var(--muted)">Loading…</div></div>' +
    '</div></div>';

  // ── Section 2: Active Integrations grid ───────────────────────────────
  const card = (icon, name, on, desc, badgeLabel, kind, costNote, enableCmd) => {
    const badge = badgeLabel === 'ON'   ? '<span class="integ-badge on">ON</span>'   :
                  badgeLabel === 'OFF'  ? '<span class="integ-badge off">OFF</span>' :
                  badgeLabel === 'DEMO' ? '<span class="integ-badge demo">DEMO</span>' :
                  badgeLabel === 'LIVE' ? '<span class="integ-badge on">LIVE</span>' :
                                         '<span class="integ-badge off">OFF</span>';
    const kindBadge = kind === 'native'
      ? '<span class="integ-kind-native">NATIVE</span>'
      : '<span class="integ-kind-ext">EXTERNAL</span>';
    const cost = costNote ? '<div class="integ-cost">' + esc(costNote) + '</div>' : '';
    let toggleBtn = '';
    if (enableCmd) {
      const disableCmd = enableCmd.replace('enable', 'disable').replace('integrate ', 'integrate --disable ');
      const cmd = on ? disableCmd : enableCmd;
      const label = on ? '⏹ Disable' : '▶ Enable';
      const cls = on ? 'integ-toggle off' : 'integ-toggle on';
      toggleBtn = '<button class="' + cls + '" onclick="copyCmd(\'' + esc(cmd).replace(/\\/g, '\\\\').replace(/'/g, "\\'") + '\')" title="Copy command">' + label + '</button>';
    }
    return '<div class="integ-card ' + (on ? 'active' : 'inactive') + '">' +
      '<div class="integ-icon">' + icon + '</div>' +
      '<div class="integ-body">' +
      '<div class="integ-name">' + esc(name) + badge + kindBadge + '</div>' +
      '<div class="integ-desc">' + esc(desc) + '</div>' +
      cost +
      toggleBtn +
      '</div></div>';
  };

  const hpMode = (integ.honeypot_mode || 'off').toLowerCase();
  const hpBadge = hpMode === 'always_on' ? 'ON' : hpMode === 'listener' ? 'LIVE' : hpMode === 'demo' ? 'DEMO' : hpMode === 'off' ? 'OFF' : 'ON';

  // ── Section 2: Active Integrations — grouped by category ─────────────
  const groupStyle = '<style>' +
    '.integ-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-bottom:12px}' +
    '.integ-card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;display:flex;align-items:flex-start;gap:12px}' +
    '.integ-card.active{border-color:rgba(58,194,126,0.4)}' +
    '.integ-card.inactive{opacity:0.65}' +
    '.integ-icon{font-size:1.4rem;flex-shrink:0}' +
    '.integ-body{flex:1;min-width:0}' +
    '.integ-name{font-size:0.85rem;font-weight:700;color:var(--text);margin-bottom:2px}' +
    '.integ-desc{font-size:0.68rem;color:var(--muted);line-height:1.4}' +
    '.integ-cost{font-size:0.62rem;color:var(--muted);opacity:0.75;margin-top:3px;line-height:1.4}' +
    '.integ-hint{font-size:0.62rem;color:var(--accent);margin-top:5px}' +
    '.integ-toggle{display:inline-block;margin-top:6px;padding:4px 12px;border:1px solid var(--line);border-radius:8px;font-size:0.65rem;font-weight:600;cursor:pointer;background:transparent;transition:all 0.2s}' +
    '.integ-toggle.on{color:var(--ok);border-color:var(--ok)}' +
    '.integ-toggle.on:hover{background:rgba(74,222,128,0.1)}' +
    '.integ-toggle.off{color:var(--muted);border-color:var(--line)}' +
    '.integ-toggle.off:hover{background:rgba(139,157,184,0.1)}' +
    '.integ-hint code{font-family:\'JetBrains Mono\',monospace}' +
    '.integ-badge{display:inline-block;font-size:0.6rem;font-weight:700;padding:2px 7px;border-radius:20px;margin-left:6px;vertical-align:middle}' +
    '.integ-badge.on{background:rgba(58,194,126,0.2);color:var(--ok)}' +
    '.integ-badge.off{background:rgba(139,157,184,0.1);color:var(--muted)}' +
    '.integ-badge.demo{background:rgba(255,184,77,0.15);color:var(--warn)}' +
    '.integ-kind-native{display:inline-block;font-size:0.52rem;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:5px;vertical-align:middle;background:rgba(120,229,255,0.12);color:var(--accent);letter-spacing:0.04em}' +
    '.integ-kind-ext{display:inline-block;font-size:0.52rem;font-weight:700;padding:1px 5px;border-radius:4px;margin-left:5px;vertical-align:middle;background:rgba(255,184,77,0.12);color:var(--warn);letter-spacing:0.04em}' +
    '.integ-group{margin-bottom:18px}' +
    '.integ-group-header{display:flex;align-items:center;justify-content:space-between;cursor:pointer;padding:8px 0;user-select:none}' +
    '.integ-group-title{font-size:0.72rem;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:var(--accent)}' +
    '.integ-group-count{font-size:0.65rem;color:var(--muted)}' +
    '.integ-group-chevron{font-size:0.8rem;color:var(--muted);transition:transform 0.2s}' +
    '.integ-group-chevron.collapsed{transform:rotate(-90deg)}' +
    '.integ-group-body{overflow:hidden;transition:max-height 0.3s ease}' +
    '.integ-group-body.collapsed{max-height:0 !important;margin:0;padding:0}' +
    '@media(max-width:640px){.integ-grid{grid-template-columns:1fr}}' +
    '</style>';

  // Group builder: title, cards array, initially expanded?
  const group = (title, cards, expanded) => {
    const onCount = cards.filter(c => c.includes('integ-card active')).length;
    const total = cards.length;
    const id = 'ig-' + title.replace(/[^a-z]/gi, '').toLowerCase();
    const chevCls = expanded ? '' : ' collapsed';
    const bodyCls = expanded ? '' : ' collapsed';
    return '<div class="integ-group">' +
      '<div class="integ-group-header" onclick="(function(){ var b=document.getElementById(\'' + id + '\'); var c=b.previousElementSibling.querySelector(\'.integ-group-chevron\'); b.classList.toggle(\'collapsed\'); c.classList.toggle(\'collapsed\'); })()">' +
      '<span class="integ-group-title">' + title + '</span>' +
      '<span style="display:flex;align-items:center;gap:8px">' +
      '<span class="integ-group-count">' + onCount + '/' + total + ' active</span>' +
      '<span class="integ-group-chevron' + chevCls + '">&#9662;</span>' +
      '</span></div>' +
      '<div class="integ-group-body' + bodyCls + '" id="' + id + '" style="max-height:2000px">' +
      '<div class="integ-grid">' + cards.join('') + '</div></div></div>';
  };

  // ── Build Kill Chain card (needs runtime data) ──
  const kcCard = (function() {
    // 2026-05-15: kill chain is integrated inline in every agent build
    // (crates/killchain/ migration, see CLAUDE.md). The `kill_chain`
    // block being present on /api/status is the ground truth that it
    // is loaded — the legacy `pids_tracked !== undefined` check tested
    // a field that was never emitted, so the card always read OFF
    // even on hosts with active chain detection.
    const kc = s.kill_chain || {};
    const kcOn = s.kill_chain !== undefined && s.kill_chain !== null;
    const kcTotal = (kc.total_blocked || 0) + (kc.total_pre_chain || 0);
    const kcDesc = kcTotal > 0
      ? kcTotal + ' chain(s) detected today — ' + (kc.total_blocked||0) + ' blocked, ' + (kc.total_pre_chain||0) + ' pre-chain'
      : 'Multi-step attack correlation — detects reverse shells, privilege escalation chains';
    const kcPatterns = kc.patterns || {};
    const patternList = Object.keys(kcPatterns).map(function(p) { return p + ': ' + kcPatterns[p]; }).join(', ');
    const kcCost = 'Native syscall correlation. Patterns: ' + (patternList || 'none detected yet');
    return card(lucideIcon('link'), 'Kill Chain', kcOn, kcDesc, kcOn ? 'ON' : 'OFF', 'native', kcCost, '');
  })();

  // 2026-05-15: XDP Firewall detection — pre-fix the card keyed off a
  // status field that the agent never populated, so the indicator
  // always rendered OFF even on hosts with the XDP program actively
  // loaded in the kernel. The honest signal is the operator having
  // added `block-ip-xdp` to `responder.allowed_skills` (i.e. wired
  // XDP into the response pipeline). Verified on prod: agent had this
  // flag set + `bpftool prog` showed innerwarden_xdp loaded +
  // blocked-ips.txt had 15k+ entries — but the card still said OFF.
  const xdpOn = (resp && Array.isArray(resp.allowed_skills)
    && resp.allowed_skills.indexOf('block-ip-xdp') !== -1);

  html += '<div class="report-section"><div class="report-section-title">Active Integrations</div>' +
    groupStyle +

    // ── Core Protection (always visible, expanded) ──
    group('Core Protection', [
      card(lucideIcon('bot'), 'AI Analysis',   s.ai_enabled,     'Analyzes threats and selects the best response action',       s.ai_enabled ? 'ON' : 'OFF', 'native', 'Built into InnerWarden - no external service needed.', 'innerwarden enable ai'),
      card(lucideIcon('shield'), 'IP Blocker',    resp.enabled,     'Automatically blocks IPs via UFW/iptables when AI decides',   resp.enabled ? 'ON' : 'OFF', 'native', 'Zero cost. Uses your existing firewall.',               'innerwarden enable block-ip'),
      card(lucideIcon('flask-conical'), 'Honeypot',      hpMode !== 'off', 'Decoy server that captures and logs attacker behavior',       hpBadge,                     'native', 'listener mode activates on AI demand; always_on keeps it permanently open.', ''),
      card(lucideIcon('flame'), 'XDP Firewall',  xdpOn,            'Wire-speed IP blocking at network driver - 10M+ pps drop',    xdpOn ? 'ON' : 'OFF',         'native', 'Layered defense: XDP drops in-kernel at line rate alongside the ufw/iptables backend. Enable: add `block-ip-xdp` to `responder.allowed_skills` in agent.toml.', ''),
    ], true) +

    // ── Kernel Hardening (expanded — v0.6.0 features) ──
    group('Kernel Hardening', [
      kcCard,
      card(lucideIcon('lock'), 'Sensitive Path Guard', s.sensitive_write||true, 'LSM hook blocks writes to /etc/shadow, sudoers, authorized_keys, crontab', s.sensitive_write !== false ? 'ON' : 'OFF', 'native', 'Capability-based policy: per-cgroup and per-process write permissions via BPF maps.', ''),
      card(lucideIcon('flame'), 'io_uring Monitor',     s.io_uring||true,       'Detects io_uring syscall bypass evasion — invisible to most security tools', s.io_uring !== false ? 'ON' : 'OFF', 'native', 'Tracepoints on submit_sqe/submit_req + create. Alerts on CONNECT, ACCEPT, OPENAT, URING_CMD.', ''),
      card(lucideIcon('server'), 'Container Drift',      s.container_drift||true,'Detects binaries dropped after container start via overlayfs upper-layer',   s.container_drift !== false ? 'ON' : 'OFF', 'native', 'Overlayfs upper-layer drift check at execve using inode layout from BTF.', ''),
      card(lucideIcon('shield'), 'Sudo Protection',      s.sudo_protection||false, 'Detects privilege abuse and suspends sudo access',  s.sudo_protection ? 'ON' : 'OFF', 'native', 'Detects 11 threat categories including SUID manipulation, SSH key injection, log tampering.', 'innerwarden enable sudo-protection'),
      card(lucideIcon('crosshair'), 'Execution Guard',      s.execution_guard||false, 'Structural AST analysis of shell commands - catches obfuscation', s.execution_guard ? 'ON' : 'OFF', 'native', 'tree-sitter-bash analysis. Detects reverse shells, curl|bash, hex obfuscation.', 'innerwarden enable execution-guard'),
      card(lucideIcon('shield-check'), 'Shield (DDoS)',        integ.shield||false,    'Packet flood detection + Cloudflare edge push for volumetric attacks', integ.shield ? 'ON' : 'OFF', 'native', 'Detects SYN/UDP/ICMP floods. Pushes to Cloudflare edge when enabled.', ''),
      card(lucideIcon('dna'), 'Threat DNA',           integ.dna||false,       'Attacker fingerprinting and behavioral correlation across sessions',   integ.dna ? 'ON' : 'OFF', 'native', 'Always active. Tracks attack patterns, timing signatures, tool fingerprints.', ''),
    ], true) +

    // ── Alerts & Notifications (collapsed) ──
    group('Alerts & Notifications', [
      card(lucideIcon('bot'), 'Telegram',  integ.telegram,     'Real-time alerts + inline approval buttons on your phone', integ.telegram ? 'ON' : 'OFF', 'external', 'Free. Best solo-operator channel - supports bidirectional approve/reject.', 'innerwarden notify telegram'),
      card(lucideIcon('bot'), 'Slack',     integ.slack,         'Incident notifications to a Slack team channel',          integ.slack ? 'ON' : 'OFF',    'external', 'Free (requires workspace). Alongside Telegram doubles alert volume.',      'innerwarden notify slack'),
      card(lucideIcon('bot'), 'Discord',   integ.discord||false, 'Incident notifications to a Discord server channel',      integ.discord ? 'ON' : 'OFF',  'external', 'Free. Incoming Webhook, colour-coded embeds. Same alerts as Telegram/Slack.', 'innerwarden notify discord'),
      card(lucideIcon('bot'), 'Web Push',  integ.web_push||false, 'Browser push notifications - no Telegram/Slack needed', integ.web_push ? 'ON' : 'OFF', 'native', 'VAPID-based. Subscribe from the dashboard bell icon. No external service.', ''),
      card(lucideIcon('alert-triangle'), 'PagerDuty', (s.webhook_format||'') === 'pagerduty', 'On-call alerts via PagerDuty Events API v2', (s.webhook_format||'') === 'pagerduty' ? 'ON' : 'OFF', 'external', 'Set webhook.format = \"pagerduty\" and webhook.url to PagerDuty endpoint.', 'innerwarden configure webhook'),
      card(lucideIcon('alert-circle'), 'Opsgenie',  (s.webhook_format||'') === 'opsgenie',  'On-call alerts via Opsgenie Alert API',      (s.webhook_format||'') === 'opsgenie' ? 'ON' : 'OFF',  'external', 'Set webhook.format = \"opsgenie\" and webhook.url to Opsgenie endpoint.', 'innerwarden configure webhook'),
    ], false) +

    // ── Threat Intelligence (collapsed) ──
    group('Threat Intelligence', [
      card(lucideIcon('globe'), 'GeoIP',     integ.geoip,          'Adds country/ISP info to every threat - free, no key needed', integ.geoip ? 'ON' : 'OFF', 'native', 'Free. Calls ip-api.com (45 req/min). Best first enrichment to enable.', 'innerwarden integrate geoip'),
      card(lucideIcon('search'), 'AbuseIPDB', integ.abuseipdb,      'IP reputation + delayed community reporting (5min grace)',    integ.abuseipdb ? 'ON' : 'OFF', 'external', 'Free plan: 1,000 req/day. Reports delayed 5 min for false-positive correction.', 'innerwarden integrate abuseipdb'),
      card(lucideIcon('globe'), 'CrowdSec',  integ.crowdsec||false, 'Community threat intelligence - known-bad IPs on incident',  integ.crowdsec ? 'ON' : 'OFF', 'external', 'Free. Requires CrowdSec LAPI running locally. Lookup-only.', 'innerwarden integrate crowdsec'),
      card(lucideIcon('link'), 'Mesh Network', integ.mesh||false,  'Collaborative defense - peers exchange block signals',       integ.mesh ? 'ON' : 'OFF', 'native', 'Decentralized threat intel sharing between InnerWarden instances.', 'innerwarden integrate mesh'),
    ], false) +

    // ── External Services (collapsed) ──
    group('External Services', [
      card(lucideIcon('shield'), 'Cloudflare',   integ.cloudflare,      'Pushes blocked IPs to Cloudflare edge after block-ip fires', integ.cloudflare ? 'ON' : 'OFF', 'external', 'Free plan supports IP Access Rules. Effective for DDoS edge-layer defense.', 'innerwarden integrate cloudflare'),
      card(lucideIcon('bar-chart-3'), 'Prometheus',    true,                  'Metrics endpoint at /metrics - scrape with Prometheus/Grafana', 'ON', 'native', 'Always available when dashboard is active. No config needed.', ''),
    ], false) +

    '</div>';

  // ── Section 2b: Integration advisor ────────────────────────────────────
  const conflicts = [];
  // (No conflicts to check - fail2ban removed, AbuseIPDB reports delayed)

  // Informational notes: valid setups worth being aware of, NOT problems.
  const notes = [];
  if (integ.telegram && integ.slack) {
    notes.push({
      a: 'Telegram', b: 'Slack',
      msg: 'Both channels deliver High/Critical alerts — an intentional, supported setup: Telegram for real-time response on your phone, Slack for team visibility. Solo operator who wants less noise can keep just one, but running both is fine.'
    });
  }

  const recommendations = [];
  if (!integ.geoip)     recommendations.push({ icon: lucideIcon('globe'), text:'Enable GeoIP - free, zero noise, adds country/ISP to every AI decision', cmd:'innerwarden integrate geoip' });
  if (!integ.telegram)  recommendations.push({ icon: lucideIcon('bot'), text:'Enable Telegram - real-time alerts with approve/reject buttons on your phone', cmd:'innerwarden notify telegram' });
  if (!integ.abuseipdb) recommendations.push({ icon: lucideIcon('search'), text:'Enable AbuseIPDB - free API key, enriches AI context with IP reputation score', cmd:'innerwarden integrate abuseipdb' });
  if (!integ.cloudflare && resp.enabled) recommendations.push({ icon: lucideIcon('shield'), text:'Enable Cloudflare - push blocked IPs to the edge after every block-ip decision', cmd:'innerwarden integrate cloudflare' });
  if (!integ.mesh) recommendations.push({ icon: lucideIcon('link'), text:'Enable Mesh - share threat intel with other InnerWarden instances', cmd:'innerwarden integrate mesh' });

  if (conflicts.length > 0 || notes.length > 0 || recommendations.length > 0) {
    html += '<div class="report-section"><div class="report-section-title">Integration Advisor</div>' +
      '<style>' +
      '.advisor-block{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px}' +
      '.advisor-conflict{border-left:3px solid var(--warn)}' +
      '.advisor-note{border-left:3px solid var(--muted)}' +
      '.advisor-rec{border-left:3px solid var(--accent)}' +
      '.advisor-label{font-size:0.65rem;font-weight:700;letter-spacing:0.06em;margin-bottom:6px}' +
      '.advisor-label.warn{color:var(--warn)}' +
      '.advisor-label.info{color:var(--muted)}' +
      '.advisor-label.ok{color:var(--accent)}' +
      '.advisor-pair{font-size:0.75rem;font-weight:700;color:var(--text);margin-bottom:3px}' +
      '.advisor-msg{font-size:0.68rem;color:var(--muted);line-height:1.5}' +
      '.advisor-cmd{font-size:0.62rem;color:var(--accent);margin-top:5px;font-family:\'JetBrains Mono\',monospace}' +
      '</style>';

    conflicts.forEach(c => {
      html += '<div class="advisor-block advisor-conflict">' +
        '<div class="advisor-label warn" style="display:flex;align-items:center;gap:6px">' + lucideIcon('alert-triangle',{size:14}) + ' OVERLAP DETECTED</div>' +
        '<div class="advisor-pair">' + esc(c.a) + ' ↔ ' + esc(c.b) + '</div>' +
        '<div class="advisor-msg">' + esc(c.msg) + '</div>' +
        '</div>';
    });

    notes.forEach(n => {
      html += '<div class="advisor-block advisor-note">' +
        '<div class="advisor-label info" style="display:flex;align-items:center;gap:6px">' + lucideIcon('info',{size:14}) + ' MULTI-CHANNEL ACTIVE</div>' +
        '<div class="advisor-pair">' + esc(n.a) + ' + ' + esc(n.b) + '</div>' +
        '<div class="advisor-msg">' + esc(n.msg) + '</div>' +
        '</div>';
    });

    if (recommendations.length > 0) {
      const next = recommendations[0];
      html += '<div class="advisor-block advisor-rec">' +
        '<div class="advisor-label ok" style="display:flex;align-items:center;gap:6px">' + lucideIcon('flame',{size:14}) + ' RECOMMENDED NEXT STEP</div>' +
        '<div class="advisor-pair">' + next.icon + ' ' + esc(next.text) + '</div>' +
        '<div class="advisor-cmd">$ ' + esc(next.cmd) + '</div>' +
        '</div>';
      if (recommendations.length > 1) {
        html += '<div style="font-size:0.62rem;color:var(--muted);padding:0 4px 12px">After that: ';
        html += recommendations.slice(1).map(r => esc(r.icon + ' ' + r.cmd)).join(' &nbsp;·&nbsp; ');
        html += '</div>';
      }
    }

    html += '</div>';
  }

  // ── Section 3: Sensor Collectors ──────────────────────────────────────
  // 2026-05-15: drop collectors flagged `not_applicable` (e.g. macOS
  // unified log on Linux). The PR29 health badges accurately said
  // "NOT FOUND" for those, but on a Linux host they cannot physically
  // exist — better to hide than to render a forever-red row.
  collectors = collectors.filter(function(c) { return !c.not_applicable; });
  if (collectors.length > 0) {
    const colIcons = {
      auth_log: lucideIcon('lock'), journald: lucideIcon('clipboard-list'), docker: lucideIcon('server'), nginx_access: lucideIcon('globe'), nginx_error: lucideIcon('alert-triangle'),
      auditd: lucideIcon('search'), ebpf: lucideIcon('flame'),
      syslog_firewall: lucideIcon('shield'), firmware_integrity: lucideIcon('wrench'), cloudtrail: lucideIcon('globe'), macos_log: lucideIcon('cpu'),      };
    const colStyle =
      '.col-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:4px}' +
      '.col-row{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:11px 14px;display:flex;align-items:center;gap:10px}' +
      '.col-row.col-active{border-color:rgba(58,194,126,0.35)}' +
      '.col-row.col-detected{border-color:rgba(255,184,77,0.25)}' +
      '.col-row.col-missing{opacity:0.5}' +
      '.col-ico{font-size:1.2rem;flex-shrink:0}' +
      '.col-body{flex:1;min-width:0}' +
      '.col-name{font-size:0.78rem;font-weight:700;color:var(--text);display:flex;flex-wrap:wrap;align-items:center;gap:4px}' +
      '.col-meta{font-size:0.62rem;color:var(--muted);margin-top:2px}' +
      '.col-evt{display:inline-block;font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;margin-left:6px;vertical-align:middle;background:rgba(120,229,255,0.12);color:var(--accent)}' +
      '.col-status-active{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(58,194,126,0.2);color:var(--ok)}' +
      '.col-status-detected{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(255,184,77,0.15);color:var(--warn)}' +
      '.col-status-missing{font-size:0.58rem;font-weight:700;padding:1px 6px;border-radius:20px;background:rgba(100,100,100,0.15);color:var(--muted)}' +
      '.col-kind-native{display:inline-block;font-size:0.5rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:4px;vertical-align:middle;background:rgba(120,229,255,0.1);color:var(--accent)}' +
      '.col-kind-ext{display:inline-block;font-size:0.5rem;font-weight:700;padding:1px 4px;border-radius:3px;margin-left:4px;vertical-align:middle;background:rgba(255,184,77,0.1);color:var(--warn)}' +
      '@media(max-width:900px){.col-grid{grid-template-columns:repeat(2,1fr)}}' +
      '@media(max-width:640px){.col-grid{grid-template-columns:1fr}}';

    html += '<div class="report-section"><div class="report-section-title">Sensor Collectors</div>' +
      '<style>' + colStyle + '</style>' +
      '<div style="font-size:0.65rem;color:var(--muted);margin-bottom:12px">' +
      '<span class="col-status-active">ACTIVE</span> log file exists + written in last 2h &nbsp; ' +
      '<span class="col-status-detected">DETECTED</span> log file exists but stale or not yet seen today &nbsp; ' +
      '<span class="col-status-missing">NOT FOUND</span> tool not installed / log absent' +
      '</div>' +
      '<div class="col-grid">';

    collectors.forEach(c => {
      const icon = colIcons[c.id] || lucideIcon('server');
      const kindBadge = c.kind === 'native'
        ? '<span class="col-kind-native">NATIVE</span>'
        : '<span class="col-kind-ext">EXTERNAL</span>';
      let statusBadge, rowCls;
      if (c.active) {
        statusBadge = '<span class="col-status-active">ACTIVE</span>';
        rowCls = 'col-active';
      } else if (c.detected) {
        statusBadge = '<span class="col-status-detected">DETECTED</span>';
        rowCls = 'col-detected';
      } else {
        statusBadge = '<span class="col-status-missing">NOT FOUND</span>';
        rowCls = 'col-missing';
      }
      const evtBadge = c.events_today > 0
        ? '<span class="col-evt">' + c.events_today + ' events today</span>'
        : '';
      html += '<div class="col-row ' + rowCls + '">' +
        '<div class="col-ico">' + icon + '</div>' +
        '<div class="col-body">' +
        '<div class="col-name">' + esc(c.name) + kindBadge + statusBadge + evtBadge + '</div>' +
        '<div class="col-meta">' + esc(c.desc) + '</div>' +
        ((!c.detected && c.kind === 'external') ? '<div style="font-size:0.58rem;color:var(--accent);margin-top:3px">Not installed - optional external tool</div>' : '') +
        '</div></div>';
    });

    html += '</div></div>';
  }

  // 2026-05-15 slim-down: removed the "Data Files" section. Post-spec-016
  // events + incidents live in SQLite; the two remaining JSONL files
  // (decisions / telemetry) are implementation detail the operator
  // never acts on. Data directory path moved to a single inline line
  // for the rare on-call case where the path matters.
  html += '<div class="report-section"><div class="report-section-title">Data Directory</div>' +
    '<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.78rem;color:var(--muted);padding:4px 0">' + esc(s.data_dir || '-') + '</div></div>';

  // ── Section 5: Knowledge Graph stats ──────────────────────────────────
  const gs = s.graph || {};
  if (gs.node_count) {
    const gmem = gs.memory_bytes ? (gs.memory_bytes / 1024 / 1024).toFixed(1) + ' MB' : '?';
    const byType = gs.nodes_by_type || {};
    html += '<div class="report-section"><div class="report-section-title">Knowledge Graph</div>' +
      '<div style="display:flex;gap:16px;flex-wrap:wrap;padding:4px 0;font-size:0.78rem;">' +
      '<span>Nodes: <b>' + (gs.node_count||0) + '</b></span>' +
      '<span>Edges: <b>' + (gs.edge_count||0) + '</b></span>' +
      '<span>Memory: <b>' + gmem + '</b></span>' +
      '<span>Incidents: <b>' + (gs.incident_nodes||0) + '</b></span>' +
      '<span>Threat Intel: <b>' + (gs.threat_intel_nodes||0) + '</b></span>' +
      '</div>' +
      '<div style="font-size:0.72rem;color:var(--muted);padding:2px 0">' +
      Object.entries(byType).map(function(e) { return e[0] + ':' + e[1]; }).join(' · ') +
      '</div></div>';
  }

  // ── Section 6: Metrics Drift ─────────────────────────────────────
  // 2026-05-16 PR-H: dropped the "spec 024" tag from the visible
  // subtitle (operator-facing copy must not leak internal spec
  // numbers — they're noise to the end user).
  // The populated content is injected asynchronously by loadMetricsDrift().
  html += '<div class="report-section" id="metrics-drift-section">' +
    '<div class="report-section-title">' +
      'Metrics Drift <span style="font-size:0.72rem;color:var(--muted);font-weight:normal">' +
        '· scraping /metrics</span>' +
    '</div>' +
    '<div id="metrics-drift-body"><div class="muted">Loading…</div></div>' +
    '</div>';

  return html;
}

// ─── Spec 024 Metrics Drift ────────────────────────────────────────────
//
// Reads the agent's own /metrics endpoint (Prometheus text, served by
// dashboard/agent_api::api_prometheus_metrics) and renders the 10
// spec-024 drift metrics. No external Prometheus server needed.
//
// Invoked by loadStatus() after renderStatus completes. Missing metrics
// render as 0 rather than omitting rows so operators always see the
// expected shape.

const METRICS_DRIFT_KEYS = [
  { key: 'innerwarden_incidents_per_hour',          labelDim: 'severity', heading: 'Incidents / hour',            alert: '±3σ from 7-day mean' },
  { key: 'innerwarden_telegram_msgs_per_hour',      labelDim: null,       heading: 'Telegram msgs / hour',         alert: '>50/h warn · >200/h crit' },
  { key: 'innerwarden_blocks_per_hour',             labelDim: 'backend',  heading: 'Blocks / hour',                alert: '±3σ from 7-day mean' },
  { key: 'innerwarden_honeypot_sessions_per_hour',  labelDim: null,       heading: 'Honeypot sessions / hour',     alert: '0 for 24h · warn' },
  { key: 'innerwarden_tracker_detections_per_hour', labelDim: 'pattern',  heading: 'Tracker detections / hour',    alert: '0 for 24h when incidents>10 · warn' },
  { key: 'innerwarden_orphaned_responses_total',    labelDim: null,       heading: 'Orphaned responses (total)',   alert: 'Any increment · critical' },
  { key: 'innerwarden_revert_failures_total',       labelDim: null,       heading: 'Revert failures (total)',      alert: 'increase over 1h >10 · warn' },
  { key: 'innerwarden_ai_provider_errors_per_hour', labelDim: 'provider', heading: 'AI provider errors / hour',    alert: '>5/h · warn' },
  { key: 'innerwarden_gate_suppressed_total',       labelDim: null,       heading: 'Gate suppressed (total)',      alert: 'low rate + high telegram volume = gate drift' },
  { key: 'innerwarden_event_rate_per_hour',         labelDim: 'source',   heading: 'Event rate / hour',            alert: '0 for 1h = source silent' },
];

async function loadMetricsDrift() {
  const body = document.getElementById('metrics-drift-body');
  if (!body) return;
  try {
    const resp = await fetch('/metrics', { credentials: 'same-origin' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const text = await resp.text();
    const parsed = parsePrometheusText(text);
    body.innerHTML = renderMetricsDrift(parsed);
  } catch (e) {
    body.innerHTML = '<div class="muted">Could not read /metrics: ' + esc(String(e.message)) + '</div>';
  }
}

function parsePrometheusText(text) {
  // Map: metric_name → Array<{labels: {k:v}, value: number}>
  const out = new Map();
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw || raw.startsWith('#')) continue;
    // NAME{l1="v1",l2="v2"} VALUE  |  NAME VALUE
    const m = raw.match(/^([a-zA-Z_][a-zA-Z0-9_]*)(?:\{([^}]*)\})?\s+(-?\d+(?:\.\d+)?)/);
    if (!m) continue;
    const name = m[1];
    const labels = {};
    if (m[2]) {
      const parts = m[2].split(',');
      for (let p = 0; p < parts.length; p++) {
        const pm = parts[p].match(/^\s*([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"\s*$/);
        if (pm) labels[pm[1]] = pm[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      }
    }
    const val = Number(m[3]);
    if (!out.has(name)) out.set(name, []);
    out.get(name).push({ labels: labels, value: val });
  }
  return out;
}

function renderMetricsDrift(parsed) {
  let html = '<div style="font-size:0.74rem;color:var(--muted);padding-bottom:6px">' +
    'Live view of the 10 metrics scraped by <code>docs/prometheus-alerts.yaml</code>. ' +
    'Zero across the board on a quiet host is expected; sudden jumps or collapses signal drift.' +
    '</div>';
  html += '<table class="report-table" style="font-size:0.78rem">' +
    '<thead><tr>' +
    '<th style="text-align:left">Metric</th>' +
    '<th style="text-align:left">Dimension</th>' +
    '<th style="text-align:right">Value</th>' +
    '<th style="text-align:left">Alert rule</th>' +
    '</tr></thead><tbody>';
  for (let i = 0; i < METRICS_DRIFT_KEYS.length; i++) {
    const entry = METRICS_DRIFT_KEYS[i];
    const rows = parsed.get(entry.key) || [];
    if (rows.length === 0) {
      html += '<tr>' +
        '<td><code>' + esc(entry.key) + '</code></td>' +
        '<td class="muted">' + (entry.labelDim ? esc(entry.labelDim) + ': —' : '—') + '</td>' +
        '<td style="text-align:right">0</td>' +
        '<td class="muted">' + esc(entry.alert) + '</td>' +
        '</tr>';
      continue;
    }
    for (let r = 0; r < rows.length; r++) {
      const row = rows[r];
      const dim = entry.labelDim
        ? esc(entry.labelDim) + ': <code>' + esc(row.labels[entry.labelDim] || '—') + '</code>'
        : '—';
      html += '<tr>' +
        '<td><code>' + esc(entry.key) + '</code></td>' +
        '<td>' + dim + '</td>' +
        '<td style="text-align:right">' + formatMetricValue(row.value) + '</td>' +
        '<td class="muted">' + esc(entry.alert) + '</td>' +
        '</tr>';
    }
  }
  html += '</tbody></table>';
  return html;
}

function formatMetricValue(v) {
  if (!isFinite(v)) return '-';
  if (Math.abs(v) >= 100) return v.toFixed(0);
  if (Math.abs(v) >= 10)  return v.toFixed(1);
  return v.toFixed(2);
}

// On mobile: auto-collapse the list when a journey is opened, re-open via button
function collapseLeftOnMobile() {
  if (window.innerWidth <= 860 && leftPanelOpen) {
    toggleLeftPanel();
  }
}

// ── Baseline (Health tab) — three-level UX (2026-05-03 redesign, ──
//                           moved from Intel 2026-05-15 PR-C) ─────────
//
// Operator complaint: the previous version dumped every learned
// signal as a long table and used SOC vocabulary ("lineages",
// "observations", "EMA"). Both the security analyst and the lay
// operator bounced off it. The redesign answers three questions in
// order:
//
//   1. Is everything normal right now?  → Hero (1 line, always visible)
//   2. If not, what changed?              → Deviation cards (top 5)
//   3. What does the agent consider normal here? → "Show learned baseline" (collapsed)
//
// The Hero card paints semaphore colours; deviation cards are
// actionable (each links to the relevant journey); the learned
// baseline section is opt-in. Layouts use heatmap + sparkline so
// the operator can read a week's pattern in one glance instead of
// scrolling a 24-row table per user.

// Friendly headlines + emoji + suggested action text per anomaly type.
// Server returns the raw `anomaly_type` enum value; this map turns it
// into a card the operator can read in 2 seconds.
// 2026-05-03 (PR #419 Wave 2): translated PT-BR → EN to align with
// the rest of the dashboard. Original strings were Portuguese-only,
// inconsistent with all other tabs. Operator request.
const BASELINE_ANOMALY_LABELS = {
  event_rate_drop: {
    icon: '📉',
    headline: (a) => `${prettySource(a)} went silent`,
    explainer: (a) => `Expected this hour: about ${a.expected}. Seen: ${a.observed}.`,
    why: 'Could mean nobody used the service or something disabled the logs. Worth checking.',
  },
  event_rate_spike: {
    icon: '📈',
    headline: (a) => `${prettySource(a)} spiked above normal`,
    explainer: (a) => `Expected: about ${a.expected}. Seen: ${a.observed}.`,
    why: 'Sudden activity peak. Could be a deploy, an external scan, or an attack in progress.',
  },
  process_lineage: {
    icon: '🌿',
    headline: (a) => 'Process lineage never seen before',
    explainer: (a) => a.description,
    why: 'The agent has never observed this parent → child on this host. Often indicates a shell spawning out of a web service.',
  },
  user_login_time: {
    icon: '🌙',
    headline: (a) => `${a.subject || 'User'} logged in outside typical hours`,
    explainer: (a) => `Typical hours: ${a.expected}. Login now: ${a.observed}.`,
    why: 'Access outside the historical pattern. Confirm whether it was you or an authorised user.',
  },
  new_destination: {
    icon: '🔀',
    headline: (a) => `${a.subject || 'Process'} connected to a new destination`,
    explainer: (a) => `Typical destinations: ${a.expected}. Now: ${a.observed}.`,
    why: 'A known process talking to an unfamiliar endpoint. Risk profile changes.',
  },
};

function prettySource(a) {
  // Pull a friendly source name from the description if present, or
  // fall back to a generic phrase. Server passes details inline.
  const m = (a.description || '').match(/source ['"]?([a-z_]+)['"]?/i);
  return m ? m[1] : 'Event collection';
}

function baselineCardForAnomaly(a) {
  const meta = BASELINE_ANOMALY_LABELS[a.anomaly_type] || {
    icon: '⚠️',
    headline: () => 'Pattern outside normal',
    explainer: (x) => x.description || '',
    why: '',
  };
  const ageMin = Math.max(0, Math.floor((Date.now() - new Date(a.ts).getTime()) / 60000));
  const ageStr = ageMin < 60
    ? `${ageMin}m ago`
    : ageMin < 1440
      ? `${Math.floor(ageMin / 60)}h ago`
      : `${Math.floor(ageMin / 1440)}d ago`;
  const sevColor = a.severity === 'critical' ? '#e74c3c'
    : a.severity === 'high' ? '#f39c12'
    : a.severity === 'medium' ? '#f59e0b'
    : 'var(--dim)';
  const subjectLink = a.subject
    ? `<button type="button" onclick="homeBannerOpenPivot('${a.anomaly_type === 'user_login_time' ? 'user' : 'ip'}', '${esc(a.subject)}')" style="margin-top:6px;padding:4px 10px;border-radius:4px;border:1px solid var(--accent);background:transparent;color:var(--accent);cursor:pointer;font-size:0.75rem;">Investigate ${esc(a.subject)} →</button>`
    : '';
  return `
    <div class="baseline-deviation-card">
      <div style="display:flex;align-items:flex-start;gap:10px;">
        <div style="font-size:1.5rem;line-height:1;">${meta.icon}</div>
        <div style="flex:1;">
          <div style="display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;">
            <span style="font-weight:600;font-size:0.92rem;">${esc(meta.headline(a))}</span>
            <span style="font-size:0.7rem;color:${sevColor};text-transform:uppercase;letter-spacing:0.05em;">${esc(a.severity)}</span>
            <span style="font-size:0.7rem;color:var(--dim);">${ageStr}</span>
          </div>
          <div style="font-size:0.82rem;color:var(--text);margin-top:4px;line-height:1.5;">${esc(meta.explainer(a))}</div>
          ${meta.why ? `<div style="font-size:0.75rem;color:var(--dim);margin-top:4px;font-style:italic;">${esc(meta.why)}</div>` : ''}
          ${subjectLink}
        </div>
      </div>
    </div>`;
}

function baselineHeroCard(b, deviations24h) {
  if (!b.mature) {
    const days = b.training_days || 0;
    const remaining = Math.max(0, 7 - days);
    return `
      <div class="baseline-hero baseline-hero-learning">
        <div class="baseline-hero-icon">🔵</div>
        <div class="baseline-hero-body">
          <div class="baseline-hero-title">Learning what's normal on this server</div>
          <div class="baseline-hero-sub">${days} of 7 days collected. Anomaly detection starts in ${remaining} ${remaining === 1 ? 'day' : 'days'}.</div>
        </div>
      </div>`;
  }
  if (deviations24h === 0) {
    return `
      <div class="baseline-hero baseline-hero-normal">
        <div class="baseline-hero-icon">🟢</div>
        <div class="baseline-hero-body">
          <div class="baseline-hero-title">Normal</div>
          <div class="baseline-hero-sub">The server is behaving the same as on recent days. No patterns outside normal in the last 24 hours.</div>
        </div>
      </div>`;
  }
  return `
    <div class="baseline-hero baseline-hero-deviation">
      <div class="baseline-hero-icon">🟡</div>
      <div class="baseline-hero-body">
        <div class="baseline-hero-title">Something changed</div>
        <div class="baseline-hero-sub">${deviations24h} ${deviations24h === 1 ? 'pattern' : 'patterns'} outside normal in the last 24 hours. See what changed below.</div>
      </div>
    </div>`;
}

// 2026-05-03 (Wave 5): pagination state for the login heatmap. Stays a
// module-level let so back/forward inside the same Baseline render
// preserves the page; switching tabs resets via `_loginHeatmapPage = 0`
// in `loadBaseline`. Toggle state is persisted in localStorage so the
// operator's choice survives reloads.
let _loginHeatmapPage = 0;
const LOGIN_HEATMAP_PAGE_SIZE = 20;
const LOGIN_HEATMAP_LS_KEY = 'innerwarden.baseline.showServices';
// 2026-05-10: persist the "What I consider normal here" <details>
// open state so pagination re-renders don't collapse the section
// the operator was actively reading. Operator complaint: clicking
// Next on the user-list pagination collapsed the entire learned-
// baseline section. The HTML <details> default is closed, and
// loadBaseline() re-renders intelContent.innerHTML on every page
// change, so the open attribute was never preserved.
const BASELINE_LEARNED_OPEN_LS_KEY = 'innerwarden.baseline.learnedOpen';

function baselineLearnedIsOpen() {
  try {
    return localStorage.getItem(BASELINE_LEARNED_OPEN_LS_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function baselineLearnedSetOpen(v) {
  try {
    localStorage.setItem(BASELINE_LEARNED_OPEN_LS_KEY, v ? '1' : '0');
  } catch (_) {}
}

function loginHeatmapShowServices() {
  try {
    return localStorage.getItem(LOGIN_HEATMAP_LS_KEY) === '1';
  } catch (_) {
    return false;
  }
}

function loginHeatmapSetShowServices(v) {
  try {
    localStorage.setItem(LOGIN_HEATMAP_LS_KEY, v ? '1' : '0');
  } catch (_) {}
}

// Exposed onclick handlers for the toggle + pagination. Re-renders by
// re-calling `renderBaselineHealthSection(_baselineMountSelector)` so
// the controls go through the same data path as the initial load — a
// single source of truth for what the user sees.
function _rerenderBaseline() {
  if (_baselineMountSelector) renderBaselineHealthSection(_baselineMountSelector);
}
window.toggleLoginHeatmapServices = function () {
  loginHeatmapSetShowServices(!loginHeatmapShowServices());
  _loginHeatmapPage = 0;
  _rerenderBaseline();
};
window.loginHeatmapNextPage = function () {
  _loginHeatmapPage += 1;
  _rerenderBaseline();
};
window.loginHeatmapPrevPage = function () {
  _loginHeatmapPage = Math.max(0, _loginHeatmapPage - 1);
  _rerenderBaseline();
};
// 2026-05-10: persist <details open> state for the learned-baseline
// section so re-renders triggered by user-list pagination do not
// collapse the section the operator was actively reading.
window.baselineLearnedOnToggle = function (el) {
  baselineLearnedSetOpen(el && el.open);
};

function loginHeatmap(logins, userClasses) {
  // Full-width 24×N heatmap. Each user gets a single row of 24 cells.
  // Bright cell = login activity seen in that hour historically.
  //
  // 2026-05-03 (Wave 5 — semantics fix):
  // - PAM emits "session opened" entries for daemon accounts
  //   (snap_daemon, systemd-resolve, messagebus, _apt, ...) that share
  //   plumbing with real SSH logins. Without filtering, the heatmap
  //   reads as "many users have logged in" when in reality only the
  //   `Human` + `Root` rows are real human SSH sessions.
  // - The endpoint enriches the JSON with `user_classes`. When that
  //   field is missing (older agent / classification failed), every
  //   user falls back to `unknown` and is shown — operator visibility
  //   beats false reassurance.
  // - The "Show system accounts" toggle is persisted in localStorage
  //   so the operator's choice survives reloads.
  // - Pagination kicks in only when visible humans exceed
  //   LOGIN_HEATMAP_PAGE_SIZE (20). Below that threshold, no paging
  //   controls render at all — keeps the simple case simple.
  const allUsers = Object.entries(logins);
  if (allUsers.length === 0) return '';
  const classes = userClasses || {};
  const classOf = (u) => classes[u] || 'unknown';

  const showServices = loginHeatmapShowServices();
  const visible = allUsers.filter(([user]) => {
    const c = classOf(user);
    if (c === 'service') return showServices;
    return true; // human, root, unknown — always visible
  });
  const hiddenServices = allUsers.length - visible.length;

  const totalPages = Math.max(1, Math.ceil(visible.length / LOGIN_HEATMAP_PAGE_SIZE));
  if (_loginHeatmapPage >= totalPages) _loginHeatmapPage = totalPages - 1;
  const pageStart = _loginHeatmapPage * LOGIN_HEATMAP_PAGE_SIZE;
  const pageUsers = visible.slice(pageStart, pageStart + LOGIN_HEATMAP_PAGE_SIZE);

  const classBadge = (c) => {
    const labels = { human: 'human', root: 'root', service: 'service', unknown: 'unknown' };
    const label = labels[c] || c;
    return `<span class="login-class-badge login-class-badge-${c}">${label}</span>`;
  };

  const rows = pageUsers.map(([user, hours]) => {
    const c = classOf(user);
    const cells = hours.map((v, i) => {
      const active = v > 0;
      const cls = active ? 'login-cell login-cell-active' : 'login-cell';
      const tip = `${user} (${c}) - ${i}:00 ${active ? '✓ session at this hour' : '(no record)'}`;
      return `<div class="${cls}" title="${esc(tip)}"></div>`;
    }).join('');
    return `
      <div class="login-heatmap-row">
        <div class="login-heatmap-user">
          ${classBadge(c)}
          <span class="login-heatmap-user-name" title="${esc(user)}">${esc(user)}</span>
        </div>
        <div class="login-heatmap-cells">${cells}</div>
      </div>`;
  }).join('');

  // Toggle row + (optional) pagination row + (optional) hint about
  // hidden service entries. Keep them above the grid so the operator
  // sees the controls before the data.
  const showHideLabel = showServices
    ? `Hide system accounts`
    : (hiddenServices > 0
      ? `Show system accounts (${hiddenServices})`
      : `Show system accounts`);
  const toggleRow = `
    <div class="login-heatmap-controls">
      <button type="button" class="login-heatmap-toggle" onclick="toggleLoginHeatmapServices()">
        ${esc(showHideLabel)}
      </button>
      ${hiddenServices > 0 && !showServices ? `
        <span class="login-heatmap-hint">
          ${hiddenServices} ${hiddenServices === 1 ? 'daemon PAM session is' : 'daemon PAM sessions are'} hidden (snap_daemon, systemd-resolve, etc.) — they share SSH plumbing but are not real human logins.
        </span>` : ''}
    </div>`;

  const paginationRow = visible.length > LOGIN_HEATMAP_PAGE_SIZE ? `
    <div class="login-heatmap-pagination">
      <button type="button" onclick="loginHeatmapPrevPage()" ${_loginHeatmapPage === 0 ? 'disabled' : ''}>← Prev</button>
      <span class="login-heatmap-page-meta">Page ${_loginHeatmapPage + 1} of ${totalPages} · showing ${pageUsers.length} of ${visible.length} users</span>
      <button type="button" onclick="loginHeatmapNextPage()" ${_loginHeatmapPage >= totalPages - 1 ? 'disabled' : ''}>Next →</button>
    </div>` : '';

  return `
    ${toggleRow}
    <div class="login-heatmap">
      <div class="login-heatmap-axis"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
      ${rows}
    </div>
    ${paginationRow}`;
}

function eventRateAggregateSparkline(rates) {
  const sourceCount = Object.keys(rates).length;
  if (sourceCount === 0) return '';
  // Aggregate: sum per hour across all sources. Operator wants the
  // overall pulse, not per-source detail at this level.
  const aggregate = new Array(24).fill(0);
  for (const hours of Object.values(rates)) {
    for (let i = 0; i < 24; i++) aggregate[i] += hours[i] || 0;
  }
  const max = Math.max(...aggregate, 1);
  const bars = aggregate.map((v, i) => {
    const h = Math.max(2, (v / max) * 36);
    const tooltip = `${i}:00 - ~${v.toFixed(0)} typical events`;
    return `<div class="sparkline-bar" style="height:${h}px;" title="${tooltip}"></div>`;
  }).join('');
  return `
    <div class="baseline-sparkline">
      <div class="baseline-sparkline-label">Typical activity per hour (all ${sourceCount} sources combined)</div>
      <div class="baseline-sparkline-bars">${bars}</div>
      <div class="baseline-sparkline-axis"><span>0h</span><span>6h</span><span>12h</span><span>18h</span><span>23h</span></div>
    </div>`;
}

function topProcessDestinations(dests, limit) {
  const entries = Object.entries(dests)
    .map(([p, ips]) => ({ proc: p, count: Array.isArray(ips) ? ips.length : 0 }))
    .filter((x) => x.count > 0)
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
  if (entries.length === 0) return '<p style="color:var(--dim);font-size:0.8rem;">No destinations observed yet.</p>';
  return `
    <ul class="baseline-dest-list">
      ${entries.map((x) => `
        <li><code>${esc(x.proc)}</code> connects to <strong>${x.count}</strong> ${x.count === 1 ? 'known destination' : 'known destinations'}</li>
      `).join('')}
    </ul>`;
}

function topProcessLineages(lineages, limit) {
  // The wire shape can be either an array of strings ("nginx→sh") or
  // an object map. Normalise.
  let list = [];
  if (Array.isArray(lineages)) list = lineages;
  else if (lineages && typeof lineages === 'object') list = Object.keys(lineages);
  if (list.length === 0) return '';
  return `
    <p style="font-size:0.8rem;margin:6px 0;color:var(--dim);">
      ${list.length} parent→child chains considered normal. Examples:
      ${list.slice(0, limit).map((l) => `<code>${esc(l)}</code>`).join(' · ')}
    </p>`;
}

// 2026-05-15 PR-C: Baseline moved from Intel to Health. Targets a
// mount-point id on the Health page (parallel to
// renderEnforcementHealthSection in responses.js). No abort
// controller — Health doesn't have sub-tab cycling, so the
// _activeFetch_intel signal is not needed here.
//
// `_baselineMountSelector` remembers the last mount so the pagination/
// toggle handlers above can re-fetch + re-render without the caller
// having to re-pass the id.
let _baselineMountSelector = null;
async function renderBaselineHealthSection(mountSelector) {
  _baselineMountSelector = mountSelector;
  const content = document.getElementById(mountSelector);
  if (!content) return;
  content.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading baseline…</div>';
  try {
    const b = await loadJson('/api/baseline-status');

    // Anomalies in the last 24h. Server may or may not surface them;
    // tolerate both shapes.
    const anomalies = Array.isArray(b.recent_anomalies) ? b.recent_anomalies : [];
    const since24h = Date.now() - 24 * 3600 * 1000;
    const recent = anomalies
      .filter((a) => a.ts && new Date(a.ts).getTime() >= since24h)
      .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime());

    let html = '';

    // ── Level 1: Hero ────────────────────────────────────────
    html += baselineHeroCard(b, recent.length);

    // ── Level 2: deviation cards (top 5) ─────────────────────
    if (recent.length > 0) {
      html += '<h3 class="baseline-section-title">What changed in the last 24 hours</h3>';
      html += '<div class="baseline-deviations">';
      html += recent.slice(0, 5).map(baselineCardForAnomaly).join('');
      html += '</div>';
      if (recent.length > 5) {
        html += `<p style="font-size:0.78rem;color:var(--dim);margin-top:8px;">+${recent.length - 5} other patterns. <a href="#threats" style="color:var(--accent);">See in investigation →</a></p>`;
      }
    } else if (b.mature) {
      html += '<div class="baseline-empty-deviations">No deviations detected in the last 24 hours.</div>';
    }

    // ── Level 3: collapsed "learned baseline" ────────────────
    const lineages = b.process_lineages;
    const lineageCount = Array.isArray(lineages)
      ? lineages.length
      : (lineages && typeof lineages === 'object' ? Object.keys(lineages).length : 0);
    const learnedSummary = `
      ${(b.training_days || 0) >= 7 ? '✓ 7+ days of learning' : `${b.training_days || 0}/7 days of learning`}
      · ${(b.total_observations || 0).toLocaleString('en-US')} events observed
      · ${lineageCount} known process lineages
    `;
    const learnedOpenAttr = baselineLearnedIsOpen() ? 'open' : '';
    html += `
      <details class="baseline-learned" id="baselineLearnedSection" ${learnedOpenAttr} ontoggle="window.baselineLearnedOnToggle && window.baselineLearnedOnToggle(this)">
        <summary class="baseline-learned-summary">
          <span>What I consider normal here</span>
          <span class="baseline-learned-meta">${learnedSummary.replace(/\s+/g, ' ').trim()}</span>
        </summary>
        <div class="baseline-learned-body">
          ${eventRateAggregateSparkline(b.event_rate_by_hour || {})}
          ${Object.keys(b.user_login_hours || {}).length > 0 ? `
            <h4 class="baseline-subtitle">Who logs in, when</h4>
            <p style="font-size:0.8rem;color:var(--dim);margin:0 0 8px;">Each row is a user; each square is an hour of the day this user was seen with an active session. System accounts (snap_daemon, systemd-resolve, _apt, ...) are hidden by default — they share PAM plumbing with real SSH logins but are not human sessions.</p>
            ${loginHeatmap(b.user_login_hours, b.user_classes)}
          ` : ''}
          ${Object.keys(b.process_destinations || {}).length > 0 ? `
            <h4 class="baseline-subtitle">Processes that talk to the outside</h4>
            ${topProcessDestinations(b.process_destinations, 6)}
          ` : ''}
          ${lineageCount > 0 ? `
            <h4 class="baseline-subtitle">Learned process lineages</h4>
            ${topProcessLineages(lineages, 6)}
          ` : ''}
        </div>
      </details>`;

    content.innerHTML = html;
  } catch(e) {
    content.innerHTML = `<p style="color:#e74c3c">Failed to load Baseline: ${e.message}</p>`;
  }
}

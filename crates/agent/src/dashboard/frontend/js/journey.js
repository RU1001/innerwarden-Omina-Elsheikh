// ── Enforcement block (2026-05-15) ─────────────────────────────────────
// Renders a compact "what is enforced for this subject RIGHT NOW" panel
// at the top of the journey detail. Replaces the cross-attacker
// Responses tab for the 95% case: operator clicks an attacker and wants
// to confirm "is this IP really blocked? on which backend? when does it
// expire?". Read-only in this PR; manual revert ships in a follow-up
// when the backend POST /api/responses/:id/revert endpoint lands.
function renderEnforcementBlock(subjectType, subjectValue, responsesPayload) {
  if ((subjectType || '').toLowerCase() !== 'ip' || !subjectValue) return '';
  if (!responsesPayload || !Array.isArray(responsesPayload.active)) return '';
  var matches = responsesPayload.active.filter(function(a) {
    return a && a.target === subjectValue;
  });
  if (matches.length === 0) return '';

  var rows = matches.map(function(a) {
    var stateKind = (a.state && a.state.kind) || 'active';
    var stateBadge;
    if (stateKind === 'active') {
      stateBadge = '<span class="enf-state enf-state-active">active</span>';
    } else if (stateKind === 'revert_pending') {
      stateBadge = '<span class="enf-state enf-state-pending">revert pending</span>';
    } else if (stateKind === 'revert_failed') {
      stateBadge = '<span class="enf-state enf-state-failed">revert failed</span>';
    } else {
      stateBadge = '<span class="enf-state">' + esc(stateKind) + '</span>';
    }
    var ttlSecs = a.ttl_secs || 0;
    var ttlH = Math.floor(ttlSecs / 3600);
    var ttlLabel = ttlH > 0 ? (ttlH + 'h') : Math.max(0, Math.floor(ttlSecs / 60)) + 'm';
    var remSecs = a.remaining_secs || 0;
    var remMins = Math.floor(remSecs / 60);
    var remHrs = Math.floor(remMins / 60);
    var remaining = remHrs > 0 ? (remHrs + 'h ' + (remMins % 60) + 'm') : (remMins + 'm');
    var incident = a.incident_id ? ' · <span class="enf-incident">' + esc(a.incident_id) + '</span>' : '';
    // Spec 076 phase 2: show whether the rule is actually live, not just within
    // its TTL. `enforcement_verified` comes from the reconciler confirming the
    // rule against the real firewall — so the panel can't claim "enforced"
    // while the rule silently dropped.
    var verifiedBadge;
    if (a.enforcement_verified) {
      verifiedBadge = '<span class="enf-verified" title="confirmed live in the firewall by the reconciler">&#10003; live</span>';
    } else if (a.last_verified_live) {
      verifiedBadge = '<span class="enf-unverified" title="last confirmed live a while ago — may have lapsed; reconciler will re-check">&#9888; stale</span>';
    } else {
      verifiedBadge = '<span class="enf-unverified" title="not yet confirmed against the live firewall">&#9888; unverified</span>';
    }
    return '<div class="enf-row">'
      + '<span class="enf-backend">' + esc(a.backend || '—') + '</span>'
      + stateBadge
      + verifiedBadge
      + '<span class="enf-type">' + esc(a.type || 'block_ip') + '</span>'
      + '<span class="enf-ttl">TTL ' + esc(ttlLabel) + '</span>'
      + '<span class="enf-remaining">' + esc(remaining) + ' remaining</span>'
      + incident
      + '</div>';
  }).join('');

  var allVerified = matches.every(function(a) { return a.enforcement_verified; });
  var title = allVerified
    ? 'ENFORCEMENT · enforced right now (verified live)'
    : 'ENFORCEMENT · enforced (verifying against live firewall)';
  return '<div class="enf-block">'
    + '<div class="enf-title">' + title + '</div>'
    + rows
    + '</div>';
}

// ── Kind badge ─────────────────────────────────────────────────────────
function kindBadge(entry) {
  const d = entry.data || {};
  switch (entry.kind) {
    case 'event': {
      const s = d.severity || 'info';
      const cls = s === 'critical' ? 'bk-event-crit' : s === 'high' ? 'bk-event-high' : s === 'medium' ? 'bk-event-med' : 'bk-event';
      return `<span class="bk ${cls}">${esc(s)}</span>`;
    }
    case 'incident':     return `<span class="bk bk-incident">INCIDENT</span>`;
    case 'decision': {
      // PR #423 Wave 4c: prefer the stored `execution_result` (real
      // outcome) over the derived auto_executed-based label. The legacy
      // path lied for `skipped: already blocked` cases by showing SKIPPED
      // without explaining WHY the block didn't run.
      const er = (d.execution_result || '').toString();
      if (er.startsWith('failed')) {
        return `<span class="bk bk-decision-fail" title="${esc(er)}">FAILED</span>`;
      }
      if (er.startsWith('skipped')) {
        // Strip the "skipped: " prefix for the badge tooltip but keep
        // the reason if present (operators want the WHY).
        const why = er.length > 8 ? er.slice(8).trim() : '';
        const tip = why ? `Skipped: ${why}` : 'Skipped';
        return `<span class="bk bk-decision-skip" title="${esc(tip)}">SKIPPED</span>`;
      }
      if (er === 'ok') {
        if (d.dry_run) return `<span class="bk bk-decision-dry">DRY RUN</span>`;
        return `<span class="bk bk-decision">EXECUTED</span>`;
      }
      // Fallback for older rows where execution_result is missing
      // (graph-path entries until queue item Wave 4d lands).
      if (!d.auto_executed) return `<span class="bk bk-decision-skip">SKIPPED</span>`;
      if (d.dry_run)        return `<span class="bk bk-decision-dry">DRY RUN</span>`;
      return `<span class="bk bk-decision">EXECUTED</span>`;
    }
    case 'decision_missing': {
      // PR #423 Wave 4c: an audit-trail gap surfaced explicitly so the
      // operator notices instead of inferring from the absence of a row.
      return `<span class="bk bk-decision-missing" title="No decision recorded for this incident">NO DECISION</span>`;
    }
    case 'honeypot_ssh':    return `<span class="bk bk-honeypot" style="display:inline-flex;align-items:center;gap:4px">${lucideIcon('bug',{size:12})} SSH</span>`;
    case 'honeypot_http':   return `<span class="bk bk-honeypot" style="display:inline-flex;align-items:center;gap:4px">${lucideIcon('bug',{size:12})} HTTP</span>`;
    case 'honeypot_banner': return `<span class="bk bk-honeypot" style="display:inline-flex;align-items:center;gap:4px">${lucideIcon('bug',{size:12})} BANNER</span>`;
    default: return `<span class="bk bk-event">${esc(entry.kind)}</span>`;
  }
}

// ── Dot class ──────────────────────────────────────────────────────────
function dotCls(entry) {
  const d = entry.data || {};
  switch (entry.kind) {
    case 'event': return 'dot-event-' + (d.severity || 'info');
    case 'incident': return 'dot-incident';
    case 'decision': {
      const er = (d.execution_result || '').toString();
      if (er.startsWith('failed')) return 'dot-decision-fail';
      if (er.startsWith('skipped') || !d.auto_executed || d.dry_run) return 'dot-decision-dry';
      return 'dot-decision';
    }
    case 'decision_missing': return 'dot-decision-missing';
    case 'honeypot_ssh':
    case 'honeypot_http':
    case 'honeypot_banner': return 'dot-honeypot';
    default: return 'dot-default';
  }
}

// ── Summary line ───────────────────────────────────────────────────────
// 2026-05-01 (audit finding 1.6): this function previously called
// `esc()` internally on each return path AND the single call site
// (`renderEvidenceCard` at line 285) wrapped the result in another
// `esc()`. The double escape turned `>` into `&amp;gt;` which the
// browser renders as the literal `&gt;` text — that is exactly
// what the auditor saw on event timelines (e.g. `tcp_stream.ssh
// SSH ? -&gt; ? (...)`). Canonical pattern: this function returns
// plain text, the rendering boundary escapes once.
function entrySummary(entry) {
  const d = entry.data || {};
  switch (entry.kind) {
    case 'event':
      return (d.event_kind || '') + ' - ' + (d.summary || '');
    case 'incident':
      return '[' + (d.severity || '').toUpperCase() + '] ' + (d.title || '') + ': ' + (d.summary || '');
    case 'decision': {
      const conf = ((d.confidence || 0) * 100).toFixed(0);
      const reason = (d.reason || '').substring(0, 70);
      return d.action_type + ' (conf: ' + conf + '%) - ' + reason;
    }
    case 'decision_missing': {
      // PR #423 Wave 4c: render the audit-gap explicitly. Operator
      // sees "No decision recorded · audit gap" instead of an empty
      // "Handled automatically" stamped on a decision-less incident.
      return 'No decision recorded · audit gap';
    }
    case 'honeypot_ssh': {
      const attempts = d.auth_attempts || [];
      const creds = attempts.filter(a => a.password).slice(0, 3)
        .map(a => (a.username || '') + '/' + (a.password || '')).join(', ');
      return attempts.length + ' auth attempt(s)' + (creds ? ' · ' + creds : '');
    }
    case 'honeypot_http': {
      const reqs = d.http_requests || [];
      const forms = reqs.filter(r => r.form_fields && r.form_fields.length > 0);
      const formCreds = forms.slice(0, 2).map(r => {
        const fields = Object.fromEntries((r.form_fields || []).map(([k,v]) => [k,v]));
        return (fields.username || fields.user || '') + '/' + (fields.password || fields.pass || '');
      }).filter(Boolean).join(', ');
      return reqs.length + ' request(s)' + (formCreds ? ' · ' + formCreds : '');
    }
    case 'honeypot_banner':
      return 'Banner probe - ' + (d.bytes_captured ?? 0) + ' bytes captured';
    default:
      return entry.kind;
  }
}

// ── D5: Verdict card ───────────────────────────────────────────────────
function verdictValueCls(label, value) {
  const v = (value || '').toLowerCase();
  if (label === 'access') {
    if (v === 'blocked') return 'v-ok';
    if (v === 'successful' || v === 'active') return 'v-danger';
    if (v === 'attempted') return 'v-warn';
    return 'v-muted';
  }
  if (label === 'containment') {
    if (v === 'contained' || v === 'blocked') return 'v-ok';
    if (v === 'active') return 'v-danger';
    return 'v-muted';
  }
  if (label === 'privilege') {
    if (v === 'abused') return 'v-danger';
    if (v === 'suspicious') return 'v-warn';
    return 'v-muted';
  }
  if (label === 'honeypot') {
    return v === 'engaged' ? 'v-accent' : 'v-muted';
  }
  return 'v-muted';
}

function renderVerdictCard(j) {
  if (!j.verdict) return '';
  const v = j.verdict;
  // Simplified verdict: just containment status + confidence
  const isContained = v.containment_status === 'blocked' || v.containment_status === 'honeypot';
  const statusColor = isContained ? 'var(--ok)' : v.containment_status === 'active' ? 'var(--danger)' : 'var(--muted)';
  const statusLabel = isContained ? 'Contained' : v.containment_status === 'active' ? 'Active — needs attention' : 'Under review';
  const confColor = v.confidence === 'high' ? 'var(--ok)' : v.confidence === 'medium' ? 'var(--warn)' : 'var(--muted)';
  // Audit 2.3 phase 2: surface a "what's in this journey" scale line
  // immediately below the verdict verb. The operator sees decision /
  // event counts before scrolling. JourneySummary always carries
  // these fields so the helper renders empty parts gracefully when
  // any are zero (skips the segment instead of "0 events").
  const s = j.summary || {};
  const summaryParts = [];
  if (s.events_count) summaryParts.push(s.events_count + ' event' + (s.events_count === 1 ? '' : 's') + ' analysed');
  if (s.incidents_count) summaryParts.push(s.incidents_count + ' incident' + (s.incidents_count === 1 ? '' : 's'));
  if (s.decisions_count) summaryParts.push(s.decisions_count + ' decision' + (s.decisions_count === 1 ? '' : 's') + ' taken');
  if (s.honeypot_count) summaryParts.push(s.honeypot_count + ' honeypot session' + (s.honeypot_count === 1 ? '' : 's'));
  const summaryLine = summaryParts.length
    ? '<div class="verdict-scale" style="margin-top:6px;font-size:0.66rem;color:var(--muted);letter-spacing:0.02em">' +
      esc(summaryParts.join(' · ')) +
      '</div>'
    : '';
  // Audit 4.2/4.3/4.4: attach the glossary tooltip to the verdict
  // status verb so the operator sees the canonical definition of
  // "Contained / Active / Under review" instead of relying on
  // page-context guesswork.
  var verdictTermKey = isContained
    ? 'contained'
    : v.containment_status === 'active'
    ? 'open'
    : 'unresolved';
  var statusTitle = (typeof glossaryTitle === 'function') ? glossaryTitle(verdictTermKey) : '';
  var confTitle = (typeof glossaryTitle === 'function') ? glossaryTitle('confidence') : '';
  return `
    <div class="verdict-card" style="padding:12px 16px">
      <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <span style="font-size:0.72rem;font-weight:700;color:${statusColor}"${statusTitle}>${statusLabel}</span>
        <span style="font-size:0.62rem;color:var(--dim)">·</span>
        <span style="display:inline-flex;align-items:center;gap:4px;font-size:0.68rem;color:var(--dim)"${confTitle}>
          <span class="conf-dot" style="background:${confColor}"></span>${esc(v.confidence || 'low')} confidence
        </span>
        ${v.entry_vector && v.entry_vector !== 'unknown' ? '<span style="font-size:0.62rem;color:var(--dim)">·</span><span style="font-size:0.68rem;color:var(--muted)">' + humanLabel(v.entry_vector) + '</span>' : ''}
      </div>
      ${summaryLine}
    </div>`;
}

// ── D5: Chapter rail ────────────────────────────────────────────────────
const STAGE_CLASS = {
  reconnaissance:         'stage-recon',
  initial_access_attempt: 'stage-access',
  access_success:         'stage-success',
  privilege_abuse:        'stage-privilege',
  response:               'stage-response',
  containment:            'stage-containment',
  honeypot_interaction:   'stage-honeypot',
};

function renderChapterRail(j) {
  if (!j.chapters || j.chapters.length === 0) return '';
  const pills = j.chapters.map((ch, i) => {
    const stageCls = STAGE_CLASS[ch.stage] || '';
    return `
      <div class="chapter-pill ${stageCls}" onclick="scrollToChapter(${i})" title="${esc(ch.summary)}">
        <div class="chapter-stage">${esc(ch.stage.replace(/_/g, ' '))}</div>
        <div class="chapter-pill-title">${esc(ch.title)}</div>
        <div class="chapter-count">${ch.entry_count} event${ch.entry_count !== 1 ? 's' : ''}</div>
      </div>`;
  }).join('');
  return `<div class="chapter-rail" id="chapterRail">${pills}</div>`;
}

function scrollToChapter(chapterIdx) {
  if (!window._journeyData || !window._journeyData.chapters) return;
  const ch = window._journeyData.chapters[chapterIdx];
  if (!ch || !ch.entry_indices || ch.entry_indices.length === 0) return;
  const el = document.getElementById('tl-entry-' + ch.entry_indices[0]);
  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  document.querySelectorAll('.chapter-pill').forEach((p, i) => {
    p.classList.toggle('active', i === chapterIdx);
  });
}

// ── D5: Evidence card (human-first, raw JSON secondary) ────────────────

// Kill chain timeline renderer - renders when evidence contains kill_chain kind
function renderKillChainTimeline(evidence) {
  if (!evidence || !Array.isArray(evidence)) return null;
  const kc = evidence.find(e => e.kind && e.kind.indexOf('kill_chain') !== -1);
  if (!kc) return null;
  const pattern = kc.pattern || kc.kind || 'KILL_CHAIN';
  const status = kc.blocked ? 'BLOCKED' : 'DETECTED';
  const statusCls = kc.blocked ? 'kc-blocked' : 'kc-detected';
  const proc = kc.process || kc.command || '';
  const pid = kc.pid ? ' (PID ' + kc.pid + (kc.uid != null ? ', UID ' + kc.uid : '') + ')' : '';
  const steps = kc.steps || kc.syscalls || [];
  const c2 = kc.c2 || kc.remote_addr || '';

  let stepsHtml = '';
  steps.forEach(function(s) {
    const ts = s.ts ? esc(fmtTime(s.ts)) + ' → ' : '';
    const desc = esc(s.description || s.call || s.summary || JSON.stringify(s));
    const blocked = s.blocked || s.result === 'BLOCKED';
    stepsHtml += '<div class="kc-step' + (blocked ? ' kc-blocked-step' : '') + '">' +
      ts + desc + (blocked ? ' → BLOCKED' : '') + '</div>';
  });

  return '<div class="kill-chain-timeline">' +
    '<div class="kc-header">' +
      '<span class="kc-pattern" style="display:inline-flex;align-items:center;gap:4px">' + lucideIcon('link',{size:12}) + ' ' + esc(pattern) + '</span>' +
      '<span class="kc-status ' + statusCls + '">' + esc(status) + '</span>' +
    '</div>' +
    (proc ? '<div class="kc-process">' + esc(proc) + esc(pid) + '</div>' : '') +
    (stepsHtml ? '<div class="kc-steps">' + stepsHtml + '</div>' : '') +
    (c2 ? '<div class="kc-c2">C2: ' + esc(c2) + '</div>' : '') +
  '</div>';
}

function renderEvidenceCard(entry, idx) {
  const d = entry.data || {};

  // Check for kill chain evidence in incident entries
  if (entry.kind === 'incident' && d.evidence) {
    const kcHtml = renderKillChainTimeline(
      Array.isArray(d.evidence) ? d.evidence : [d.evidence]
    );
    if (kcHtml) {
      const kcDetector = d.detector || (d.incident_id || '').split(':')[0] || 'kill_chain';
      const kcIp = d.source_ip || d.ip || '';
      const kcTitle = humanIncidentTitle(kcDetector, d.title || '', kcIp);
      return `
        <div id="tl-entry-${idx}">
          <div class="evidence-header">
            <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
            <span class="bk bk-incident">KILL CHAIN</span>
          </div>
          <div class="evidence-title">${esc(kcTitle)}</div>
          ${kcHtml}
          <pre class="evidence-raw" id="raw-${idx}" data-json="${esc(JSON.stringify(entry.data))}"></pre>
        </div>`;
    }
  }

  // ── Humanized incident cards ──
  if (entry.kind === 'incident') {
    const detector = d.detector || (d.incident_id || '').split(':')[0] || '';
    const ip = d.source_ip || d.ip || '';
    const sev = (d.severity || 'info').toLowerCase();
    const hTitle = humanIncidentTitle(detector, d.title || '', ip);
    // Determine outcome from journey context (passed via _journeyOutcome global)
    const jOutcome = window._currentJourneyOutcome || 'unknown';
    const ctx = contextLine(jOutcome, sev);

    // Build collapsible forensic detail
    const lines = [];
    if (d.severity)          lines.push('Severity: ' + d.severity);
    if (d.source_ip || d.ip) lines.push('IP: ' + (d.source_ip || d.ip));
    if (d.user)              lines.push('User: ' + d.user);
    if (d.port)              lines.push('Port: ' + d.port);
    if (d.command)           lines.push('Command: ' + d.command);
    if (d.detector)          lines.push('Detector: ' + d.detector);
    if (d.file_path)         lines.push('File: ' + d.file_path);
    const rawTitle = d.title || '';
    const rawSummary = d.summary || '';

    const outcomeClass = jOutcome === 'blocked' ? 'entry-contained' :
      jOutcome === 'active' ? 'entry-open' :
      jOutcome === 'monitoring' ? 'entry-monitored' : '';

    return `
      <div class="evidence-card ${outcomeClass}" id="tl-entry-${idx}">
        <div class="evidence-header">
          <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
          ${kindBadge(entry)}
          <button type="button" class="detail-toggle" onclick="toggleDetail(this)">Show details</button>
        </div>
        <div class="evidence-title">${esc(hTitle)}</div>
        <div class="human-context ${ctx.cls}">${ctx.text}</div>
        <div class="detail-body">
          <div style="font-size:0.72rem;color:var(--muted);margin-bottom:4px;font-weight:600">Original: ${esc(rawTitle)}</div>
          ${rawSummary ? '<div style="font-size:0.7rem;color:var(--dim);margin-bottom:6px;line-height:1.4">' + esc(rawSummary) + '</div>' : ''}
          ${lines.length ? '<div class="evidence-meta">' + lines.map(l => esc(l)).join('<br>') + '</div>' : ''}
          <button type="button" class="evidence-raw-toggle" onclick="toggleRaw(${idx})" style="margin-top:6px">Raw JSON</button>
          <pre class="evidence-raw" id="raw-${idx}" data-json="${esc(JSON.stringify(entry.data))}"></pre>
        </div>
      </div>`;
  }

  // ── Non-incident entries (decisions, events, honeypot) — keep original rendering ──
  const lines = [];
  if (d.severity)          lines.push('Severity: ' + d.severity);
  if (d.source_ip || d.ip) lines.push('IP: ' + (d.source_ip || d.ip));
  if (d.user)              lines.push('User: ' + d.user);
  if (d.port)              lines.push('Port: ' + d.port);
  if (d.command)           lines.push('Command: ' + d.command);
  if (d.action_type)       lines.push('Action: ' + d.action_type);
  if (d.confidence)        lines.push('Confidence: ' + d.confidence);
  if (d.execution_result)  lines.push('Result: ' + d.execution_result);
  if (d.reason)            lines.push('Reason: ' + d.reason);
  if (d.detector)          lines.push('Detector: ' + d.detector);
  if (d.file_path)         lines.push('File: ' + d.file_path);
  if (d.summary && !lines.length) lines.push(d.summary);
  const metaHtml = lines.length
    ? '<div class="evidence-meta">' + lines.map(l => esc(l)).join('<br>') + '</div>'
    : '';
  const obsVerifyHtml = (d.reason && d.reason.startsWith('obs-verify'))
    ? renderObsVerifyScore(d.reason) : '';
  // Spec 049 PR9: provenance block for decision rows. Rendered
  // ABOVE the legacy meta so the operator reads "who decided" first.
  const provHtml = (entry.kind === 'decision') ? renderDecisionProvenance(d) : '';
  return `
    <div class="evidence-card" id="tl-entry-${idx}">
      <div class="evidence-header">
        <span class="tl-ts">${esc(fmtTime(entry.ts))}</span>
        ${kindBadge(entry)}
        <button type="button" class="evidence-raw-toggle" onclick="toggleRaw(${idx})">Raw JSON</button>
      </div>
      <div class="evidence-title">${esc(entrySummary(entry))}</div>
      ${provHtml}
      ${metaHtml}
      ${obsVerifyHtml}
      <pre class="evidence-raw" id="raw-${idx}" data-json="${esc(JSON.stringify(entry.data))}"></pre>
    </div>`;
}

// Spec 049 PR10 — Recurrence block on the Cases drill-down. Reads
// `j.recurrence` (backend-emitted from attacker_intel for IP
// subjects) and renders an operator-facing summary: pattern badge
// + visit count + first/last seen + returns-after-unblock + a
// link back to the full attacker profile in Intel > Profiles.
//
// Returns '' when the backend did not emit the field (non-IP
// subjects, missing profile, sqlite unavailable). Operator sees
// no block in that case — better than a fake "0 visits" panel.
function renderRecurrenceBlock(rec) {
  if (!rec || typeof rec !== 'object') return '';
  var label = rec.pattern_label || rec.pattern || 'Unknown';
  var visits = rec.visit_count != null ? rec.visit_count : 0;
  var days = rec.total_days_active != null ? rec.total_days_active : 0;
  // fmtDateTime (date + time) defined in api.js; fall back to a raw
  // ISO-date slice if it is unavailable for any reason (script load
  // order edge case).
  var fmt = (typeof fmtDateTime === 'function')
    ? fmtDateTime
    : function(ts) { return (ts || '').slice(0, 10); };
  var first = rec.first_seen ? fmt(rec.first_seen) : '—';
  var last = rec.last_seen ? fmt(rec.last_seen) : '—';
  var returnsRaw = rec.returns_after_unblock != null ? rec.returns_after_unblock : 0;
  var returnsLine = returnsRaw > 0
    ? '<span class="recurrence-pill recurrence-returned">' +
        '↻ ' + esc(String(returnsRaw)) + ' return(s) after unblock <small>(approx.)</small>' +
      '</span>'
    : '<span class="recurrence-pill">No returns after unblock</span>';
  // 2026-05-15: open the specific attacker profile, not the generic
  // Intel tab. profile_link is `/api/attacker-profiles/<ip>`; pull
  // the IP off the tail. The helper openIntelProfile centralises the
  // showView('intel') + setTimeout + showProfileDetail dance.
  var profileIp = '';
  if (rec.profile_link) {
    var parts = String(rec.profile_link).split('/');
    profileIp = parts[parts.length - 1] || '';
  }
  var profileHref = profileIp
    ? '<a href="#intel" class="recurrence-profile-link" ' +
        'onclick="event.preventDefault();openIntelProfile(\'' +
        esc(profileIp) +
        '\')">View full profile →</a>'
    : '';
  // Snake-case wire string for CSS hooks (per-pattern styling can
  // land in a future PR; PR10 keeps chrome neutral). Sanitize defensively.
  var patternKey = String(rec.pattern || 'unknown').replace(/[^a-z0-9_]/gi, '');
  return (
    '<div class="recurrence-block recurrence-pattern-' + esc(patternKey) + '">' +
      '<div class="recurrence-header">' +
        '<span class="recurrence-eyebrow">Recurrence</span>' +
        '<span class="recurrence-pattern-badge">' + esc(label) + '</span>' +
      '</div>' +
      '<div class="recurrence-meta">' +
        '<span class="recurrence-pill"><strong>' + esc(String(visits)) +
          '</strong> visit' + (visits === 1 ? '' : 's') + '</span>' +
        '<span class="recurrence-pill"><strong>' + esc(String(days)) +
          '</strong> day' + (days === 1 ? '' : 's') + ' active</span>' +
        '<span class="recurrence-pill">First seen: ' + esc(first) + '</span>' +
        '<span class="recurrence-pill">Last seen: ' + esc(last) + '</span>' +
        returnsLine +
      '</div>' +
      (profileHref ? '<div class="recurrence-footer">' + profileHref + '</div>' : '') +
    '</div>'
  );
}

// Spec 049 PR9 — Decision provenance block. Renders WHICH layer
// decided (algorithm gate / killchain fast-path / correlation rule
// / AI Local Warden / AI LLM / auto-rule / honeypot post-session /
// observation verifier / manual operator / unknown) plus the
// operator-facing detail line backend derived from the persisted
// `ai_provider` + `reason` + `confidence`.
//
// Renders the `unknown` layer too — surfacing it honestly is the
// PR9 contract. An "unknown (provider: X)" badge gives the operator
// a starting point for investigation rather than hiding the gap.
var DECISION_LAYER_LABELS = {
  algorithm_gate:        'Algorithm gate',
  killchain_fast_path:   'Killchain fast-path',
  correlation_rule:      'Correlation rule',
  ai_local_warden:       'AI · Local Warden',
  ai_llm:                'AI · LLM',
  auto_rule:             'Auto-rule',
  honeypot_post_session: 'Honeypot post-session',
  observation_verifier:  'Observation verifier',
  manual_operator:       'Manual operator',
  unknown:               'Unknown'
};

function renderDecisionProvenance(d) {
  if (!d || !d.decision_layer) return '';
  var layerKey = String(d.decision_layer);
  var label = DECISION_LAYER_LABELS[layerKey] || layerKey;
  var detail = String(d.decision_layer_detail || '');
  var safeKey = layerKey.replace(/[^a-z0-9_]/gi, '');
  return (
    '<div class="decision-provenance decision-provenance-' + esc(safeKey) + '">' +
      '<span class="decision-provenance-label">Decision provenance</span>' +
      '<span class="decision-provenance-badge">' + esc(label) + '</span>' +
      (detail
        ? '<span class="decision-provenance-detail">' + esc(detail) + '</span>'
        : '') +
    '</div>'
  );
}

function toggleTimeline() {
  var el = document.getElementById('timelineSection');
  if (!el) return;
  var isOpen = el.style.display !== 'none';
  el.style.display = isOpen ? 'none' : 'block';
}

// Audit 5.2: forensic-timeline filter. Returns the entries list
// narrowed to system actions (decisions + honeypot sessions) when
// `window._journeyActionsOnly` is set; returns the input unchanged
// otherwise. Pure helper for testability.
function applyForensicFilter(entries) {
  if (!window._journeyActionsOnly) return entries || [];
  return (entries || []).filter(function(e) {
    if (!e || !e.kind) return false;
    if (e.kind === 'decision') return true;
    if (e.kind.indexOf('honeypot') === 0) return true;
    // Incident kind keeps the lead card visible so the operator
    // still sees what triggered each action — without it the
    // forensic timeline reads as a stream of decisions with no
    // context about the threat that was actioned.
    if (e.kind === 'incident') return true;
    return false;
  });
}

function toggleForensicFilter() {
  window._journeyActionsOnly = !window._journeyActionsOnly;
  // Re-render from cached data so the toggle is instant; loadJourney
  // already stashes the response on window._journeyData (line ~598).
  var j = window._journeyData;
  if (!j || typeof state === 'undefined' || !state.selected || !state.selected.value) return;
  // Easiest re-render: ask loadJourney to redraw. It is idempotent
  // for the same subject + filters and returns from the network
  // cache fast enough that the operator perceives it as instant.
  if (typeof loadJourney === 'function') {
    loadJourney(state.selected.type, state.selected.value);
  }
}

async function askAiExplain(subjectType, subjectValue) {
  var resultEl = document.getElementById('aiExplainResult');
  if (!resultEl) return;
  resultEl.style.display = 'block';
  resultEl.innerHTML = '<div style="font-size:0.75rem;color:var(--muted)">Asking AI to explain...</div>';
  try {
    var resp = await fetch('/api/ai-explain?type=' + encodeURIComponent(subjectType) + '&value=' + encodeURIComponent(subjectValue), { cache: 'no-store' });
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    var data = await resp.json();
    resultEl.innerHTML =
      '<div style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px;display:flex;align-items:center;gap:6px">' + lucideIcon('bot',{size:14}) + ' AI Explanation</div>' +
      '<div style="font-size:0.8rem;color:var(--text);line-height:1.6">' + esc(data.explanation || 'No explanation available.') + '</div>';
  } catch (e) {
    resultEl.innerHTML =
      '<div style="font-size:0.75rem;color:var(--warn)">AI explanation not available yet. This feature requires the AI provider to be configured and reachable.</div>';
  }
}

function toggleRaw(idx) {
  const el = document.getElementById('raw-' + idx);
  if (!el) return;
  if (!el.textContent && el.dataset.json) {
    try { el.textContent = JSON.stringify(JSON.parse(el.dataset.json), null, 2); } catch(e) { el.textContent = el.dataset.json; }
    delete el.dataset.json;
  }
  el.classList.toggle('open');
}

// ── Render single timeline entry ───────────────────────────────────────
function renderEntry(entry, idx) {
  const dot = dotCls(entry);
  return `
    <div class="tl-item">
      <div class="tl-spine">
        <div class="tl-dot ${esc(dot)}"></div>
        <div class="tl-connector"></div>
      </div>
      <div class="tl-body">
        ${renderEvidenceCard(entry, idx)}
      </div>
    </div>`;
}

// 2026-05-01 (`tracked-spec-investigation-ux`): timeline grouping
// helpers. The journey API returns a flat list of entries
// (`event` / `incident` / `decision` / `honeypot_*`); the audit
// caught that an operator looking at a single attack saw it
// rendered 5+ times across these kinds. Grouping by incident_id
// collapses the chatter into one expandable card per incident
// while keeping ungrouped raw events visible inline.

/// Extract the grouping key from an entry. Returns `null` for
/// entries that should remain ungrouped (raw events with no
/// incident context, honeypot sessions, etc.). When grouping by
/// incident_id, every entry whose `data.incident_id` matches goes
/// in the same group regardless of `kind`.
function entryGroupKey(entry) {
  const d = (entry && entry.data) || {};
  // PR #423 Wave 4c: `decision_missing` placeholders share the
  // incident_id of the parent incident so they group together.
  if (entry.kind === 'incident' || entry.kind === 'decision' || entry.kind === 'decision_missing') {
    const id = d.incident_id || '';
    return id ? id : null;
  }
  // Some event entries are tagged with the incident_id they
  // belong to (e.g. tcp_stream events that fed a kill_chain
  // detection). When present, fold them into the same group;
  // otherwise leave ungrouped.
  if (entry.kind === 'event' && d.incident_id) {
    return d.incident_id;
  }
  return null;
}

/// Walk `entries` in order and produce a list of groups. Each
/// group is `{key, lead, members}` where `lead` is the most
/// informative entry (incident kind preferred over decision over
/// event) and `members` are the rest in original order. Ungrouped
/// entries are emitted as singleton groups so the renderer can
/// treat groups uniformly.
function groupEntriesByIncident(entries) {
  const order = []; // group keys in first-seen order
  const groups = new Map(); // key → {key, lead, members, kindRank}
  // Lead-rank: lower is preferred. Incident is the canonical
  // "this is what happened" header, decision is "what we did",
  // events are evidence. The lead surfaces the title that the
  // operator scans first.
  const leadRank = (kind) => {
    if (kind === 'incident') return 0;
    if (kind === 'decision') return 1;
    if (kind === 'event') return 2;
    return 3;
  };
  entries.forEach((e, idx) => {
    const k = entryGroupKey(e);
    if (k === null) {
      const ungroupedKey = '__ungrouped_' + idx;
      order.push(ungroupedKey);
      groups.set(ungroupedKey, { key: ungroupedKey, lead: e, members: [], idx });
      return;
    }
    if (!groups.has(k)) {
      order.push(k);
      groups.set(k, { key: k, lead: e, members: [], idx, leadKind: e.kind });
      return;
    }
    const g = groups.get(k);
    if (leadRank(e.kind) < leadRank(g.lead.kind)) {
      // Demote the previous lead into members and replace.
      g.members.push(g.lead);
      g.lead = e;
      g.leadKind = e.kind;
    } else {
      g.members.push(e);
    }
  });
  return order.map((k) => groups.get(k));
}

/// Render one group: the lead entry full-size plus a collapsed
/// "show N more" expander when there are members. Group index is
/// stable across re-renders so the expander toggle keeps working.
function renderEntryGroup(group, gIdx) {
  // Singleton (no incident dedup) — render exactly the legacy way.
  // Preserves the operator-visible appearance for events that don't
  // belong to any incident.
  //
  // 2026-05-02 (release ladder f. — Home critical-alert deeplink):
  // wrap singletons that carry a group key (i.e. an incident_id) in
  // a thin <div data-group-key> so the deeplink scroll-to-incident
  // selector in loadJourney finds them. Without this, the deeplink
  // only matched grouped (multi-member) incidents and silently
  // missed the singleton cases.
  if (!group.members || group.members.length === 0) {
    var inner = renderEntry(group.lead, gIdx);
    if (group.key) {
      return '<div class="tl-singleton" data-group-key="' + esc(group.key) + '">' + inner + '</div>';
    }
    return inner;
  }
  const memberCount = group.members.length;
  const memberHtml = group.members
    .map((m, mi) => renderEntry(m, gIdx * 100 + mi + 1))
    .join('');
  const dot = dotCls(group.lead);
  const expanderId = 'group-members-' + gIdx;
  return `
    <div class="tl-item tl-group" data-group-key="${esc(group.key || '')}">
      <div class="tl-spine">
        <div class="tl-dot ${esc(dot)}"></div>
        <div class="tl-connector"></div>
      </div>
      <div class="tl-body">
        ${renderEvidenceCard(group.lead, gIdx)}
        <div style="margin-top:6px;font-size:0.72rem">
          <button type="button" class="tl-group-toggle"
            onclick="toggleGroupMembers('${esc(expanderId)}', this)"
            style="background:transparent;border:1px solid var(--border);color:var(--accent);padding:3px 10px;border-radius:4px;cursor:pointer;font-size:0.7rem">
            Show ${memberCount} related ${memberCount === 1 ? 'entry' : 'entries'} ▾
          </button>
        </div>
        <div id="${esc(expanderId)}" style="display:none;margin-top:8px;padding-left:8px;border-left:2px solid rgba(255,255,255,0.06)">
          ${memberHtml}
        </div>
      </div>
    </div>`;
}

function toggleGroupMembers(id, btn) {
  const el = document.getElementById(id);
  if (!el) return;
  const showing = el.style.display !== 'none';
  el.style.display = showing ? 'none' : 'block';
  if (btn) {
    const text = btn.textContent || '';
    btn.textContent = showing
      ? text.replace('▴', '▾').replace('Hide', 'Show')
      : text.replace('▾', '▴').replace('Show', 'Hide');
  }
}

function toggleEntry(idx) {
  // Legacy: kept for compatibility; D5 uses toggleRaw instead.
  toggleRaw(idx);
}


async function loadJourney(subjectType, subjectValue, focusIncidentId) {
  state.selected = { type: subjectType, value: subjectValue };
  syncFiltersFromUi();
  syncUrl();
  document.querySelectorAll('.attacker-card').forEach(c => c.classList.remove('active'));
  const card = document.querySelector(
    '.attacker-card[data-subject-type="' + CSS.escape(subjectType) + '"][data-subject-value="' + CSS.escape(subjectValue) + '"]'
  );
  if (card) {
    card.classList.add('active');
    // On mobile: scroll the active card into view and collapse list
    if (window.innerWidth <= 860) {
      card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      setTimeout(collapseLeftOnMobile, 200);
    }
  }

  document.getElementById('homeState').style.display = 'none';
  document.getElementById('journeyContent').style.display = 'block';
  document.getElementById('journeyContent').innerHTML = '<div class="loading" style="padding:40px;text-align:center"><div class="spinner" style="display:inline-block;width:20px;height:20px;border:2px solid var(--line2);border-top-color:var(--accent);border-radius:50%;animation:spin .6s linear infinite;margin-bottom:8px"></div><br>Loading timeline\u2026</div>';

  const panel = document.getElementById('rightPanel');

  // 2026-05-02 audit fix (P7): timeline got stuck on "Loading..."
  // for >15s after rapid toggle / IP switching because the previous
  // fetch resolved last and overwrote the new content. Cancel any
  // in-flight journey fetch before kicking off the next one.
  if (window._activeFetch_journey && typeof window._activeFetch_journey.abort === 'function') {
    try { window._activeFetch_journey.abort(); } catch (_) {}
  }
  const journeyAbort = new AbortController();
  window._activeFetch_journey = journeyAbort;
  const journeySignal = journeyAbort.signal;

  try {
    const baseQs = buildQuery({
      subject_type: subjectType,
      subject: subjectValue,
      date: state.filters.date,
      severity_min: state.filters.severity_min,
      detector: state.filters.detector,
      window_seconds: state.filters.window_seconds,
    });
    const shouldCompare = state.filters.compare_date && state.filters.compare_date !== state.filters.date;
    const compareQs = shouldCompare
      ? buildQuery({
          subject_type: subjectType,
          subject: subjectValue,
          date: state.filters.compare_date,
          severity_min: state.filters.severity_min,
          detector: state.filters.detector,
          window_seconds: state.filters.window_seconds,
        })
      : '';
    const [j, compare, responsesPayload] = await Promise.all([
      loadJson('/api/journey?' + baseQs, { signal: journeySignal }),
      shouldCompare ? loadJson('/api/journey?' + compareQs, { signal: journeySignal }) : Promise.resolve(null),
      // 2026-05-15: pull active enforcement for the Enforcement block.
      // Endpoint returns ALL active entries; we filter client-side to
      // the rows whose `target` matches this subject's IP. Tiny payload
      // (~35 rows on a busy host) — no separate per-IP filter needed.
      loadJson('/api/responses', { signal: journeySignal }).catch(function() { return {}; }),
    ]);
    window._currentJourneyOutcome = j.outcome || 'unknown';
    window._lastResponsesPayload = responsesPayload;
    const first = j.first_seen ? fmtDateTime(j.first_seen) : '-';
    const last  = j.last_seen  ? fmtDateTime(j.last_seen)  : '-';
    const summary = j.summary || {};
    const shortcuts = Array.isArray(summary.pivot_shortcuts) ? summary.pivot_shortcuts : [];
    const hints = Array.isArray(summary.hints) ? summary.hints : [];

    const summaryGrid = `
      <div class="summary-grid">
        <div class="summary-cell"><div class="summary-label">Entries</div><div class="summary-value">${summary.total_entries ?? j.entries.length}</div></div>
        <div class="summary-cell"><div class="summary-label">Events</div><div class="summary-value">${summary.events_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Incidents</div><div class="summary-value">${summary.incidents_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Decisions</div><div class="summary-value">${summary.decisions_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Honeypot</div><div class="summary-value">${summary.honeypot_count ?? 0}</div></div>
        <div class="summary-cell"><div class="summary-label">Window</div><div class="summary-value">${state.filters.window_seconds ? esc(state.filters.window_seconds + 's') : 'full day'}</div></div>
      </div>`;

    const hintsHtml = hints.length
      ? `<ul class="hint-list">${hints.map((h) => `<li class="hint-item">${esc(h)}</li>`).join('')}</ul>`
      : '<div class="empty">No hints available for current scope.</div>';

    const shortcutsHtml = shortcuts.length
      ? `<div class="shortcut-wrap">${shortcuts.map((token) =>
          `<button type="button" class="shortcut-btn" onclick="openPivotShortcut('${esc(token)}')">${esc(token)}</button>`
        ).join('')}</div>`
      : '';

    // Build action buttons if D3 actions are enabled for this subject type.
    // Spec 037 Threats UX bundle: respect the operator's protection mode.
    //   * read_only (actionCfg.enabled=false): hide buttons entirely.
    //   * watch    (actionCfg.enabled=true && actionCfg.dry_run=true):
    //               render disabled with a tooltip so the operator
    //               sees what's possible without misclicking a no-op.
    //   * guard    (actionCfg.enabled=true && actionCfg.dry_run=false):
    //               render normally.
    let actionBtns = '';
    const isWatchMode = actionCfg && actionCfg.enabled && actionCfg.dry_run === true;
    const watchAttrs = isWatchMode
      ? ' disabled title="Watch mode: actions are dry-run only. Switch to Guard mode to execute."'
      : '';
    const watchStyle = isWatchMode ? 'opacity:0.55;cursor:not-allowed' : '';
    const blockedNow = j.outcome === 'blocked'
      || (j.block_state && j.block_state.kind === 'blocked_now');
    if (actionCfg && actionCfg.enabled && subjectType === 'ip') {
      if (!blockedNow) {
        actionBtns += `<button type="button" class="journey-btn action-block" style="${watchStyle}"${watchAttrs}
          onclick="showActionModal('block_ip','${esc(subjectValue)}',null)">⊘ Block IP</button>`;
      } else {
        // 2026-06-10: the inverse of Block. A contained/blocked case used to
        // offer ZERO buttons (Block hides once blocked). Unblock queues a
        // revert the agent loop performs (see /api/action/unblock-ip).
        actionBtns += `<button type="button" class="journey-btn action-unblock" style="${watchStyle}"${watchAttrs}
          onclick="showActionModal('unblock_ip','${esc(subjectValue)}',null)">⊘ Unblock IP</button>`;
      }
      // Trust IP (monitor-only): mark this IP benign so the agent stops
      // AUTO-blocking it. Still detected/logged/notified — only the automated
      // response is suppressed (see /api/action/trust-ip). Available whether or
      // not it's currently blocked.
      actionBtns += `<button type="button" class="journey-btn action-trust" style="${watchStyle}"${watchAttrs}
        onclick="showActionModal('trust_ip','${esc(subjectValue)}',null)">✓ Trust IP</button>`;
    }
    if (actionCfg && actionCfg.enabled && subjectType === 'user') {
      actionBtns += `<button type="button" class="journey-btn action-suspend" style="${watchStyle}"${watchAttrs}
        onclick="showActionModal('suspend_user',null,'${esc(subjectValue)}')">⏸ Suspend sudo</button>`;
    }
    // 2026-06-10: case-level triage verbs. Operate on every incident in the
    // case (collected from the journey at click time). A case in "Needs your
    // attention" (outcome 'open') can be Dismissed or moved to Monitor; an
    // already-handled case can be Reopened.
    if (actionCfg && actionCfg.enabled) {
      if (j.outcome === 'open') {
        actionBtns += `<button type="button" class="journey-btn action-dismiss" style="${watchStyle}"${watchAttrs}
          onclick="showCaseTriageModal('dismiss')">✓ Dismiss (reviewed)</button>`;
        actionBtns += `<button type="button" class="journey-btn action-monitor" style="${watchStyle}"${watchAttrs}
          onclick="showCaseTriageModal('monitor')">⊙ Monitor</button>`;
      } else if (['dismissed', 'monitoring', 'blocked', 'honeypot'].indexOf(j.outcome) !== -1) {
        actionBtns += `<button type="button" class="journey-btn action-reopen" style="${watchStyle}"${watchAttrs}
          onclick="showCaseTriageModal('reopen')">↺ Reopen</button>`;
      }
    }

    // D5: store journey data globally for scrollToChapter
    window._journeyData = j;

    let html = `
      <div style="margin-bottom:12px">
        <button type="button" class="journey-btn" onclick="showHomeState()" style="font-size:0.68rem">← Back to Overview</button>
      </div>
      <div class="journey-header">
        <span class="journey-ip">${esc(j.subject || subjectValue)}</span>
        <span class="${outcomeCls(typeof outcomeOf === 'function' ? outcomeOf({outcome: j.outcome}) : j.outcome)}">${outcomeLabel(typeof outcomeOf === 'function' ? outcomeOf({outcome: j.outcome}) : j.outcome)}</span>
        ${blockStateBadgeHtml(j.block_state)}
        <span class="journey-time">${esc(first)} → ${esc(last)}</span>
        <!-- 2026-05-15 PR-D: campaign membership tag. Empty until
             loadCampaignTagForJourney resolves; shown only when this
             attacker IP belongs to one of the clusters returned by
             /api/campaigns. Click opens the campaign modal. -->
        <span id="journeyCampaignTag" class="journey-campaign-tag" style="display:none"></span>
      </div>
      <div class="journey-subtitle">${esc((j.subject_type || subjectType).toUpperCase())} journey · ${j.entries.length} timeline entries · click any row to expand</div>
      ${renderRecurrenceBlock(j.recurrence)}
      ${renderEnforcementBlock(subjectType, subjectValue, responsesPayload)}
      <div class="journey-actions">
        <button type="button" class="journey-btn" onclick="downloadSnapshot('json')">Export JSON</button>
        <button type="button" class="journey-btn" onclick="downloadSnapshot('md')">Export Markdown</button>
        <!-- Spec 049 PR11 — Audit CSV export. The MSSP deliverable;
             includes metadata header (period, filters, reproducibility
             hash) + one row per journey entry. Reproducible: same
             period+filters+cases → same hash, regardless of when the
             export runs. -->
        <button type="button" class="journey-btn" onclick="downloadSnapshot('csv')">Export Audit CSV</button>
        ${actionBtns}
      </div>
      <!-- verdict card removed: narrative "What happened" + Intelligence section cover this -->
      ${(function() {
        // TL;DR — human-readable narrative, mode-aware.
        const incidents = j.entries.filter(e => e.kind === 'incident');
        const decisions = j.entries.filter(e => e.kind === 'decision');
        // Journey entries serialize decisions as {kind, ts, data:{action_type,...}}.
        // The legacy read of `e.action` returned undefined for every entry so
        // `wasBlocked` was always false and the narrative fell through to
        // "AI decided to monitor" even when a block_ip actually executed.
        const actionOf = e => ((e && e.data && e.data.action_type) || '');
        const blocks = decisions.filter(e => actionOf(e).includes('block'));
        if (incidents.length === 0 && decisions.length === 0) return '';

        const topIncident = incidents.length > 0 ? incidents[0] : null;
        const topData = topIncident ? (topIncident.data || {}) : {};
        const topTitle = topData.title || '';
        const wasBlocked = blocks.length > 0;
        const isGuard = (window._agentMode || 'guard') === 'guard';
        const isResolved = j.outcome === 'blocked' || j.outcome === 'honeypot';

        // Collect all unique detectors across incidents for multi-detector signal
        const allDetectors = new Set();
        incidents.forEach(function(inc) {
          var d = (inc.data || {}).detector || ((inc.data || {}).incident_id || '').split(':')[0] || '';
          if (d) allDetectors.add(d);
        });
        const detLabels = Array.from(allDetectors).map(function(d) { return humanLabel(d); });

        let narrative = '';
        if (topIncident) {
          // Use the incident title for specific context, detector label as category
          if (topTitle && topTitle !== 'unknown') {
            narrative += '<strong>' + esc(topTitle) + '</strong>';
          } else {
            narrative += '<strong>' + esc(detLabels[0] || 'Threat') + '</strong> detected';
          }
          if (incidents.length > 1) narrative += ' (' + incidents.length + ' incidents total)';
          if (detLabels.length > 1) {
            narrative += '. Triggered <strong>' + detLabels.length + ' detectors</strong>: ' + esc(detLabels.join(', '));
          }
          narrative += '. ';
        }
        if (wasBlocked) {
          narrative += 'The AI <strong style="color:var(--ok)">blocked</strong> this threat';
          if (blocks.length > 1) narrative += ' (' + blocks.length + ' actions)';
          narrative += '. ';
        } else if (decisions.length > 0) {
          // Pair with the actionOf() reader above: decisions carry the
          // action label on `data.action_type`, not on the entry itself.
          const action = actionOf(decisions[0]) || 'monitor';
          narrative += 'The AI decided to <strong>' + esc(action.replace(/_/g, ' ')) + '</strong>. ';
        }
        if (isResolved) {
          narrative += 'Threat <strong style="color:var(--ok)">contained</strong>. No action needed.';
        } else if (isGuard) {
          narrative += 'The AI is <strong>still observing</strong> this activity.';
        }

        let html = '<div style="padding:12px 16px;margin-bottom:12px;border-radius:10px;background:rgba(120,229,255,0.04);border:1px solid rgba(120,229,255,0.12)">' +
          '<div style="font-size:0.68rem;font-weight:700;color:var(--accent);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:4px">What happened</div>' +
          '<div style="font-size:0.8rem;color:var(--text);line-height:1.5">' + narrative + '</div></div>';

        // When guard is OFF and the threat is NOT resolved, show a prominent
        // decision block with AI recommendation + action buttons. This is
        // the operator's moment to decide.
        if (!isGuard && !isResolved && subjectType === 'ip') {
          const topSev = topData.severity || '';
          const sevHigh = topSev === 'critical' || topSev === 'high';
          const hasThreatIntel = allDetectors.has('threat_intel') || allDetectors.has('graph_threat_intel');
          const multiDetector = allDetectors.size > 1;

          let recText = '';
          if (hasThreatIntel && sevHigh) {
            recText = 'This IP is in a <strong style="color:var(--danger)">known malicious threat feed</strong> and triggered ' + allDetectors.size + ' detectors. <strong>Blocking is strongly recommended.</strong>';
          } else if (hasThreatIntel) {
            recText = 'This IP is in a <strong>known malicious threat feed</strong>. The AI recommends blocking.';
          } else if (sevHigh && multiDetector) {
            recText = 'This is a <strong style="color:var(--danger)">' + esc(topSev) + ' severity</strong> threat that triggered ' + allDetectors.size + ' detectors. The AI recommends <strong>blocking this IP</strong>.';
          } else if (sevHigh) {
            recText = 'This is a <strong style="color:var(--danger)">' + esc(topSev) + ' severity</strong> threat. The AI recommends <strong>blocking this IP</strong>.';
          } else {
            recText = 'The AI detected suspicious activity from this IP. You can block it or continue observing.';
          }

          html += '<div style="padding:16px;margin-bottom:12px;border-radius:10px;background:rgba(244,63,94,0.06);border:1px solid rgba(244,63,94,0.2)">' +
            '<div style="font-size:0.68rem;font-weight:700;color:var(--danger);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px">\u26A0 Your decision needed</div>' +
            '<div style="font-size:0.8rem;color:var(--text);line-height:1.5;margin-bottom:12px">' + recText + '</div>' +
            '<div style="display:flex;gap:8px;flex-wrap:wrap">' +
              '<button type="button" style="padding:8px 20px;font-size:0.8rem;font-weight:700;border-radius:8px;border:1px solid var(--danger);background:var(--danger);color:#fff;cursor:pointer" onclick="showActionModal(\'block_ip\',\'' + esc(subjectValue) + '\',null)">\u26D4 Block this IP</button>' +
              '<button type="button" style="padding:8px 20px;font-size:0.8rem;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--muted);cursor:pointer" onclick="showToast(\'Continuing to observe\',\'ok\')">Keep observing</button>' +
            '</div>' +
          '</div>';
        }

        return html;
      })()}
      <!-- Attack graph available in Graph tab -->
      <div id="journeyGraphContainer" style="display:none"></div>
      <div class="guided-grid">
        <section class="guided-card">
          <div class="guided-title">Investigation Summary</div>
          ${summaryGrid}
          ${shortcutsHtml}
        </section>
        <section class="guided-card">
          <div class="guided-title">Intelligence</div>
          ${hintsHtml}
        </section>
      </div>`;

    if (compare) {
      const baseS = j.summary || {};
      const cmpS = compare.summary || {};
      const metrics = [
        ['Entries', baseS.total_entries ?? j.entries.length, cmpS.total_entries ?? compare.entries.length],
        ['Incidents', baseS.incidents_count ?? 0, cmpS.incidents_count ?? 0],
        ['Decisions', baseS.decisions_count ?? 0, cmpS.decisions_count ?? 0],
        ['Honeypot', baseS.honeypot_count ?? 0, cmpS.honeypot_count ?? 0],
      ];
      const compareRows = metrics.map(([label, current, previous]) => {
        const delta = Number(current) - Number(previous);
        const deltaLabel = delta > 0 ? '+' + delta : String(delta);
        const deltaCls = delta > 0 ? 'delta-pos' : (delta < 0 ? 'delta-neg' : 'delta-neu');
        return `<div class="compare-cell">
          <div class="summary-label">${esc(label)}</div>
          <div class="summary-value">${current} <span class="${deltaCls}">(${deltaLabel})</span></div>
          <div class="summary-label">compare: ${previous}</div>
        </div>`;
      }).join('');
      html += `
        <section class="guided-card" style="margin-bottom:14px">
          <div class="guided-title">Comparison vs ${esc(state.filters.compare_date)}</div>
          <div class="journey-subtitle" style="margin-bottom:10px">
            current outcome: <strong>${esc(outcomeLabel(j.outcome))}</strong> · compare outcome: <strong>${esc(outcomeLabel(compare.outcome))}</strong>
          </div>
          <div class="compare-grid">${compareRows}</div>
        </section>`;
    }

    // ── AI Decision Reasoning (surfaced from decision entries) ─────────
    // Show the AI's own reasoning prominently, before any technical data.
    // This is the "why" that the operator needs to trust the AI's action.
    const aiDecisions = j.entries.filter(e => e.kind === 'decision' && (e.data || {}).reason);
    if (aiDecisions.length > 0) {
      const dec = aiDecisions[0].data;
      const conf = ((dec.confidence || 0) * 100).toFixed(0);
      const wasExecuted = dec.auto_executed && !dec.dry_run;
      const actionLabel = (dec.action_type || '').replace(/_/g, ' ');
      html += '<div style="padding:14px 16px;margin-bottom:12px;border-radius:10px;background:rgba(74,222,128,0.04);border:1px solid rgba(74,222,128,0.15)">' +
        '<div style="font-size:0.68rem;font-weight:700;color:var(--ok);letter-spacing:0.05em;text-transform:uppercase;margin-bottom:6px">' +
        (wasExecuted ? lucideIcon('bot',{size:14}) + ' AI Decision — ' + esc(actionLabel) + ' (' + conf + '% confidence)' : lucideIcon('bot',{size:14}) + ' AI Analysis') +
        '</div>' +
        '<div style="font-size:0.78rem;color:var(--text);line-height:1.6">' + esc(dec.reason || '') + '</div>' +
      '</div>';
    }

    // ── Ask AI button ─────────────────────────────────────────────────
    // Audit 5.2: forensic-timeline filter button next to "technical
    // entries" toggle. When on, the timeline hides raw events and
    // shows only system actions (decisions + honeypot sessions),
    // which is what an operator preparing a client report or audit
    // wants. State is sticky in `window._journeyActionsOnly` so the
    // toggle survives re-renders driven by SSE refreshes.
    var actionsOnly = !!window._journeyActionsOnly;
    var actionsLabel = actionsOnly
      ? 'Show all entries'
      : 'Show actions only';
    html += '<div style="display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap">' +
      '<button type="button" class="journey-btn" style="background:rgba(120,229,255,0.08);border-color:var(--accent);color:var(--accent)" ' +
        'onclick="askAiExplain(\'' + esc(subjectType) + '\',\'' + esc(subjectValue) + '\')">' +
        lucideIcon('bot',{size:14}) + ' Ask AI to explain</button>' +
      '<button type="button" class="journey-btn" onclick="toggleTimeline()">' +
        lucideIcon('clipboard-list',{size:14}) + ' Show ' + j.entries.length + ' technical entries</button>' +
      '<button type="button" id="forensicFilterBtn" class="journey-btn" onclick="toggleForensicFilter()" ' +
        'title="Hide raw events; show only block/dismiss/escalate/honeypot actions">' +
        lucideIcon('shield-check',{size:14}) + ' ' + actionsLabel + '</button>' +
    '</div>';
    html += '<div id="aiExplainResult" style="display:none;padding:14px 16px;margin-bottom:12px;border-radius:10px;background:rgba(120,229,255,0.04);border:1px solid rgba(120,229,255,0.12)"></div>';

    // ── Chapter rail (collapsed with timeline) ─────────────────────────
    html += '<div id="timelineSection" style="display:none">';
    html += renderChapterRail(j);

    html += '<div class="timeline">';

    var visibleEntries = applyForensicFilter(j.entries);
    if (visibleEntries.length === 0) {
      var emptyMsg = j.entries.length === 0
        ? 'No entries found for this selection on the chosen filters.'
        : (actionsOnly
            ? 'No system actions taken for this subject yet. Toggle off "Show actions only" to see raw events.'
            : 'No entries found for this selection on the chosen filters.');
      html += '<div class="empty">' + esc(emptyMsg) + '</div>';
    } else {
      // 2026-05-01 (audit finding 2.3, `tracked-spec-investigation-ux`):
      // group entries by incident_id and render each group as one
      // lead card + a collapsed "show N more" expander for the
      // remaining members. The pre-fix render flattened every
      // event / incident / decision into its own row, producing
      // the audit's complaint that the same incident appeared 5+
      // times across raw eBPF events, AI dismiss decisions, and
      // human-readable summaries — operator preparing a client
      // report had to manually de-duplicate.
      const grouped = groupEntriesByIncident(visibleEntries);
      grouped.forEach((group, gi) => { html += renderEntryGroup(group, gi); });
    }

    html += '</div></div>';
    document.getElementById('journeyContent').innerHTML = html;

    // 2026-05-02 audit (release ladder f.): if a specific incident_id
    // was passed (typically from Home's critical-alert "Review →"
    // banner), find the matching group in the rendered timeline and
    // scroll it into view + flash a highlight. Falls back silently
    // when the incident_id isn't in the visible groups (e.g. the
    // operator filtered it out via the journey filters).
    if (focusIncidentId) {
      var safeKey = (window.CSS && CSS.escape) ? CSS.escape(focusIncidentId) : focusIncidentId;
      var match = document.querySelector(
        'div.tl-group[data-group-key="' + safeKey + '"], div.tl-singleton[data-group-key="' + safeKey + '"]'
      );
      if (match) {
        match.scrollIntoView({ behavior: 'smooth', block: 'center' });
        match.classList.add('tl-deeplink-flash');
        setTimeout(function() {
          if (match) match.classList.remove('tl-deeplink-flash');
        }, 2400);
      }
    }

    // Load mini-graph for this subject
    loadJourneyGraph(subjectType, subjectValue);
    // 2026-05-15 PR-D: hydrate the campaign-membership tag in the
    // header. Async so a missing /api/campaigns or a non-IP subject
    // doesn't delay the rest of the journey render.
    loadCampaignTagForJourney(subjectType, subjectValue);
  } catch (e) {
    // Swallow AbortError quietly: a fast user toggle/IP switch raced
    // and we already kicked off the new fetch that owns the panel.
    if (e && (e.name === 'AbortError' || e.code === 20)) return;
    document.getElementById('journeyContent').innerHTML = '<div class="err">Failed to load journey: ' + esc(e.message) + '</div>';
  }
}

// Cytoscape node-color palette keyed by NodeType string identifier
// (see `crates/agent/src/knowledge_graph/types.rs`). Defining this
// as a `var` (function-scoped, hoisted) so the inline cytoscape
// style callback below can reference it without a load-order
// dependency. Pre-2026-05-01 this map was assumed to exist
// somewhere, was never defined anywhere, and caused
// `ReferenceError: NODE_COLORS is not defined` to surface in the
// DOM the moment a journey graph rendered (audit finding 1.8).
// Colours are tuned for readability against the dashboard's dark
// theme; types not listed fall through to the neutral grey
// (`#6b7280`) preserved at the call site.
var NODE_COLORS = {
  process:   '#60a5fa', // blue — runtime
  ip:        '#fb7185', // red — network endpoint, often hostile
  file:      '#fbbf24', // amber — filesystem
  user:      '#a78bfa', // purple — identity
  domain:    '#fb923c', // orange — DNS / external
  port:      '#34d399', // green — service
  container: '#22d3ee', // cyan — workload
  device:    '#a3e635', // lime — hardware
  system:    '#94a3b8', // slate — system services
  incident:  '#f87171', // light red — incident node
  campaign:  '#e879f9', // magenta — campaign cluster
};

async function loadJourneyGraph(subjectType, subjectValue) {
  const container = document.getElementById('journeyGraphContainer');
  if (!container) return;

  // Map journey subject type to graph node type
  const typeMap = { ip: 'ip', user: 'user', container: 'container', path: 'file', file: 'file' };
  const gType = typeMap[subjectType] || subjectType;

  try {
    // Ensure Cytoscape.js is loaded
    if (typeof cytoscape === 'undefined') {
      try {
        await new Promise((resolve, reject) => {
          const s = document.createElement('script');
          s.src = 'https://unpkg.com/cytoscape@3.30.4/dist/cytoscape.min.js';
          s.onload = resolve;
          s.onerror = reject;
          document.head.appendChild(s);
          setTimeout(() => reject(new Error('timeout')), 5000);
        });
      } catch (e) {
        container.innerHTML = '<p style="padding:20px;text-align:center;color:var(--dim);font-size:0.75rem">Graph requires internet (Cytoscape.js)</p>';
        return;
      }
    }

    const data = await loadJson('/api/graph/neighborhood?type=' + encodeURIComponent(gType) + '&value=' + encodeURIComponent(subjectValue) + '&depth=2');

    if (!data.nodes || data.nodes.length === 0) {
      container.innerHTML = '<p style="padding:20px;text-align:center;color:var(--dim);font-size:0.75rem">No graph data for this entity yet</p>';
      return;
    }

    const cy = cytoscape({
      container: container,
      elements: { nodes: data.nodes, edges: data.edges },
      style: [
        { selector: 'node', style: {
          'label': 'data(label)',
          'background-color': function(ele) { return NODE_COLORS[ele.data('type')] || '#6b7280'; },
          'color': '#e8eef5',
          'text-valign': 'bottom',
          'text-margin-y': 3,
          'font-size': '9px',
          'width': function(ele) { return Math.max(12, Math.min(35, 8 + ele.degree() * 2)); },
          'height': function(ele) { return Math.max(12, Math.min(35, 8 + ele.degree() * 2)); },
          'border-width': function(ele) { return ele.data('center') ? 3 : 1; },
          'border-color': function(ele) { return ele.data('center') ? '#00d9ff' : '#333'; },
        }},
        { selector: 'edge', style: {
          'width': 1,
          'line-color': '#444',
          'target-arrow-color': '#555',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'label': 'data(relation)',
          'font-size': '7px',
          'color': '#555',
          'text-rotation': 'autorotate',
          'text-margin-y': -6,
        }},
      ],
      layout: { name: 'cose', animate: false, nodeRepulsion: 6000, idealEdgeLength: 60, padding: 15 },
      minZoom: 0.3, maxZoom: 4,
      userPanningEnabled: true,
      userZoomingEnabled: true,
    });

    // Click on a node: navigate to its journey if it's an IP or user
    cy.on('tap', 'node', function(evt) {
      const d = evt.target.data();
      if (d.type === 'Ip') {
        loadJourney('ip', d.label);
      } else if (d.type === 'User') {
        loadJourney('user', d.label);
      }
    });

  } catch (e) {
    container.innerHTML = '<p style="padding:20px;text-align:center;color:var(--dim);font-size:0.75rem">Graph: ' + esc(e.message) + '</p>';
  }
}

// ── Observation Verification score display (spec 021 Phase D) ──────────

/** Parse obs-verify reason string and render a visual score badge + breakdown.
 *  Format: "obs-verify score X/100: reason1, reason2"
 *  or:     "obs-verify AI: VERDICT — reason"
 */
function renderObsVerifyScore(reason) {
  if (!reason) return '';

  // Parse "obs-verify score X/100: details"
  var scoreMatch = reason.match(/obs-verify score (\d+)\/100:\s*(.*)/);
  if (scoreMatch) {
    var score = parseInt(scoreMatch[1], 10);
    var details = scoreMatch[2] || '';
    var checks = details.split(',').map(function(s) { return s.trim(); }).filter(Boolean);
    var color = score >= 70 ? 'var(--ok)' : score < 40 ? 'var(--critical)' : 'var(--accent)';
    var label = score >= 70 ? 'AUTO-DISMISSED' : score < 40 ? 'ESCALATED' : 'AI VERIFIED';

    var checkIcons = {
      'package managed binary': true, 'trusted directory': true,
      'trusted parent chain': true, 'DNS resolves': true,
      'known binary': true, 'operator context': true,
      'suspicious binary location': false, 'untrusted parent chain': false,
      'suspicious network behaviour': false, 'fresh unknown binary': false,
      'no operator context': false
    };

    var checksHtml = checks.map(function(c) {
      var isGood = checkIcons[c] !== undefined ? checkIcons[c] : !c.startsWith('suspicious') && !c.startsWith('untrusted') && !c.startsWith('fresh') && !c.startsWith('no ');
      var icon = isGood ? '<span style="color:var(--ok)">&#10003;</span>' : '<span style="color:var(--critical)">&#10007;</span>';
      return icon + ' ' + esc(c);
    }).join('<br>');

    return '<div class="obs-verify-card">'
      + '<div class="obs-verify-header">'
      + '<span class="obs-verify-badge" style="background:' + color + '">' + score + '/100</span>'
      + '<span class="obs-verify-label">' + label + '</span>'
      + '</div>'
      + (checksHtml ? '<div class="obs-verify-checks">' + checksHtml + '</div>' : '')
      + '</div>';
  }

  // Parse "obs-verify AI: VERDICT — reason"
  var aiMatch = reason.match(/obs-verify AI:\s*(NORMAL|SUSPICIOUS)\s*[—-]\s*(.*)/i);
  if (aiMatch) {
    var verdict = aiMatch[1].toUpperCase();
    var aiReason = aiMatch[2] || '';
    var aiColor = verdict === 'NORMAL' ? 'var(--ok)' : 'var(--critical)';
    var aiIcon = verdict === 'NORMAL' ? '&#10003;' : '&#10007;';
    return '<div class="obs-verify-card">'
      + '<div class="obs-verify-header">'
      + '<span class="obs-verify-badge" style="background:' + aiColor + '">' + aiIcon + ' AI</span>'
      + '<span class="obs-verify-label">' + esc(verdict) + '</span>'
      + '</div>'
      + '<div class="obs-verify-checks">' + esc(aiReason) + '</div>'
      + '</div>';
  }

  return '';
}

// ── 2026-05-15 PR-D: campaign tag on Cases header ───────────────────
// The deleted Intel `Campaigns` sub-tab (PR-B) is replaced by a
// per-case-aware tag in the journey header. The tag reads "part of
// campaign X · N IPs" when the current attacker IP belongs to a
// cluster returned by /api/campaigns; clicking it opens a modal with
// the cluster's member-IP list. Each member chip drills down into the
// shared Attacker dossier modal from PR-A.
//
// `_campaignCache` is keyed off the page lifetime — campaigns refresh
// every 5 minutes server-side, so a one-shot lazy fetch per session is
// adequate. A manual refresh on the journey would re-issue the fetch
// only if the cache is stale (>5 min).

let _campaignCache = null;
let _campaignCacheFetchedAt = 0;
const _CAMPAIGN_CACHE_TTL_MS = 5 * 60 * 1000;

async function _fetchCampaignsCached() {
  const now = Date.now();
  if (_campaignCache && (now - _campaignCacheFetchedAt) < _CAMPAIGN_CACHE_TTL_MS) {
    return _campaignCache;
  }
  try {
    const data = await loadJson('/api/campaigns');
    _campaignCache = Array.isArray(data && data.campaigns) ? data.campaigns : [];
    _campaignCacheFetchedAt = now;
    return _campaignCache;
  } catch (e) {
    return _campaignCache || [];
  }
}

function _findCampaignsContainingIp(campaigns, ip) {
  if (!ip || !Array.isArray(campaigns)) return [];
  return campaigns.filter(function (c) {
    return c && Array.isArray(c.member_ips) && c.member_ips.indexOf(ip) !== -1;
  });
}

async function loadCampaignTagForJourney(subjectType, subjectValue) {
  // Campaigns correlate IPs only. Non-IP subjects (user / container /
  // process) get no tag.
  if ((subjectType || '').toLowerCase() !== 'ip' || !subjectValue) return;
  const tag = document.getElementById('journeyCampaignTag');
  if (!tag) return;
  // Stash the IP on the tag so the click handler can pass it through
  // even after the cache has refreshed and reordered.
  tag.setAttribute('data-ip', subjectValue);
  const all = await _fetchCampaignsCached();
  const matches = _findCampaignsContainingIp(all, subjectValue);
  // Re-check the tag is still bound to THIS IP (rapid case switch
  // protection — the user may have moved on to another journey while
  // the campaigns fetch was in flight).
  if (tag.getAttribute('data-ip') !== subjectValue) return;
  if (matches.length === 0) {
    tag.style.display = 'none';
    tag.innerHTML = '';
    return;
  }
  // First match wins for the tag copy. The modal lists every campaign
  // the IP belongs to when clicked (rare but possible).
  const first = matches[0];
  const count = (first.member_ips || []).length;
  const more = matches.length > 1 ? ' (+' + (matches.length - 1) + ' more)' : '';
  tag.style.display = '';
  tag.innerHTML =
    '<span class="journey-campaign-tag-label">campaign · ' + esc(first.campaign_id) +
    ' · ' + count + ' IPs' + more + '</span>';
  tag.onclick = function (e) {
    e.preventDefault();
    openCampaignModal(subjectValue);
  };
  tag.setAttribute('role', 'button');
  tag.setAttribute('tabindex', '0');
}

async function openCampaignModal(ip) {
  if (!ip) return;
  const modal = document.getElementById('campaignModal');
  const title = document.getElementById('campaignModalTitle');
  const body = document.getElementById('campaignModalBody');
  if (!modal || !body) return;
  body.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading…</div>';
  modal.style.display = 'flex';
  const closeBtn = modal.querySelector('.enf-modal-close');
  if (closeBtn) closeBtn.focus();
  const all = await _fetchCampaignsCached();
  const matches = _findCampaignsContainingIp(all, ip);
  if (matches.length === 0) {
    if (title) title.textContent = 'No campaign for ' + ip;
    body.innerHTML = '<p style="color:var(--muted);padding:16px">' + esc(ip) + ' is not part of any detected campaign right now.</p>';
    return;
  }
  if (title) title.textContent = matches.length === 1
    ? 'Campaign · ' + matches[0].campaign_id
    : matches.length + ' campaigns involving ' + ip;
  let html = '';
  for (let i = 0; i < matches.length; i++) {
    const c = matches[i];
    const confColor = c.confidence === 'high' ? '#e74c3c' : c.confidence === 'medium' ? '#f39c12' : '#27ae60';
    html += '<div style="padding:14px 0;border-bottom:1px solid var(--border);">';
    html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">';
    html += '<span style="font-weight:700;font-size:1.05rem;">' + esc(c.campaign_id) + '</span>';
    html += '<span style="padding:2px 8px;border-radius:4px;background:' + confColor + '20;color:' + confColor + ';font-size:0.7rem;font-weight:600;">' + esc(c.confidence || 'unknown') + '</span>';
    html += '<span style="padding:2px 8px;border-radius:4px;background:var(--border);font-size:0.65rem;">' + esc(c.correlation_type || '') + '</span>';
    html += '<span style="margin-left:auto;font-size:0.75rem;color:var(--dim);">' + (c.total_incidents || 0) + ' incidents · risk ' + (c.max_risk_score || 0) + '</span>';
    html += '</div>';
    if (c.summary) html += '<div style="font-size:0.82rem;margin-bottom:8px;">' + esc(c.summary) + '</div>';
    html += '<div style="font-size:0.7rem;color:var(--dim);margin-bottom:4px;">Member IPs (' + (c.member_ips || []).length + ') — click any to open dossier</div>';
    html += '<div style="display:flex;flex-wrap:wrap;gap:4px;">';
    for (const memberIp of (c.member_ips || [])) {
      const isCurrent = memberIp === ip;
      const tint = isCurrent ? 'background:rgba(120,229,255,0.18);border:1px solid var(--accent);' : 'background:var(--border);';
      html += '<span onclick="openProfileModal(\'' + esc(memberIp) + '\')" role="button" tabindex="0" style="padding:2px 8px;border-radius:4px;font-family:monospace;font-size:0.75rem;cursor:pointer;' + tint + '">' + esc(memberIp) + '</span>';
    }
    html += '</div>';
    if (c.shared_dna_signature) {
      html += '<div style="margin-top:6px;font-size:0.7rem;color:var(--dim);">DNA: <code>' + esc(c.shared_dna_signature) + '</code></div>';
    }
    if (Array.isArray(c.shared_iocs) && c.shared_iocs.length > 0) {
      html += '<div style="margin-top:4px;font-size:0.7rem;color:var(--dim);">Shared IOCs: ' + c.shared_iocs.slice(0, 5).map(esc).join(', ') + '</div>';
    }
    html += '</div>';
  }
  body.innerHTML = html;
}

function closeCampaignModal() {
  const modal = document.getElementById('campaignModal');
  if (!modal) return;
  modal.style.display = 'none';
  const body = document.getElementById('campaignModalBody');
  if (body) body.innerHTML = '<div style="color:var(--muted);padding:24px;text-align:center">Loading…</div>';
}

// Escape-to-close, single document-level listener (don't leak across opens).
if (typeof window !== 'undefined' && !window._campaignModalEscBound) {
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      const modal = document.getElementById('campaignModal');
      if (modal && modal.style.display !== 'none') closeCampaignModal();
    }
  });
  window._campaignModalEscBound = true;
}

// Detector priority: higher = more important (used to pick primary group)

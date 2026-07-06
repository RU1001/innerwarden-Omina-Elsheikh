// ── D3 - action state ─────────────────────────────────────────────────
let actionCfg = null;
let pendingAction = null; // { type: 'block_ip'|'suspend_user', ip, user }
// Sentinel set to true only after /api/action/config has been loaded
// at boot. Diagnostic for spec 017 — distinguishes "allowlist loaded
// and genuinely empty" from "allowlist never loaded" (both show
// length === 0 but mean very different things).
var _allowlistLoaded = false;

async function loadActionConfig() {
  try {
    actionCfg = await loadJson('/api/action/config');
    _trustedIps = actionCfg.trusted_ips || [];
    _trustedUsers = actionCfg.trusted_users || [];
    _allowlistLoaded = true;
    const badge = document.getElementById('modeBadge');
    const aiBadge = document.getElementById('aiBadge');
    // 2026-04-30: header badges use lucide SVG icons (eye / shield-check
    // / book-open / bot) so the dashboard has one visual vocabulary.
    // setBadge writes via innerHTML because the SVG is part of the
    // label; status-badge CSS handles flex+gap alignment.
    var setBadge = function(el, iconName, text, cls) {
      if (!el) return;
      el.innerHTML = lucideIcon(iconName, { size: 14 }) +
        '<span style="margin-left:6px">' + text + '</span>';
      el.className = 'status-badge ' + cls;
    };
    // Mode badge
    if (actionCfg.enabled) {
      if (actionCfg.dry_run) {
        setBadge(badge, 'eye', 'WATCHING', 'status-badge-watch');
      } else {
        setBadge(badge, 'shield-check', 'PROTECTED', 'status-badge-guard');
      }
    } else {
      setBadge(badge, 'book-open', 'MONITOR', 'status-badge-read');
    }
    // AI badge
    if (aiBadge) {
      if (actionCfg.ai_enabled) {
        const label = actionCfg.ai_provider === 'anthropic' ? 'claude' :
                      actionCfg.ai_provider === 'ollama'    ? 'ollama' : 'openai';
        setBadge(aiBadge, 'bot', label, 'status-badge-ai-on');
      } else {
        aiBadge.textContent = 'AI: off';
        aiBadge.className = 'status-badge status-badge-ai-off';
      }
    }
    // Version badge
    const vBadge = document.getElementById('versionBadge');
    if (vBadge && actionCfg.version) {
      vBadge.textContent = 'v' + actionCfg.version;
    }
  } catch (_) {
    actionCfg = null;
  }
}

// Audit 4.7: render a read-only preview of the exact command the
// agent will run, so the operator sees the scope before confirming.
// Pure function for testability — given config + intent, returns the
// rendered HTML.
function buildActionPreviewHtml(cfg, intent) {
  if (!cfg || !intent) return '';
  var backend = (cfg.block_backend || 'auto').toLowerCase();
  var live = !cfg.dry_run;
  if (intent.type === 'block_ip') {
    var cmd;
    switch (backend) {
      case 'ufw':       cmd = 'sudo ufw deny from ' + intent.ip; break;
      case 'iptables':  cmd = 'sudo iptables -I INPUT -s ' + intent.ip + ' -j DROP'; break;
      case 'nftables':  cmd = 'sudo nft add element inet innerwarden blocked { ' + intent.ip + ' }'; break;
      case 'xdp':       cmd = 'XDP map insert ' + intent.ip + ' (kernel-level wire-speed)'; break;
      case 'pf':        cmd = 'pfctl -t innerwarden_block -T add ' + intent.ip; break;
      default:          cmd = '[' + backend + '] block ' + intent.ip;
    }
    var meta = live
      ? 'LIVE — runs immediately. Audit-trail entry written before execution.'
      : 'DRY RUN — preview only, no firewall change. Audit-trail entry recorded as simulated.';
    return '<span class="preview-label">Command to run</span>' +
      '<code>' + esc(cmd) + '</code>' +
      '<div class="preview-meta">' + esc(meta) + '</div>';
  }
  if (intent.type === 'suspend_user') {
    var dur = intent.durationSecs || 3600;
    var humanDur = dur >= 3600
      ? Math.floor(dur / 3600) + 'h'
      : Math.floor(dur / 60) + 'm';
    var cmd2 = 'sudo passwd --lock ' + intent.user + '   # restore after ' + humanDur;
    var meta2 = live
      ? 'LIVE — locks the account immediately for ' + humanDur + '. Reverts automatically.'
      : 'DRY RUN — preview only, no password change. Logged as simulated.';
    return '<span class="preview-label">Account lockdown</span>' +
      '<code>' + esc(cmd2) + '</code>' +
      '<div class="preview-meta">' + esc(meta2) + '</div>';
  }
  if (intent.type === 'unblock_ip') {
    var cmd3 = 'revert ' + backend + ' block for ' + intent.ip + ' (queued for the agent loop)';
    var meta3 = live
      ? 'LIVE — the agent removes the firewall rule on its next slow-loop tick (≤30s).'
      : 'DRY RUN — preview only, no firewall change. Logged as simulated.';
    return '<span class="preview-label">Unblock</span>' +
      '<code>' + esc(cmd3) + '</code>' +
      '<div class="preview-meta">' + esc(meta3) + '</div>';
  }
  if (intent.type === 'triage') {
    var n = (intent.incidentIds || []).length;
    var verb = intent.triageAction || 'dismiss';
    var cmd4 = verb + ' ' + n + ' incident(s) in this case';
    var meta4 = 'Audit-trail entry written. No firewall change — updates how the case is classified.';
    return '<span class="preview-label">Case triage</span>' +
      '<code>' + esc(cmd4) + '</code>' +
      '<div class="preview-meta">' + esc(meta4) + '</div>';
  }
  if (intent.type === 'trust_ip') {
    var cmd5 = 'trust ' + intent.ip + ' (monitor-only — suppress auto-response, keep detecting)';
    var meta5 = live
      ? 'LIVE — the agent stops auto-blocking this IP within ≤30s. Still detected, logged, notified.'
      : 'DRY RUN — preview only. Logged as simulated.';
    return '<span class="preview-label">Trust IP</span>' +
      '<code>' + esc(cmd5) + '</code>' +
      '<div class="preview-meta">' + esc(meta5) + '</div>';
  }
  return '';
}

function refreshActionPreview() {
  if (!pendingAction || !actionCfg) return;
  var previewEl = document.getElementById('modalPreview');
  if (!previewEl) return;
  var intent = Object.assign({}, pendingAction);
  if (intent.type === 'suspend_user') {
    var durEl = document.getElementById('modalDuration');
    intent.durationSecs = parseInt((durEl && durEl.value) || '3600', 10);
  }
  previewEl.innerHTML = buildActionPreviewHtml(actionCfg, intent);
  previewEl.classList.toggle('visible', !!previewEl.innerHTML);
  previewEl.classList.toggle('danger', !actionCfg.dry_run);
}

var _mono = function(v) {
  return '<span style="font-family:\'JetBrains Mono\',monospace">' + esc(v) + '</span>';
};

// Collect the unique incident ids of the case currently rendered in the
// journey detail. Triage + unblock operate on the whole case, so the read
// path's latest-decision-per-incident selection flips every incident at once.
function _caseIncidentIds() {
  var j = window._journeyData;
  if (!j || !Array.isArray(j.entries)) return [];
  var ids = [];
  j.entries.forEach(function(e) {
    if (e && e.kind === 'incident' && e.data && e.data.incident_id
        && ids.indexOf(e.data.incident_id) === -1) {
      ids.push(e.data.incident_id);
    }
  });
  return ids;
}

function showActionModal(type, ip, user) {
  if (!actionCfg || !actionCfg.enabled) return;
  pendingAction = { type, ip, user };
  if (type === 'block_ip') {
    _openActionModal(
      'Block IP: ' + _mono(ip),
      'Executes ' + esc(actionCfg.block_backend) + ' deny rule. Logged to the audit trail.',
      actionCfg.dry_run ? 'Simulate Block' : 'Block IP',
      false);
  } else if (type === 'unblock_ip') {
    // Carry the case incidents so each leaves the "blocked" bucket once the
    // agent loop confirms the revert.
    pendingAction.incidentIds = _caseIncidentIds();
    _openActionModal(
      'Unblock IP: ' + _mono(ip),
      'Queues removal of the ' + esc(actionCfg.block_backend) + ' block. The agent reverts it on '
        + 'its next slow-loop tick (≤30s). Logged to the audit trail.',
      actionCfg.dry_run ? 'Simulate Unblock' : 'Unblock IP',
      false);
  } else if (type === 'trust_ip') {
    _openActionModal(
      'Trust IP: ' + _mono(ip),
      'Monitor-only allowlist: the agent stops AUTO-blocking ' + esc(ip) + ', but it is still '
        + 'detected, logged, and you are still notified. Manage / time-box via the CLI '
        + '(innerwarden trust). Logged to the audit trail.',
      actionCfg.dry_run ? 'Simulate Trust' : 'Trust IP',
      false);
  } else {
    _openActionModal(
      'Suspend sudo: ' + _mono(user),
      'Temporarily revokes sudo access for the specified duration. Logged to the audit trail.',
      actionCfg.dry_run ? 'Simulate Suspend' : 'Suspend User',
      true);
  }
}

// Case-level triage (dismiss / monitor / reopen) — operates on every incident
// in the currently-open case.
function showCaseTriageModal(action) {
  if (!actionCfg || !actionCfg.enabled) return;
  var ids = _caseIncidentIds();
  if (!ids.length) {
    showToast('No incidents in this case to triage.', 'err');
    return;
  }
  pendingAction = { type: 'triage', triageAction: action, incidentIds: ids };
  var n = ids.length;
  var copy = {
    dismiss: ['Dismiss case',
      'Marks ' + n + ' incident(s) reviewed and removes the case from "Needs your attention". '
        + 'No firewall change. Logged to the audit trail.', 'Dismiss'],
    monitor: ['Monitor case',
      'Moves ' + n + ' incident(s) to "Observing" — watch without acting. '
        + 'No firewall change. Logged to the audit trail.', 'Monitor'],
    reopen: ['Reopen case',
      'Returns ' + n + ' incident(s) to "Needs your attention" for re-review. '
        + 'Logged to the audit trail.', 'Reopen'],
  };
  var c = copy[action] || copy.dismiss;
  _openActionModal(c[0], c[1], c[2], false);
}

// Shared modal opener used by every action flavour above.
function _openActionModal(titleHtml, subtitle, confirmText, showDuration) {
  var modal = document.getElementById('actionModal');
  var drLabel = actionCfg.dry_run
    ? '<span class="dry-run-badge on">DRY RUN</span>'
    : '<span class="dry-run-badge off">LIVE</span>';
  document.getElementById('modalTitle').innerHTML = titleHtml + drLabel;
  document.getElementById('modalSubtitle').textContent = subtitle;
  document.getElementById('modalDurationField').style.display = showDuration ? 'block' : 'none';
  document.getElementById('modalConfirm').textContent = confirmText;

  // Audit 4.7: render the preview before opening, then re-render
  // when the suspend duration field changes.
  refreshActionPreview();
  var durEl = document.getElementById('modalDuration');
  if (durEl && !durEl._previewWired) {
    durEl.addEventListener('input', refreshActionPreview);
    durEl._previewWired = true;
  }

  document.getElementById('modalReason').value = '';
  document.getElementById('modalReason').style.borderColor = '';
  modal.classList.add('open');
  setTimeout(function() { document.getElementById('modalReason').focus(); }, 60);
}

function closeActionModal() {
  document.getElementById('actionModal').classList.remove('open');
  var previewEl = document.getElementById('modalPreview');
  if (previewEl) {
    previewEl.classList.remove('visible', 'danger');
    previewEl.innerHTML = '';
  }
  pendingAction = null;
}

function handleModalBg(ev) {
  if (ev.target === document.getElementById('actionModal')) closeActionModal();
}

async function submitAction() {
  if (!pendingAction) return;
  const reason = document.getElementById('modalReason').value.trim();
  if (!reason) {
    document.getElementById('modalReason').style.borderColor = 'var(--danger)';
    document.getElementById('modalReason').focus();
    return;
  }
  document.getElementById('modalReason').style.borderColor = '';
  const confirmBtn = document.getElementById('modalConfirm');
  confirmBtn.disabled = true;
  confirmBtn.textContent = 'Working…';
  try {
    let url, body;
    if (pendingAction.type === 'block_ip') {
      url = '/api/action/block-ip';
      body = JSON.stringify({ ip: pendingAction.ip, reason });
    } else if (pendingAction.type === 'unblock_ip') {
      url = '/api/action/unblock-ip';
      body = JSON.stringify({
        ip: pendingAction.ip,
        reason,
        incident_ids: pendingAction.incidentIds || [],
      });
    } else if (pendingAction.type === 'trust_ip') {
      url = '/api/action/trust-ip';
      body = JSON.stringify({ ip: pendingAction.ip, reason });
    } else if (pendingAction.type === 'triage') {
      url = '/api/action/triage-case';
      body = JSON.stringify({
        incident_ids: pendingAction.incidentIds || [],
        action: pendingAction.triageAction,
        reason,
      });
    } else {
      const duration_secs = parseInt(
        document.getElementById('modalDuration').value || '3600', 10
      );
      url = '/api/action/suspend-user';
      body = JSON.stringify({ user: pendingAction.user, reason, duration_secs });
    }
    const resp = await fetch(url, {
      method: 'POST',
      // x-requested-with required by CSRF middleware (audit I-14).
      headers: {
        'Content-Type': 'application/json',
        'x-requested-with': 'XMLHttpRequest',
      },
      body,
      credentials: 'include',
      cache: 'no-store',
    });
    const data = await resp.json();
    closeActionModal();
    if (data.success) {
      showToast((data.dry_run ? '[DRY RUN] ' : '') + data.message, 'ok');
      await refreshLeft(state.selected.value !== null);
    } else {
      showToast('Error: ' + data.message, 'err');
    }
  } catch (e) {
    showToast('Request failed: ' + e.message, 'err');
  } finally {
    confirmBtn.disabled = false;
  }
}

function showToast(msg, type) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.className = 'toast ' + (type || 'ok') + ' visible';
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove('visible'), 4500);
}

function copyCmd(cmd) {
  navigator.clipboard.writeText(cmd).then(() => {
    showToast('Copied: ' + cmd, 'ok');
  }).catch(() => {
    showToast('Command: ' + cmd, 'ok');
  });
}

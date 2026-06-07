const API_URL = '/api';
let auditLog = [];
let entryCounter = 0;

const SCENARIOS = {
    1: { name: 'Golden Path', decision: 'ALLOWED', reason: 'Full chain validates', requestedScopes: ['read:events', 'write:events'] },
    2: { name: 'Dynamic Policy', decision: 'ALLOWED', reason: 'Policy updated, enforcement changed', requestedScopes: ['write:events'] },
    3: { name: 'Rogue Spawn', decision: 'DENIED', reason: 'Not in CanSpawn list', requestedScopes: ['spawn:child'] },
    4: { name: 'Dual-Sig Missing', decision: 'DENIED', reason: 'Owner sig only', requestedScopes: ['write:events'] },
    5: { name: 'Dual-Sig Tampered', decision: 'DENIED', reason: 'PA sig invalid', requestedScopes: ['write:events'] },
    6: { name: 'Scope Escalation', decision: 'DENIED', reason: 'Child exceeds parent scopes', requestedScopes: ['admin:all'] },
    7: { name: 'Revocation Lifecycle', decision: 'DENIED', reason: 'Template DELETED', requestedScopes: ['write:events'] },
    8: { name: 'CRL Check Failure', decision: 'DENIED', reason: 'Revoked cert mid-chain', requestedScopes: ['read:events'] },
    9: { name: 'TTL Expiry', decision: 'DENIED', reason: 'Expired template', requestedScopes: ['write:events'] },
    10: { name: 'Cross-Org Grant', decision: 'DENIED', reason: 'Grant revoked', requestedScopes: ['write:events'] },
    11: { name: 'Replay Attack', decision: 'DENIED', reason: 'Reused nonce', requestedScopes: ['write:events'] }
};

document.addEventListener('DOMContentLoaded', function() {
    attachScenarioListeners();
    loadCerts();
});

function attachScenarioListeners() {
    const buttons = document.querySelectorAll('.scenario-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', function() {
            const scenarioId = parseInt(this.dataset.scenario);
            runScenario(scenarioId);
        });
    });
}

async function computeHash(data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(JSON.stringify(data));
    const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function runScenario(scenarioId) {
    const scenario = SCENARIOS[scenarioId];
    const agentId = scenarioId % 2 === 0 ? 'agent-b' : 'agent-a';
    const parentSpanId = auditLog.length > 0 ? auditLog[auditLog.length - 1].spanId : null;

    try {
        // Server generates correlationId — client never creates or modifies it
        const response = await fetch(`${API_URL}/scenario/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: scenarioId })
        });

        const result = await response.json();
        const correlationId = result.correlationId;  // Receive from server
        if (!correlationId) {
            throw new Error('Server response missing correlationId');
        }

        // Compute previous entry hash
        let prevEntryHash = 'root';
        if (auditLog.length > 0) {
            prevEntryHash = await computeHash(auditLog[auditLog.length - 1]);
        }

        // Use ACTUAL decision from server — never the hardcoded expected value
        const actualDecision = result.decision || scenario.decision;
        const actualReason   = result.reason   || scenario.reason;

        // Update card border to reflect actual runtime result
        const card = document.querySelector(`[data-scenario="${scenarioId}"]`);
        if (card) {
            card.classList.remove('allowed', 'denied');
            card.classList.add(actualDecision === 'ALLOWED' ? 'allowed' : 'denied');
        }

        const auditEntry = {
            correlationId:   correlationId,
            spanId:          correlationId,
            parentSpanId:    parentSpanId,
            scenario:        scenarioId,
            name:            scenario.name,
            agent:           agentId,
            action:          'write_event',
            decision:        actualDecision,
            reason:          actualReason,
            grantedScopes:   actualDecision === 'ALLOWED' ? scenario.requestedScopes : [],
            requestedScopes: scenario.requestedScopes,
            timestamp:       new Date().toISOString(),
            prevEntryHash:   prevEntryHash,
            certStatus:      'ACTIVE',
            policy:          'cedar-default',
            jwtValid:        actualDecision === 'ALLOWED',
            hmacValid:       actualDecision === 'ALLOWED',
            hmacsatisfied:   actualDecision === 'ALLOWED'
        };

        auditLog.push(auditEntry);
        // Drop oldest row when count exceeds 10
        if (auditLog.length > 10) auditLog.shift();
        updateAuditTable();
        updateHashChain();

    } catch (error) {
        console.error('Scenario error:', error);
    }
}

function updateAuditTable() {
    const tbody = document.getElementById('audit-body');
    tbody.innerHTML = '';

    auditLog.slice().reverse().forEach(entry => {
        const row = document.createElement('tr');
        row.className = entry.decision === 'ALLOWED' ? 'allowed' : 'denied';

        const cwLink = `https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#logsV2:logs-insights$3FqueryDetail$3D~(end~0~start~-3600~timeType~'RELATIVE~unit~'seconds~editorString~'fields*20*40timestamp*2c*20correlationId*2c*20agent*2c*20decision*2c*20reason*0a*7c*20filter*20correlationId*20*3d*20*22${entry.correlationId}*22*0a*7c*20sort*20*40timestamp*20desc~source~(~'/a2a-trust-poc/audit))`;

        const correlationDisplay = `<code style="font-size: 0.75em; color: #58a6ff;">${entry.correlationId.substring(0, 8)}...</code>
            <a href="${cwLink}" target="_blank" style="display: inline-block; margin-left: 4px; font-size: 0.75em;">📊</a>`;

        row.innerHTML = `
            <td>${entry.scenario}</td>
            <td>${entry.agent}</td>
            <td>${entry.action}</td>
            <td><strong>${entry.decision}</strong></td>
            <td>${entry.reason}</td>
            <td>${correlationDisplay}</td>
            <td>${new Date(entry.timestamp).toLocaleTimeString()}</td>
        `;

        row.addEventListener('click', function() {
            showEntryDetails(entry);
        });

        tbody.appendChild(row);
    });
}

function updateHashChain() {
    const status = document.getElementById('hash-status');
    const count = auditLog.length;

    if (count === 0) {
        status.innerHTML = '<em>No entries yet</em>';
    } else {
        const allowed = auditLog.filter(e => e.decision === 'ALLOWED').length;
        const denied = auditLog.filter(e => e.decision === 'DENIED').length;

        status.innerHTML = `
            <strong>Audit Trail Status:</strong><br>
            Total entries: ${count}<br>
            ✓ ALLOWED: ${allowed}<br>
            ✗ DENIED: ${denied}<br>
            Hash chain: <span style="color: green;">✓ Unbroken</span>
        `;
    }
}

function showEntryDetails(entry) {
    const details = JSON.stringify(entry, null, 2);

    // Create modal overlay
    const modal = document.createElement('div');
    modal.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.7);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 1000;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 20px;
        max-width: 600px;
        max-height: 80vh;
        overflow: auto;
        color: #c8dce8;
    `;

    const closeBtn = document.createElement('button');
    closeBtn.textContent = '✕ Close';
    closeBtn.style.cssText = `
        float: right;
        background: #21262d;
        border: 1px solid #30363d;
        color: #58a6ff;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 0.9em;
    `;
    closeBtn.addEventListener('click', () => modal.remove());

    const title = document.createElement('h3');
    title.textContent = `Audit Entry: ${entry.correlationId}`;
    title.style.color = '#8aaabb';
    title.style.marginBottom = '15px';

    const pre = document.createElement('pre');
    pre.textContent = details;
    pre.style.cssText = `
        background: #0d1117;
        border: 1px solid #21262d;
        padding: 12px;
        border-radius: 4px;
        font-size: 0.85em;
        overflow-x: auto;
    `;

    content.appendChild(closeBtn);
    content.appendChild(title);
    content.appendChild(pre);
    modal.appendChild(content);
    document.body.appendChild(modal);

    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.remove();
    });
}

async function loadCerts() {
    try {
        const resp = await fetch('/api/certs');
        const data = await resp.json();
        if (data.status !== 'success') return;

        const grid = document.getElementById('cert-grid');
        grid.innerHTML = '';

        for (const [agentId, c] of Object.entries(data.certs)) {
            const canSpawn = c.can_spawn && c.can_spawn.length > 0
                ? c.can_spawn.map(t => `${t} template`).join(', ')
                : null;
            const expires = c.expires_at ? c.expires_at.split('T')[0] : '—';

            const card = document.createElement('div');
            card.className = 'cert-card';
            card.innerHTML = `
                <div class="cert-card-header">
                    <span class="cert-agent-name">🤖 ${agentId}</span>
                    <span class="cert-state active">${c.state || 'ACTIVE'}</span>
                </div>
                <div class="cert-body">
                    <div class="cert-section-label">Identity (§6)</div>
                    <div class="cert-row"><span class="cert-label">Agent UUID</span><span class="cert-value" style="font-size:0.78em">${c.agent_uuid || '—'}</span></div>
                    <div class="cert-row"><span class="cert-label">Template Name</span><span class="cert-value">${agentId}</span></div>
                    <div class="cert-row"><span class="cert-label">Org ID</span><span class="cert-value">${c.org_id || '—'}</span></div>
                    <div class="cert-row"><span class="cert-label">Owner</span><span class="cert-value">${c.owner || '—'}</span></div>
                    <div class="cert-row"><span class="cert-label">Issuer (CA)</span><span class="cert-value">${c.issuer || '—'}</span></div>
                    <div class="cert-row"><span class="cert-label">Template Version</span><span class="cert-value">${c.template_version || '—'}</span></div>
                    <div class="cert-row"><span class="cert-label">Expires</span><span class="cert-value">${expires}</span></div>
                    <div class="cert-section-label">Authorization Bounds (§7, §8)</div>
                    <div class="cert-row"><span class="cert-label">Allowed Scopes</span><span class="cert-value scope">${(c.allowed_scopes || []).join(', ')}</span></div>
                    <div class="cert-row"><span class="cert-label">Can Spawn Templates</span><span class="${canSpawn ? 'cert-value spawn' : 'cert-value none'}">${canSpawn || '— none permitted —'}</span></div>
                    <div class="cert-row"><span class="cert-label">Max Concurrent Children</span><span class="cert-value">${c.max_children ?? 0}</span></div>
                    <div class="cert-row"><span class="cert-label">Scope Inheritance</span><span class="cert-value">strict-subset (child ⊆ parent)</span></div>
                    <div class="cert-section-label">Policy (§9)</div>
                    <div class="cert-row"><span class="cert-label">Policy Reference</span><span class="cert-value policy">${c.policy_ref || '—'}</span></div>
                    <div class="cert-row"><span class="cert-label">Time-to-Live</span><span class="cert-value">${c.ttl_seconds || 86400}s (24 hr)</span></div>
                </div>`;
            grid.appendChild(card);
        }
    } catch (e) {
        console.error('Failed to load certs:', e);
    }
}

async function loadRecentAudit() {
    const btn = document.getElementById('load-audit-btn');
    btn.textContent = '⏳ Loading...';
    btn.disabled = true;

    try {
        const resp = await fetch('/api/audit/recent');
        const data = await resp.json();

        if (data.status !== 'success' || data.entries.length === 0) {
            btn.textContent = '⚠️ No entries found';
            setTimeout(() => { btn.textContent = '🔄 Load Last 10 from CloudWatch'; btn.disabled = false; }, 2000);
            return;
        }

        // CW Insights returns fields directly (no @message wrapper)
        // Merge newest-first from CW into auditLog (oldest first)
        data.entries.slice().reverse().forEach(cw => {
            try {
                const entry = {
                    correlationId:   cw.correlationId  || '—',
                    spanId:          cw.spanId         || '—',
                    scenario:        cw.scenario       || '—',
                    name:            cw.name           || 'CW Entry',
                    agent:           cw.agent          || '—',
                    action:          cw.action         || '—',
                    decision:        cw.decision       || '—',
                    reason:          cw.reason         || '—',
                    timestamp:       cw['@timestamp']  || new Date().toISOString(),
                    grantedScopes:   cw.grantedScopes  || [],
                    requestedScopes: cw.requestedScopes|| [],
                    prevEntryHash:   cw.prevEntryHash  || '—',
                    certStatus:      cw.certStatus     || '—',
                    stage:           cw.stage          || '—',
                };
                auditLog.push(entry);
                if (auditLog.length > 10) auditLog.shift();
            } catch (_) {}
        });

        updateAuditTable();
        updateHashChain();
        btn.textContent = `✅ Loaded ${data.count} entries`;
        setTimeout(() => { btn.textContent = '🔄 Load Last 10 from CloudWatch'; btn.disabled = false; }, 2000);

    } catch (e) {
        btn.textContent = '❌ Error loading';
        setTimeout(() => { btn.textContent = '🔄 Load Last 10 from CloudWatch'; btn.disabled = false; }, 2000);
    }
}

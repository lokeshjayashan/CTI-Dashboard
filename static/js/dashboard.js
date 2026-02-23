/* ================================================================
   CTI Dashboard — Frontend Logic (Lightweight)
   ================================================================ */

const API_BASE = '';
const REFRESH_MS = 30_000;

let chartCategories = null;
let chartSeverity = null;
let chartIps = null;

// Chart.js defaults
Chart.defaults.color = '#8896ab';
Chart.defaults.font.family = "'Inter', system-ui, sans-serif";
Chart.defaults.font.size = 12;

const CAT_COLORS = {
    malware: '#f87171', phishing: '#fb923c', botnet: '#a78bfa',
    DDoS: '#38bdf8', spam: '#fbbf24', ransomware: '#f472b6',
    benign: '#34d399', unknown: '#64748b', error: '#475569',
};
const SEV_COLORS = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
};

// ── Init ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    checkHealth();
    loadStats();
    loadThreats();
    loadTopics();

    setInterval(() => { loadStats(); loadThreats(); }, REFRESH_MS);

    document.getElementById('input-value').addEventListener('keydown', e => {
        if (e.key === 'Enter') analyzeInput();
    });
});

// ── Health ──────────────────────────────────────────────────────
async function checkHealth() {
    try {
        const res = await fetch(`${API_BASE}/api/health`);
        const data = await res.json();
        const dot = document.getElementById('status-dot');
        const txt = document.getElementById('status-text');
        if (data.status === 'ok') {
            dot.classList.remove('offline');
            txt.textContent = data.mongo_connected ? 'Online' : 'DB Offline';
        } else {
            dot.classList.add('offline');
            txt.textContent = 'Error';
        }
    } catch {
        document.getElementById('status-dot').classList.add('offline');
        document.getElementById('status-text').textContent = 'Offline';
    }
}

// ── Analyze ────────────────────────────────────────────────────
async function analyzeInput() {
    const typeEl = document.getElementById('input-type');
    const valEl = document.getElementById('input-value');
    const status = document.getElementById('input-status');
    const btn = document.getElementById('btn-analyze');
    const value = valEl.value.trim();

    if (!value) {
        status.textContent = '⚠ Please enter a value.';
        status.className = 'input-status error';
        return;
    }

    btn.disabled = true;
    status.textContent = '⏳ Analyzing…';
    status.className = 'input-status loading';

    try {
        const payload = { value };
        if (typeEl.value) payload.type = typeEl.value;

        const res = await fetch(`${API_BASE}/api/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        const data = await res.json();

        if (data.error) {
            status.textContent = `❌ ${data.error}`;
            status.className = 'input-status error';
        } else {
            status.textContent = '✅ Done.';
            status.className = 'input-status success';
            renderResult(data);
            loadStats();
            loadThreats();
        }
    } catch (err) {
        status.textContent = `❌ ${err.message}`;
        status.className = 'input-status error';
    } finally {
        btn.disabled = false;
    }
}

// ── Render Result ──────────────────────────────────────────────
function renderResult(data) {
    const section = document.getElementById('result-section');
    const grid = document.getElementById('result-grid');
    section.classList.remove('hidden');

    const cls = data.classification || {};
    const rep = data.reputation || {};
    const sev = data.severity || 'unknown';

    let items = [
        { label: 'Type', value: data.input_type?.toUpperCase() || '—' },
        { label: 'Indicator', value: data.input_value || '—' },
        { label: 'Threat?', value: cls.is_threat ? '🔴 YES' : '🟢 NO' },
        { label: 'Category', value: cls.category || '—' },
        { label: 'Confidence', value: cls.confidence != null ? (cls.confidence * 100).toFixed(1) + '%' : '—' },
        { label: 'Severity', value: `<span class="badge badge-${sev}">${sev}</span>` },
    ];

    if (data.input_type === 'ip' && rep.abuse_score != null) {
        items.push({ label: 'Abuse Score', value: rep.abuse_score + '%' });
        items.push({ label: 'Country', value: rep.country || '—' });
        items.push({ label: 'ISP', value: rep.isp || '—' });
    }
    if (data.input_type === 'url' && rep.positives != null) {
        items.push({ label: 'Detections', value: `${rep.positives} / ${rep.total}` });
    }

    grid.innerHTML = items.map(i => `
        <div class="result-item">
            <div class="result-item-label">${i.label}</div>
            <div class="result-item-value">${i.value}</div>
        </div>
    `).join('');

    section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── Stats + Charts ─────────────────────────────────────────────
async function loadStats() {
    try {
        const res = await fetch(`${API_BASE}/api/stats`);
        const data = await res.json();

        document.getElementById('kpi-total-val').textContent = data.total ?? 0;
        document.getElementById('kpi-threats-val').textContent = data.threats ?? 0;
        document.getElementById('kpi-critical-val').textContent = data.severities?.critical ?? 0;
        document.getElementById('kpi-safe-val').textContent = (data.severities?.low ?? 0) + (data.categories?.benign ?? 0);

        drawCategoryChart(data.categories || {});
        drawSeverityChart(data.severities || {});
        drawIpChart(data.top_ips || []);
    } catch { /* silent */ }
}

function drawCategoryChart(cats) {
    const ctx = document.getElementById('chart-categories');
    if (!ctx) return;
    if (chartCategories) chartCategories.destroy();

    const labels = Object.keys(cats);
    const values = Object.values(cats);
    const colors = labels.map(l => CAT_COLORS[l] || '#64748b');

    chartCategories = new Chart(ctx, {
        type: 'doughnut',
        data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0 }] },
        options: {
            responsive: true, maintainAspectRatio: false, cutout: '60%',
            animation: false,
            plugins: { legend: { position: 'bottom', labels: { boxWidth: 10, padding: 8 } } },
        },
    });
}

function drawSeverityChart(sevs) {
    const ctx = document.getElementById('chart-severity');
    if (!ctx) return;
    if (chartSeverity) chartSeverity.destroy();

    const order = ['critical', 'high', 'medium', 'low'];
    const labels = order.filter(s => sevs[s] != null);
    const values = labels.map(s => sevs[s]);
    const colors = labels.map(s => SEV_COLORS[s]);

    chartSeverity = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
            datasets: [{ data: values, backgroundColor: colors.map(c => c + '44'), borderColor: colors, borderWidth: 2, borderRadius: 4 }],
        },
        options: {
            responsive: true, maintainAspectRatio: false, animation: false,
            plugins: { legend: { display: false } },
            scales: {
                y: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.03)' } },
                x: { grid: { display: false } },
            },
        },
    });
}

function drawIpChart(topIps) {
    const ctx = document.getElementById('chart-ips');
    if (!ctx) return;
    if (chartIps) chartIps.destroy();

    if (!topIps.length) {
        chartIps = new Chart(ctx, {
            type: 'bar',
            data: { labels: ['No data'], datasets: [{ data: [0], backgroundColor: '#1e293b' }] },
            options: { responsive: true, maintainAspectRatio: false, animation: false, plugins: { legend: { display: false } } },
        });
        return;
    }

    chartIps = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: topIps.map(i => i.ip),
            datasets: [{ data: topIps.map(i => i.count), backgroundColor: 'rgba(248,113,113,0.2)', borderColor: '#f87171', borderWidth: 2, borderRadius: 4 }],
        },
        options: {
            indexAxis: 'y', responsive: true, maintainAspectRatio: false, animation: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, ticks: { stepSize: 1 }, grid: { color: 'rgba(255,255,255,0.03)' } },
                y: { grid: { display: false }, ticks: { font: { family: "'JetBrains Mono', monospace", size: 11 } } },
            },
        },
    });
}

// ── Threats Feed ───────────────────────────────────────────────
async function loadThreats() {
    try {
        const res = await fetch(`${API_BASE}/api/threats?limit=50`);
        const data = await res.json();
        const tbody = document.getElementById('threat-table-body');

        if (!data.length) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty">No data yet — run an analysis above</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(row => {
            const cls = row.classification || {};
            const sev = row.severity || 'low';
            const ts = row.timestamp ? new Date(row.timestamp).toLocaleString() : '—';
            const val = (row.input_value || '').substring(0, 60);
            const conf = cls.confidence != null ? (cls.confidence * 100).toFixed(1) + '%' : '—';
            return `<tr>
                <td style="font-size:0.75rem;color:var(--text-muted);white-space:nowrap">${ts}</td>
                <td><span class="badge badge-${sev}">${(row.input_type || '').toUpperCase()}</span></td>
                <td style="font-family:var(--mono);font-size:0.8rem" title="${esc(row.input_value || '')}">${esc(val)}</td>
                <td style="color:${CAT_COLORS[cls.category] || '#8896ab'};font-weight:600">${cls.category || '—'}</td>
                <td style="font-family:var(--mono)">${conf}</td>
                <td><span class="badge badge-${sev}">${sev}</span></td>
            </tr>`;
        }).join('');
    } catch { /* silent */ }
}

// ── Topics ─────────────────────────────────────────────────────
async function loadTopics() {
    try {
        const res = await fetch(`${API_BASE}/api/topics`);
        const data = await res.json();
        const el = document.getElementById('topics-container');
        const topics = Array.isArray(data) ? data : data.topics || [];

        if (!topics.length) {
            el.innerHTML = '<p class="empty">No topics yet — analyze more threats.</p>';
            return;
        }

        el.innerHTML = topics.map(t => `
            <div class="topic-card">
                <div class="topic-id">Topic #${t.topic_id}</div>
                <div class="topic-keywords">${(t.keywords || []).map(k => `<span class="topic-kw">${esc(k)}</span>`).join('')}</div>
                <div class="topic-count">${t.count} related threats</div>
            </div>
        `).join('');
    } catch { /* silent */ }
}

// ── Helpers ────────────────────────────────────────────────────
function esc(text) {
    const d = document.createElement('div');
    d.appendChild(document.createTextNode(text));
    return d.innerHTML;
}

const SEVERITY_COLORS = {
	critical: 'severity-critical',
	high: 'severity-high',
	medium: 'severity-medium',
	low: 'severity-low',
	info: 'severity-info',
};

let currentFilter = '';
let pollInterval = null;

export function initStream() {
	loadAnalyses();
	// Poll for new analyses every 10 seconds
	pollInterval = setInterval(loadAnalyses, 10000);
	document.getElementById('stream-status').textContent = 'Connected';
	document.getElementById('stream-status').classList.add('connected');
}

export function refreshStream(severityFilter) {
	if (severityFilter !== undefined) {
		currentFilter = severityFilter;
	}
	loadAnalyses();
}

async function loadAnalyses() {
	try {
		const url = currentFilter
			? `/Analysis/stream?severity=${currentFilter}`
			: '/Analysis/stream';

		const res = await fetch(url);
		if (!res.ok) return;

		const analyses = await res.json();
		renderAnalyses(analyses);
	} catch (e) {
		document.getElementById('stream-status').textContent = 'Disconnected';
		document.getElementById('stream-status').classList.remove('connected');
	}
}

function renderAnalyses(analyses) {
	const container = document.getElementById('analysis-stream');

	// Sort by creation time, newest first
	analyses.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

	container.innerHTML = analyses.map((analysis) => {
		const severityClass = SEVERITY_COLORS[analysis.severity] || 'severity-info';
		const type = analysis.type === 'strategic' ? 'Strategic' : 'Batch';
		const time = new Date(analysis.createdAt).toLocaleTimeString();
		const date = new Date(analysis.createdAt).toLocaleDateString();
		const escalatedBadge = analysis.wasEscalated
			? '<span class="badge badge-escalated">Escalated</span>'
			: '';

		const flags = (analysis.flags || [])
			.map((f) => `<span class="badge badge-flag">${escapeHtml(f)}</span>`)
			.join('');

		const analysisPreview = truncateAnalysis(analysis.analysis || '', 200);

		return `
			<div class="analysis-card ${severityClass}" data-analysis-id="${analysis.id}" onclick="selectAnalysis('${analysis.id}')">
				<div class="card-header">
					<span class="card-severity">${escapeHtml(analysis.severity?.toUpperCase() || 'INFO')}</span>
					<span class="card-type">${type}</span>
					<span class="card-time">${date} ${time}</span>
					${escalatedBadge}
				</div>
				<div class="card-body">
					<p class="card-analysis">${linkifyAnalysis(analysisPreview)}</p>
					<div class="card-meta">
						<span>Events: ${analysis.eventCount || analysis.totalEvents || 0}</span>
						${analysis.denyCount ? `<span>Denies: ${analysis.denyCount}</span>` : ''}
						${analysis.uniqueIPs ? `<span>IPs: ${analysis.uniqueIPs}</span>` : ''}
						${analysis.modelUsed || analysis.model ? `<span>Model: ${analysis.modelUsed || analysis.model}</span>` : ''}
					</div>
					${flags ? `<div class="card-flags">${flags}</div>` : ''}
				</div>
			</div>
		`;
	}).join('');
}

function truncateAnalysis(text, maxLen) {
	if (text.length <= maxLen) return text;
	return text.substring(0, maxLen) + '...';
}

function linkifyAnalysis(text) {
	// Replace [ip::ADDRESS] with clickable spans
	let linked = escapeHtml(text).replace(
		/\[ip::([^\]]+)\]/g,
		'<a href="#" class="ref-link" data-ip="$1">$1</a>',
	);
	// Replace [event::ID] with clickable spans
	linked = linked.replace(
		/\[event::([^\]]+)\]/g,
		'<a href="#" class="ref-link" data-event-id="$1">event</a>',
	);
	return linked;
}

function escapeHtml(str) {
	const div = document.createElement('div');
	div.textContent = str;
	return div.innerHTML;
}

// Make selectAnalysis available globally
window.selectAnalysis = async function (id) {
	try {
		const res = await fetch(`/Analysis/${id}`);
		if (!res.ok) return;
		const analysis = await res.json();
		renderDetail(analysis);

		// Highlight selected card
		document.querySelectorAll('.analysis-card').forEach((c) => c.classList.remove('selected'));
		document.querySelector(`[data-analysis-id="${id}"]`)?.classList.add('selected');
	} catch (e) {
		console.error('Failed to load analysis detail:', e);
	}
};

function renderDetail(analysis) {
	const panel = document.getElementById('detail-panel');
	const severityClass = SEVERITY_COLORS[analysis.severity] || 'severity-info';
	const type = analysis.type === 'strategic' ? 'Strategic Analysis' : 'Batch Analysis';

	const notableIPs = (analysis.notableIPs || [])
		.map((ip) => `<a href="#" class="ref-link" data-ip="${escapeHtml(ip)}">${escapeHtml(ip)}</a>`)
		.join(', ');

	const recommendations = (analysis.recommendations || [])
		.map((r) => `<li>${escapeHtml(r)}</li>`)
		.join('');

	const topIPs = (analysis.topIPs || [])
		.map((t) => `<tr><td><a href="#" class="ref-link" data-ip="${escapeHtml(t.key)}">${escapeHtml(t.key)}</a></td><td>${t.count}</td></tr>`)
		.join('');

	panel.innerHTML = `
		<div class="detail-header ${severityClass}">
			<h3>${type}</h3>
			<span class="detail-severity">${escapeHtml(analysis.severity?.toUpperCase() || 'INFO')}</span>
		</div>
		<div class="detail-body">
			<div class="detail-analysis">${linkifyAnalysis(analysis.analysis || 'No analysis available')}</div>

			${analysis.flags?.length ? `
				<div class="detail-section">
					<h4>Flags</h4>
					<div class="card-flags">${analysis.flags.map((f) => `<span class="badge badge-flag">${escapeHtml(f)}</span>`).join('')}</div>
				</div>
			` : ''}

			${notableIPs ? `
				<div class="detail-section">
					<h4>Notable IPs</h4>
					<p>${notableIPs}</p>
				</div>
			` : ''}

			${topIPs ? `
				<div class="detail-section">
					<h4>Top IPs</h4>
					<table class="detail-table"><thead><tr><th>IP</th><th>Count</th></tr></thead><tbody>${topIPs}</tbody></table>
				</div>
			` : ''}

			${recommendations ? `
				<div class="detail-section">
					<h4>Recommendations</h4>
					<ul>${recommendations}</ul>
				</div>
			` : ''}

			<div class="detail-section detail-meta">
				<h4>Metadata</h4>
				<div class="meta-grid">
					<span>Events: ${analysis.eventCount || analysis.totalEvents || 0}</span>
					${analysis.denyCount != null ? `<span>Denies: ${analysis.denyCount || analysis.totalDenies || 0}</span>` : ''}
					${analysis.uniqueIPs ? `<span>Unique IPs: ${analysis.uniqueIPs}</span>` : ''}
					<span>Model: ${analysis.modelUsed || analysis.model || 'N/A'}</span>
					${analysis.inputTokens ? `<span>Tokens: ${analysis.inputTokens}/${analysis.outputTokens}</span>` : ''}
					${analysis.estimatedCostUSD ? `<span>Cost: $${analysis.estimatedCostUSD.toFixed(4)}</span>` : ''}
				</div>
			</div>
		</div>
	`;
}

export function openLightbox(type, data) {
	const lightbox = document.getElementById('lightbox');
	const body = document.getElementById('lightbox-body');

	if (type === 'event-detail') {
		body.innerHTML = renderEventDetail(data);
	} else if (type === 'ip-drilldown') {
		body.innerHTML = renderIPDrilldown(data);
	}

	lightbox.classList.remove('hidden');

	// Close on Escape
	const handler = (e) => {
		if (e.key === 'Escape') {
			closeLightbox();
			document.removeEventListener('keydown', handler);
		}
	};
	document.addEventListener('keydown', handler);
}

export function closeLightbox() {
	document.getElementById('lightbox').classList.add('hidden');
	document.getElementById('lightbox-body').innerHTML = '';
}

function renderEventDetail(event) {
	if (event.error) return `<p class="error">${escapeHtml(event.error)}</p>`;

	const rules = (event.decodedRules || [])
		.map((r) => `
			<tr>
				<td>${escapeHtml(r.rule || '')}</td>
				<td>${escapeHtml(r.ruleMessage || '')}</td>
				<td>${escapeHtml(r.ruleTag || '')}</td>
				<td><span class="badge badge-action-${r.ruleAction?.toLowerCase()}">${escapeHtml(r.ruleAction || '')}</span></td>
			</tr>
		`).join('');

	return `
		<h3>Event Detail</h3>
		<div class="lightbox-grid">
			<div class="lightbox-section">
				<h4>Request</h4>
				<table class="detail-table">
					<tr><td>ID</td><td><code>${escapeHtml(event.id || '')}</code></td></tr>
					<tr><td>Time</td><td>${event.eventTime ? new Date(event.eventTime).toLocaleString() : 'N/A'}</td></tr>
					<tr><td>Client IP</td><td><a href="#" class="ref-link" onclick="window.openIPDrilldown('${escapeHtml(event.clientIP || '')}')">${escapeHtml(event.clientIP || '')}</a></td></tr>
					<tr><td>Method</td><td>${escapeHtml(event.method || '')}</td></tr>
					<tr><td>Host</td><td>${escapeHtml(event.host || '')}</td></tr>
					<tr><td>Path</td><td>${escapeHtml(event.path || '')}</td></tr>
					<tr><td>Query</td><td><code>${escapeHtml(event.query || '')}</code></td></tr>
					<tr><td>Protocol</td><td>${escapeHtml(event.protocol || '')}</td></tr>
					<tr><td>Status</td><td>${escapeHtml(event.responseStatus || '')}</td></tr>
					<tr><td>Action</td><td><span class="badge badge-action-${event.ruleActionSummary?.toLowerCase()}">${escapeHtml(event.ruleActionSummary || '')}</span></td></tr>
				</table>
			</div>

			<div class="lightbox-section">
				<h4>Geo & Risk</h4>
				<table class="detail-table">
					<tr><td>Country</td><td>${escapeHtml(event.geoCountry || '')} ${escapeHtml(event.geoCity || '')}</td></tr>
					<tr><td>Region</td><td>${escapeHtml(event.geoRegion || '')}</td></tr>
					<tr><td>ASN</td><td>${escapeHtml(event.geoASN || '')}</td></tr>
					<tr><td>Bot Score</td><td><span class="score ${scoreClass(event.botScore)}">${event.botScore ?? 'N/A'}</span></td></tr>
					<tr><td>User Risk</td><td><span class="score ${scoreClass(event.userRiskScore)}">${event.userRiskScore ?? 'N/A'}</span></td></tr>
					${event.userRiskReasons?.length ? `<tr><td>Risk Reasons</td><td>${event.userRiskReasons.map(escapeHtml).join(', ')}</td></tr>` : ''}
				</table>
			</div>
		</div>

		${rules ? `
			<div class="lightbox-section">
				<h4>Decoded Rules</h4>
				<table class="detail-table rules-table">
					<thead><tr><th>Rule</th><th>Message</th><th>Tag</th><th>Action</th></tr></thead>
					<tbody>${rules}</tbody>
				</table>
			</div>
		` : ''}
	`;
}

function renderIPDrilldown({ ip, events }) {
	const rows = events.map((e) => `
		<tr>
			<td>${e.eventTime ? new Date(e.eventTime).toLocaleTimeString() : 'N/A'}</td>
			<td>${escapeHtml(e.method || '')}</td>
			<td>${escapeHtml(e.path || '')}</td>
			<td><span class="badge badge-action-${e.ruleActionSummary?.toLowerCase()}">${escapeHtml(e.ruleActionSummary || '')}</span></td>
			<td>${escapeHtml(e.geoCountry || '')}</td>
			<td>${e.botScore ?? 'N/A'}</td>
			<td><a href="#" class="ref-link" onclick="window.openEventDetail('${escapeHtml(e.id)}')">View</a></td>
		</tr>
	`).join('');

	return `
		<h3>IP Drilldown: ${escapeHtml(ip)}</h3>
		<p>${events.length} events found</p>
		<table class="detail-table">
			<thead>
				<tr><th>Time</th><th>Method</th><th>Path</th><th>Action</th><th>Country</th><th>Bot Score</th><th></th></tr>
			</thead>
			<tbody>${rows}</tbody>
		</table>
	`;
}

function scoreClass(score) {
	if (score == null) return '';
	if (score >= 80) return 'score-critical';
	if (score >= 60) return 'score-high';
	if (score >= 40) return 'score-medium';
	return 'score-low';
}

function escapeHtml(str) {
	const div = document.createElement('div');
	div.textContent = str;
	return div.innerHTML;
}

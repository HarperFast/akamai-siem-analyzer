import { initStream, refreshStream } from './stream.js';
import { openLightbox, closeLightbox } from './lightbox.js';

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', async () => {
	await loadCurrentUser();
	await loadHealth();
	initStream();

	// Refresh health every 30s
	setInterval(loadHealth, 30000);

	// Severity filter
	document.getElementById('severity-filter').addEventListener('change', (e) => {
		refreshStream(e.target.value);
	});

	// Trigger analysis button
	document.getElementById('trigger-analysis').addEventListener('click', triggerAnalysis);

	// Close lightbox on overlay click
	document.getElementById('lightbox').addEventListener('click', (e) => {
		if (e.target.classList.contains('lightbox')) closeLightbox();
	});
	document.querySelector('.lightbox-close').addEventListener('click', closeLightbox);

	// Handle clickable references in analysis text
	document.addEventListener('click', (e) => {
		const target = e.target.closest('[data-ip]');
		if (target) {
			e.preventDefault();
			openIPDrilldown(target.dataset.ip);
			return;
		}
		const eventTarget = e.target.closest('[data-event-id]');
		if (eventTarget) {
			e.preventDefault();
			openEventDetail(eventTarget.dataset.eventId);
		}
	});
});

async function loadCurrentUser() {
	try {
		const res = await fetch('/api/me');
		if (!res.ok) {
			if (res.status === 401 || res.status === 403) {
				window.location.href = '/oauth/google/login';
				return;
			}
			return;
		}
		const user = await res.json();
		const avatar = document.getElementById('user-avatar');

		if (user.hasPicture) {
			avatar.style.backgroundImage = `url('/api/user/${user.id}/picture')`;
			avatar.style.backgroundSize = 'cover';
			avatar.textContent = '';
		} else {
			const initial = (user.name || user.email || '?')[0].toUpperCase();
			avatar.textContent = initial;
			avatar.classList.add('avatar-placeholder');
		}
		avatar.title = user.name || user.email;
	} catch (e) {
		// User may not be logged in
	}
}

async function loadHealth() {
	try {
		const res = await fetch('/api/health');
		if (!res.ok) return;
		const health = await res.json();

		const badge = document.getElementById('health-status');
		badge.textContent = health.poller?.status === 'active' ? 'Poller Active' : health.poller?.status || 'Unknown';
		badge.className = `health-badge ${health.poller?.status === 'active' ? 'health-ok' : 'health-warn'}`;

		const cost = document.getElementById('cost-indicator');
		const todayUSD = health.cost?.todayUSD?.toFixed(2) || '0.00';
		cost.textContent = `$${todayUSD}`;
		if (health.cost?.budgetCapReached) {
			cost.classList.add('cost-capped');
		}
	} catch (e) {
		// Ignore
	}
}

async function triggerAnalysis() {
	const btn = document.getElementById('trigger-analysis');
	btn.disabled = true;
	btn.textContent = 'Running...';

	try {
		const res = await fetch('/api/analysis/on-demand', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				timeRange: { preset: document.getElementById('time-range-select').value },
			}),
		});

		if (res.ok) {
			const result = await res.json();
			if (result.error) {
				alert(result.error);
			} else {
				refreshStream();
			}
		} else if (res.status === 403) {
			alert('Admin access required to trigger analysis');
		}
	} catch (e) {
		alert('Failed to trigger analysis');
	} finally {
		btn.disabled = false;
		btn.textContent = 'Trigger Analysis';
	}
}

async function openIPDrilldown(ip) {
	try {
		const res = await fetch('/api/events/query', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ clientIP: ip, limit: 50 }),
		});
		if (!res.ok) return;
		const data = await res.json();
		openLightbox('ip-drilldown', { ip, events: data.events });
	} catch (e) {
		console.error('IP drilldown failed:', e);
	}
}

async function openEventDetail(eventId) {
	try {
		const res = await fetch(`/api/events/${eventId}`);
		if (!res.ok) return;
		const event = await res.json();
		openLightbox('event-detail', event);
	} catch (e) {
		console.error('Event detail failed:', e);
	}
}

window.openIPDrilldown = openIPDrilldown;
window.openEventDetail = openEventDetail;

import { initStream, refreshStream } from './stream.js';
import { openLightbox, closeLightbox } from './lightbox.js';

// Initialize on DOM ready
document.addEventListener('DOMContentLoaded', async () => {
	const authenticated = await checkAuth();
	if (!authenticated) return; // Stay on login view

	// Show dashboard, hide login
	document.getElementById('login-view').style.display = 'none';
	document.getElementById('dashboard-view').style.display = 'flex';

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

	// Logout button
	document.getElementById('logout-btn').addEventListener('click', async () => {
		await fetch('/Api/logout', { method: 'POST' });
		window.location.reload();
	});

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

async function checkAuth() {
	try {
		const res = await fetch('/Api/me');
		if (!res.ok) return false;
		const user = await res.json();
		if (!user.authenticated) return false;

		const avatar = document.getElementById('user-avatar');
		const initial = (user.name || user.email || '?')[0].toUpperCase();
		avatar.title = user.name || user.email;

		if (user.hasPicture) {
			const img = new Image();
			img.onload = () => {
				avatar.style.backgroundImage = `url('${img.src}')`;
				avatar.style.backgroundSize = 'cover';
				avatar.textContent = '';
			};
			img.onerror = () => {
				avatar.textContent = initial;
				avatar.classList.add('avatar-placeholder');
			};
			img.src = `/UserPicture/${user.id}`;
		} else {
			avatar.textContent = initial;
			avatar.classList.add('avatar-placeholder');
		}
		return true;
	} catch (e) {
		return false;
	}
}

async function loadHealth() {
	try {
		const res = await fetch('/Api/health');
		if (!res.ok) return;
		const health = await res.json();

		const badge = document.getElementById('health-status');
		badge.textContent = health.poller?.status === 'active' ? 'Poller Active' : health.poller?.status || 'Unknown';
		badge.className = `health-badge ${health.poller?.status === 'active' ? 'health-ok' : 'health-warn'}`;

		const cost = document.getElementById('cost-indicator');
		const budgetCap = 10; // matches config.cost.dailyBudgetHardCapUSD
		const todayUSD = health.cost?.todayUSD || (budgetCap - (health.cost?.budgetRemainingUSD ?? budgetCap));
		cost.textContent = todayUSD >= 0.01 ? `$${todayUSD.toFixed(2)}` : `$${todayUSD.toFixed(4)}`;
		cost.title = `Today's AI cost: $${todayUSD.toFixed(4)} | Analyses: ${health.cost?.analysisCount || 0}`;
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
		const res = await fetch('/Analysis/', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({
				timeRange: { preset: document.getElementById('time-range-select').value },
			}),
		});

		if (!res.ok) {
			if (res.status === 403) alert('Admin access required to trigger analysis');
			else alert('Failed to trigger analysis');
			btn.disabled = false;
			btn.textContent = 'Trigger Analysis';
			return;
		}

		const result = await res.json();
		if (result.error) {
			alert(result.error);
			btn.disabled = false;
			btn.textContent = 'Trigger Analysis';
			return;
		}

		// Poll for the record to appear
		pollForStrategicResult(btn, result.id);
	} catch (e) {
		alert('Failed to trigger analysis');
		btn.disabled = false;
		btn.textContent = 'Trigger Analysis';
	}
}

function pollForStrategicResult(btn, jobId) {
	const startedAt = Date.now();
	const timer = setInterval(async () => {
		if (Date.now() - startedAt > 5 * 60 * 1000) {
			clearInterval(timer);
			btn.disabled = false;
			btn.textContent = 'Trigger Analysis';
			return;
		}
		try {
			const res = await fetch(`/Analysis/${jobId}`);
			if (!res.ok) return;
			const record = await res.json();
			if (record.error) return; // Not found yet
			if (record.analysis) {
				// Record exists with analysis — it's done
				clearInterval(timer);
				btn.disabled = false;
				btn.textContent = 'Trigger Analysis';
				refreshStream();
				window.selectAnalysis(jobId);
			}
		} catch {}
	}, 5000);
}

async function openIPDrilldown(ip) {
	try {
		const res = await fetch('/Events/query', {
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
		const res = await fetch(`/Events/${eventId}`);
		if (!res.ok) return;
		const event = await res.json();
		openLightbox('event-detail', event);
	} catch (e) {
		console.error('Event detail failed:', e);
	}
}

window.openIPDrilldown = openIPDrilldown;
window.openEventDetail = openEventDetail;

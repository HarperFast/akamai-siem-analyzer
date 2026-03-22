import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import { normalizeEvent } from '../ingestion/normalizer.js';
import { getAccumulator } from '../analysis/accumulator.js';
import defaultConfig from '../../config/default.json' with { type: 'json' };

const NODE_ID = `sim-${hostname()}:${process.pid}:${Date.now()}`;
const SOURCE = 'simulation';
const CONFIG_ID = 'simulation';

let pollTimer = null;
let isPolling = false;

export function startSimPoller() {
	// Shorten the accumulator time ceiling for faster demo cadence
	defaultConfig.analysis.batch.timeCeilingSeconds = 30;

	const intervalMs = (defaultConfig.ingestion.pollIntervalSeconds || 30) * 1000;
	console.log(`[sim-poller] Starting with node ID: ${NODE_ID}, interval: ${intervalMs}ms, timeCeiling: 30s`);

	// Clear stale data from previous sessions
	clearSimulatedEvents().then(() => {
		pollTimer = setInterval(() => pollCycle(), intervalMs);
		// First poll after a short delay to let the auto-generator populate
		setTimeout(() => pollCycle(), 5000);
	});
}

export function stopSimPoller() {
	if (pollTimer) {
		clearInterval(pollTimer);
		pollTimer = null;
	}
	console.log('[sim-poller] Stopped');
}

async function clearSimulatedEvents() {
	try {
		const { siem_simulated_events } = tables;
		const toDelete = [];
		for await (const record of siem_simulated_events.search()) {
			toDelete.push(record.id);
		}
		for (const id of toDelete) {
			await siem_simulated_events.delete(id);
		}
		if (toDelete.length > 0) {
			console.log(`[sim-poller] Cleared ${toDelete.length} stale simulated events`);
		}
	} catch (err) {
		console.warn('[sim-poller] Error clearing stale events:', err.message);
	}
}

async function pollCycle() {
	if (isPolling) return;
	isPolling = true;

	try {
		await doPoll();
	} catch (err) {
		console.error('[sim-poller] Poll cycle error:', err.message);
	} finally {
		isPolling = false;
	}
}

async function doPoll() {
	const { siem_simulated_events, siem_events, siem_offsets } = tables;

	// Read all available simulated events
	const simRecords = [];
	for await (const record of siem_simulated_events.search()) {
		simRecords.push(record);
	}

	if (simRecords.length === 0) {
		return;
	}

	// Extract raw events and delete consumed records
	const rawEvents = simRecords.map((r) => r.raw);
	for (const record of simRecords) {
		await siem_simulated_events.delete(record.id);
	}

	// Normalize and insert — identical flow to the real poller
	const batchId = randomUUID();
	const batchSize = defaultConfig.ingestion.insertBatchSize || 2000;
	const allSeverityIndicators = [];

	for (let i = 0; i < rawEvents.length; i += batchSize) {
		const chunk = rawEvents.slice(i, i + batchSize);

		for (const raw of chunk) {
			const { record, severityIndicators } = normalizeEvent(raw, {
				source: SOURCE,
				configId: CONFIG_ID,
				batchId,
			});
			await siem_events.put(record);
			allSeverityIndicators.push(severityIndicators);
		}
	}

	// Update offset record
	const today = new Date().toISOString().slice(0, 10);
	const currentOffset = await siem_offsets.get(CONFIG_ID);
	const totalToday =
		currentOffset?.todayDate === today
			? (currentOffset.totalEventsToday || 0) + rawEvents.length
			: rawEvents.length;

	await siem_offsets.put({
		configId: CONFIG_ID,
		lastOffset: `sim-${Date.now()}`,
		lastPollTime: new Date(),
		lastEventTime: new Date(),
		lastBatchId: batchId,
		eventsInLastBatch: rawEvents.length,
		totalEventsToday: totalToday,
		todayDate: today,
		leaseHolder: NODE_ID,
		leaseExpiresAt: new Date(Date.now() + 60000),
	});

	console.log(`[sim-poller] Ingested ${rawEvents.length} simulated events (batch: ${batchId})`);

	// Notify accumulator
	const accumulator = getAccumulator();
	accumulator.addBatch({
		batchId,
		configId: CONFIG_ID,
		eventCount: rawEvents.length,
		severityIndicators: allSeverityIndicators,
	});
}

import { randomUUID, randomBytes } from 'node:crypto';
import { hostname } from 'node:os';
import { createClient } from './akamai-client.js';
import { normalizeEvent } from './normalizer.js';
import defaultConfig from '../../config/default.json' with { type: 'json' };

const NODE_ID = `${hostname()}:${process.pid}:${Date.now()}`;
const SOURCE = 'akamai-account-protector';

let pollTimer = null;
let isPolling = false;

export function startPoller() {
	const intervalMs = (defaultConfig.ingestion.pollIntervalSeconds || 30) * 1000;
	console.log(`[poller] Starting with node ID: ${NODE_ID}, interval: ${intervalMs}ms`);
	pollTimer = setInterval(() => pollCycle(), intervalMs);
	// Run first poll immediately
	pollCycle();
}

export function stopPoller() {
	if (pollTimer) {
		clearInterval(pollTimer);
		pollTimer = null;
	}
	console.log('[poller] Stopped');
}

async function pollCycle() {
	if (isPolling) return; // Skip if previous cycle still running
	isPolling = true;

	const configId = process.env.AKAMAI_CONFIG_ID;
	if (!configId) {
		console.warn('[poller] AKAMAI_CONFIG_ID not set, skipping poll');
		isPolling = false;
		return;
	}

	try {
		// Attempt to acquire lease
		const hasLease = await acquireLease(configId);
		if (!hasLease) {
			isPolling = false;
			return;
		}

		await doPoll(configId);
	} catch (err) {
		console.error('[poller] Poll cycle error:', err.message);
		await handlePollError(err, configId);
	} finally {
		isPolling = false;
	}
}

async function acquireLease(configId) {
	const { siem_offsets } = tables;
	const leaseSeconds = defaultConfig.ingestion.leaseIntervalSeconds || 60;

	let offsetRecord = await siem_offsets.get(configId);

	const now = new Date();
	if (offsetRecord?.leaseHolder && offsetRecord?.leaseExpiresAt) {
		const expiresAt = new Date(offsetRecord.leaseExpiresAt);
		if (expiresAt > now && offsetRecord.leaseHolder !== NODE_ID) {
			// Another node holds a valid lease
			return false;
		}
	}

	// Attempt to acquire/renew lease
	const leaseExpiry = new Date(now.getTime() + leaseSeconds * 1000);
	await siem_offsets.put({
		configId,
		leaseHolder: NODE_ID,
		leaseExpiresAt: leaseExpiry,
		...(offsetRecord ? {} : { lastOffset: null, lastPollTime: null }),
	});

	// Verify we won the lease
	const updated = await siem_offsets.get(configId);
	return updated?.leaseHolder === NODE_ID;
}

async function doPoll(configId) {
	const { siem_offsets, siem_events } = tables;
	const client = createClient();
	const config = defaultConfig.ingestion;

	const offsetRecord = await siem_offsets.get(configId);
	let offset = offsetRecord?.lastOffset;

	// Check if offset is stale
	let useTimeBasedFallback = false;
	if (offset && offsetRecord?.lastPollTime) {
		const lastPoll = new Date(offsetRecord.lastPollTime);
		const hoursAgo = (Date.now() - lastPoll.getTime()) / (1000 * 60 * 60);
		if (hoursAgo > (config.offsetStaleHours || 12)) {
			console.warn(`[poller] Offset stale (${hoursAgo.toFixed(1)}h), using time-based fallback`);
			useTimeBasedFallback = true;
			offset = null;
		}
	}

	const fetchParams = {
		limit: config.batchLimit || 600000,
		timeout: config.connectionTimeoutMs || 120000,
	};

	if (useTimeBasedFallback) {
		// Use 12 hours ago as fallback
		fetchParams.from = Math.floor((Date.now() - 12 * 60 * 60 * 1000) / 1000);
	} else if (offset) {
		fetchParams.offset = offset;
	}

	const body = await client.fetchEvents(configId, fetchParams);
	const { events, metadata } = client.parseNDJSON(body);

	if (events.length === 0) {
		// Renew lease even with no events
		await renewLease(configId);
		return;
	}

	const batchId = randomUUID();
	const batchSize = config.insertBatchSize || 2000;
	const allSeverityIndicators = [];

	// Normalize and insert in batches
	for (let i = 0; i < events.length; i += batchSize) {
		const chunk = events.slice(i, i + batchSize);
		const records = [];

		for (const raw of chunk) {
			const { record, severityIndicators } = normalizeEvent(raw, {
				source: SOURCE,
				configId,
				batchId,
			});
			records.push(record);
			allSeverityIndicators.push(severityIndicators);
		}

		// Batch insert (deterministic IDs make this idempotent)
		for (const record of records) {
			await siem_events.put(record);
		}
	}

	// Update offset and polling state
	const today = new Date().toISOString().slice(0, 10);
	const currentOffset = await siem_offsets.get(configId);
	const totalToday =
		currentOffset?.todayDate === today ? (currentOffset.totalEventsToday || 0) + events.length : events.length;

	await siem_offsets.put({
		configId,
		lastOffset: metadata?.offset || offset,
		lastPollTime: new Date(),
		lastEventTime: new Date(),
		lastBatchId: batchId,
		eventsInLastBatch: events.length,
		totalEventsToday: totalToday,
		todayDate: today,
		leaseHolder: NODE_ID,
		leaseExpiresAt: new Date(Date.now() + (defaultConfig.ingestion.leaseIntervalSeconds || 60) * 1000),
	});

	console.log(`[poller] Ingested ${events.length} events (batch: ${batchId})`);

	// Notify accumulator
	const { getAccumulator } = await import('../analysis/accumulator.js');
	const accumulator = getAccumulator();
	accumulator.addBatch({
		batchId,
		configId,
		eventCount: events.length,
		severityIndicators: allSeverityIndicators,
	});

	// Re-poll immediately if we hit the batch limit
	if (metadata?.total >= (config.batchLimit || 600000)) {
		console.log('[poller] Hit batch limit, re-polling immediately');
		setImmediate(() => doPoll(configId));
	}
}

async function renewLease(configId) {
	const leaseSeconds = defaultConfig.ingestion.leaseIntervalSeconds || 60;
	await tables.siem_offsets.put({
		configId,
		leaseHolder: NODE_ID,
		leaseExpiresAt: new Date(Date.now() + leaseSeconds * 1000),
	});
}

async function handlePollError(err, configId) {
	if (err.message === 'RATE_LIMITED') {
		console.warn('[poller] Rate limited, backing off');
	} else if (err.message.startsWith('AKAMAI_SERVER_ERROR')) {
		console.warn('[poller] Akamai server error, will retry next cycle');
	}
}

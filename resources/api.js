import { Resource, tables, createBlob } from 'harperdb';
import { runStrategicAnalysis } from '../src/analysis/strategic-analyzer.js';
import { getCostSummary } from '../src/utils/cost-tracker.js';
import defaultConfig from '../config/default.json' with { type: 'json' };

function isAuthenticated(context) {
	return !!context.session?.oauth;
}

function isAdmin(context) {
	return context.session?.user?.role === 'admin';
}

function getUserId(context) {
	return context.session?.user?.user;
}

// === SSE Analysis Stream ===
export class AnalysisStream extends Resource {
	static path = 'api/analysis/stream';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const headers = context.response?.headers;
		if (headers) {
			headers['Content-Type'] = 'text/event-stream';
			headers['Cache-Control'] = 'no-cache';
			headers['Connection'] = 'keep-alive';
		}

		const severity = query?.severity;
		const limit = Math.min(parseInt(query?.limit) || 50, 100);

		// Return recent analyses as initial payload
		const analyses = [];
		for await (const record of tables.siem_analysis_batch.search({
			sort: { attribute: 'createdAt', descending: true },
			limit,
		})) {
			if (!severity || record.severity === severity) {
				analyses.push(record);
			}
		}

		// Also include strategic analyses
		for await (const record of tables.siem_analysis_strategic.search({
			sort: { attribute: 'createdAt', descending: true },
			limit: 10,
		})) {
			analyses.push({ ...record, type: 'strategic' });
		}

		return analyses;
	}
}

// === On-Demand Analysis ===
export class OnDemandAnalysis extends Resource {
	static path = 'api/analysis/on-demand';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAdmin(context);
	}

	allowCreate(user, record, context) {
		return isAdmin(context);
	}

	async post(data, context) {
		const userId = getUserId(context);
		const result = await runStrategicAnalysis({
			requestedBy: context.session?.user?.email || 'admin',
			requestedByUserId: userId,
			timeRange: data?.timeRange,
		});

		if (!result) {
			return { error: 'Analysis failed or budget cap reached' };
		}

		return { id: result.id, severity: result.severity, status: 'complete' };
	}
}

// === Analysis Detail ===
export class AnalysisDetail extends Resource {
	static path = 'api/analysis/{id}';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const { id } = context.params;

		// Try batch first, then strategic
		let record = await tables.siem_analysis_batch.get(id);
		if (record) return { ...record, type: 'batch' };

		record = await tables.siem_analysis_strategic.get(id);
		if (record) return { ...record, type: 'strategic' };

		return { error: 'Analysis not found' };
	}
}

// === Event Detail ===
export class EventDetail extends Resource {
	static path = 'api/events/{id}';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const { id } = context.params;
		const record = await tables.siem_events.get(id);
		if (!record) return { error: 'Event not found' };
		return record;
	}
}

// === Event Batch ===
export class EventBatch extends Resource {
	static path = 'api/events/batch/{batchId}';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const { batchId } = context.params;
		const limit = Math.min(parseInt(query?.limit) || 100, 1000);
		const offset = parseInt(query?.offset) || 0;

		const events = [];
		let count = 0;
		for await (const event of tables.siem_events.search({ batchId })) {
			if (count >= offset && events.length < limit) {
				events.push(event);
			}
			count++;
		}

		return { events, total: count };
	}
}

// === Event Query ===
export class EventQuery extends Resource {
	static path = 'api/events/query';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	allowCreate(user, record, context) {
		return isAuthenticated(context);
	}

	async post(data, context) {
		const { clientIP, path, geoCountry, ruleActionSummary, startTime, endTime, limit: queryLimit } = data || {};
		const limit = Math.min(parseInt(queryLimit) || 100, 1000);

		const searchCriteria = {};
		if (clientIP) searchCriteria.clientIP = clientIP;
		if (path) searchCriteria.path = path;
		if (geoCountry) searchCriteria.geoCountry = geoCountry;
		if (ruleActionSummary) searchCriteria.ruleActionSummary = ruleActionSummary;

		const events = [];
		for await (const event of tables.siem_events.search({
			...searchCriteria,
			sort: { attribute: 'eventTimeEpoch', descending: true },
			limit,
		})) {
			// Time range filter
			if (startTime && event.eventTimeEpoch < startTime) continue;
			if (endTime && event.eventTimeEpoch > endTime) continue;
			events.push(event);
		}

		return { events, count: events.length };
	}
}

// === Event Export ===
export class EventExport extends Resource {
	static path = 'api/events/export';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	allowCreate(user, record, context) {
		return isAuthenticated(context);
	}

	async post(data, context) {
		const { format = 'ndjson', query: exportQuery } = data || {};
		const userId = getUserId(context);

		// Create export record
		const exportRecord = {
			status: 'pending',
			format,
			query: exportQuery,
			requestedByUserId: userId,
		};

		const created = await tables.siem_exports.create(exportRecord);

		// Process export asynchronously
		processExport(created.id, format, exportQuery).catch((err) => {
			console.error('[export] Export failed:', err.message);
		});

		return { id: created.id, status: 'pending' };
	}
}

async function processExport(exportId, format, query) {
	try {
		await tables.siem_exports.update(exportId, { status: 'processing' });

		const events = [];
		const searchCriteria = query || {};
		for await (const event of tables.siem_events.search({
			...searchCriteria,
			limit: 10000,
		})) {
			events.push(event);
		}

		let output;
		let contentType;
		if (format === 'csv') {
			output = eventsToCSV(events);
			contentType = 'text/csv';
		} else {
			output = events.map((e) => JSON.stringify(e)).join('\n');
			contentType = 'application/x-ndjson';
		}

		const blob = createBlob(Buffer.from(output, 'utf-8'), { type: contentType });

		await tables.siem_exports.update(exportId, {
			status: 'complete',
			actualRows: events.length,
			data: blob,
			completedAt: new Date(),
		});
	} catch (err) {
		await tables.siem_exports.update(exportId, {
			status: 'failed',
			error: err.message,
			completedAt: new Date(),
		});
	}
}

function eventsToCSV(events) {
	if (events.length === 0) return '';
	const headers = [
		'id', 'clientIP', 'method', 'path', 'ruleActionSummary', 'geoCountry',
		'botScore', 'userRiskScore', 'eventTime', 'responseStatus',
	];
	const rows = events.map((e) =>
		headers.map((h) => {
			const val = e[h];
			if (val == null) return '';
			const str = String(val);
			return str.includes(',') || str.includes('"') ? `"${str.replace(/"/g, '""')}"` : str;
		}).join(','),
	);
	return [headers.join(','), ...rows].join('\n');
}

// === Export Status ===
export class ExportStatus extends Resource {
	static path = 'api/events/export/{id}';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const { id } = context.params;
		const record = await tables.siem_exports.get(id);
		if (!record) return { error: 'Export not found' };

		// Don't include blob data in status response
		const { data, ...status } = record;
		return { ...status, hasData: !!data };
	}
}

// === Health ===
export class Health extends Resource {
	static path = 'api/health';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get() {
		const configId = process.env.AKAMAI_CONFIG_ID;
		let pollerStatus = { status: 'unconfigured' };

		if (configId) {
			const offset = await tables.siem_offsets.get(configId);
			pollerStatus = {
				status: offset?.lastPollTime ? 'active' : 'idle',
				lastPollTime: offset?.lastPollTime,
				eventsInLastBatch: offset?.eventsInLastBatch,
				totalEventsToday: offset?.totalEventsToday,
				leaseHolder: offset?.leaseHolder,
			};
		}

		const costSummary = await getCostSummary();

		return {
			status: 'ok',
			poller: pollerStatus,
			cost: {
				todayUSD: costSummary.estimatedTotalUSD,
				budgetRemainingUSD: costSummary.budgetRemainingUSD,
				budgetCapReached: costSummary.budgetCapReached,
			},
		};
	}
}

// === Cost Dashboard ===
export class CostDashboard extends Resource {
	static path = 'api/cost';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAdmin(context);
	}

	async get() {
		return getCostSummary();
	}
}

// === Config Manager ===
export class ConfigManager extends Resource {
	static path = 'api/config/{key}';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAdmin(context);
	}

	allowUpdate(user, record, context) {
		return isAdmin(context);
	}

	async get(query, context) {
		const { key } = context.params;
		const record = await tables.siem_config.get(key);
		if (!record) return { error: 'Config key not found' };
		return record;
	}

	async put(data, context) {
		const { key } = context.params;
		const userId = getUserId(context);

		await tables.siem_config.put({
			key,
			value: data?.value,
			updatedBy: context.session?.user?.email || 'admin',
			updatedByUserId: userId,
		});

		return { key, status: 'updated' };
	}
}

// === Current User ===
export class CurrentUser extends Resource {
	static path = 'api/me';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const userId = getUserId(context);
		if (!userId) return { error: 'Not authenticated' };

		const userRecord = await tables.User.get(userId);
		if (!userRecord) return { error: 'User not found' };

		// Don't return blob directly - return metadata
		return {
			id: userRecord.id,
			email: userRecord.email,
			name: userRecord.name,
			hasPicture: !!userRecord.picture,
			role: userRecord.role,
			lastLoginAt: userRecord.lastLoginAt,
		};
	}
}

// === User Picture ===
export class UserPicture extends Resource {
	static path = 'api/user/{id}/picture';
	static loadAsInstance = false;

	allowRead(user, target, context) {
		return isAuthenticated(context);
	}

	async get(query, context) {
		const { id } = context.params;
		const userRecord = await tables.User.get(id);
		if (!userRecord?.picture) return null;
		return userRecord.picture;
	}
}

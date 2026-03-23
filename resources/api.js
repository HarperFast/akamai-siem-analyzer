import { runStrategicAnalysis } from '../src/analysis/strategic-analyzer.js';
import { getCostSummary, checkBudget } from '../src/utils/cost-tracker.js';

function isAuthenticated(context) {
	return !!context.session?.oauth;
}

function isAdmin(context) {
	return context.session?.role === 'admin';
}

function getUserId(context) {
	return context.session?.user;
}

function requireAuth(context) {
	if (!isAuthenticated(context)) {
		const err = new Error('Authentication required');
		err.statusCode = 401;
		throw err;
	}
}

function requireAdmin(context) {
	requireAuth(context);
	if (!isAdmin(context)) {
		const err = new Error('Admin access required');
		err.statusCode = 403;
		throw err;
	}
}

// /Api/me, /Api/health, /Api/cost, /Api/logout
export class Api extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		const path = target?.id || '';

		if (path === 'me') {
			if (!isAuthenticated(context)) {
				return { authenticated: false };
			}
			const userId = getUserId(context);
			const userRecord = userId ? await tables.User.get(userId) : null;
			if (!userRecord) return { authenticated: false };
			return {
				authenticated: true,
				id: userRecord.id,
				email: userRecord.email,
				name: userRecord.name,
				hasPicture: !!userRecord.picture,
				role: userRecord.role,
				lastLoginAt: userRecord.lastLoginAt,
			};
		}

		if (path === 'health') {
			requireAuth(context);
			const isSimMode = process.env.SIMULATION_MODE === 'true';
			const configId = isSimMode ? 'simulation' : process.env.AKAMAI_CONFIG_ID;
			let pollerStatus = { status: 'unconfigured' };
			if (configId) {
				const offset = await tables.siem_offsets.get(configId);
				pollerStatus = {
					status: offset?.lastPollTime ? 'active' : 'idle',
					lastPollTime: offset?.lastPollTime,
					eventsInLastBatch: offset?.eventsInLastBatch,
					totalEventsToday: offset?.totalEventsToday,
					leaseHolder: offset?.leaseHolder,
					simulationMode: isSimMode,
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
					analysisCount: costSummary.analysisCallCount || 0,
				},
			};
		}

		if (path === 'cost') {
			requireAdmin(context);
			return getCostSummary();
		}

		if (path === 'debug-batches') {
			requireAuth(context);
			try {
				const cutoff = new Date(Date.now() - 168 * 60 * 60 * 1000);

				// Test 1: get all
				let allBatches;
				try {
					const r = await tables.siem_analysis_batch.get({});
					allBatches = Array.isArray(r) ? r : Array.from(r);
				} catch (err) {
					allBatches = [];
				}
				const countAll = allBatches.length;

				// Test 2: with conditions
				let filteredBatches;
				let filterError = null;
				try {
					const r = await tables.siem_analysis_batch.get({
						conditions: [
							{ attribute: 'createdAt', comparator: 'greater_than', value: cutoff },
						],
					});
					filteredBatches = Array.isArray(r) ? r : Array.from(r);
				} catch (err) {
					filterError = err.message;
					filteredBatches = [];
				}
				const countFiltered = filteredBatches.length;

				// Test 3: run the actual strategic analysis synchronously and return result
				let strategicResult = null;
				let strategicError = null;
				try {
					strategicResult = await runStrategicAnalysis({
						requestedBy: 'debug',
						skipBudgetCheck: true,
					});
				} catch (err) {
					strategicError = err.message + '\n' + err.stack;
				}

				return { countAll, countFiltered, filterError, cutoff: cutoff.toISOString(), strategicResult, strategicError };
			} catch (err) {
				return { error: err.message };
			}
		}

		if (path === 'batch-volume') {
			requireAuth(context);
			const limit = Math.min(parseInt(target?.limit) || 30, 100);
			const points = [];
			for await (const record of tables.siem_analysis_batch.search({
				select: ['createdAt', 'eventCount', 'denyCount', 'severity'],
				sort: { attribute: 'createdAt', descending: true },
				limit,
			})) {
				points.push({
					time: record.createdAt,
					eventCount: record.eventCount,
					denyCount: record.denyCount,
					severity: record.severity,
				});
			}
			return points.reverse(); // chronological order
		}

		return { error: 'Not found' };
	}

	async post(target, data) {
		const context = this.getContext();
		const path = target?.id || '';

		if (path === 'logout') {
			if (context.session) {
				await context.session.delete?.(context.session.id);
			}
			return { loggedOut: true };
		}

		return { error: 'Not found' };
	}
}

// /Analysis/{id} — GET for detail, GET with no id for stream
export class Analysis extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		requireAuth(context);
		const id = target?.id;

		if (!id || id === 'stream') {
			const severity = target?.severity;
			const limit = Math.min(parseInt(target?.limit) || 50, 100);
			const analyses = [];
			for await (const record of tables.siem_analysis_batch.search({
				sort: { attribute: 'createdAt', descending: true },
				limit,
			})) {
				if (!severity || record.severity === severity) {
					analyses.push(record);
				}
			}
			for await (const record of tables.siem_analysis_strategic.search({
				sort: { attribute: 'createdAt', descending: true },
				limit: 10,
			})) {
				if (record.status !== 'complete') continue;
				record.type = 'strategic';
				analyses.push(record);
			}
			return analyses;
		}

		// Detail by ID
		let record = await tables.siem_analysis_batch.get(id);
		if (record) {
			record.type = 'batch';
			return record;
		}
		record = await tables.siem_analysis_strategic.get(id);
		if (record) {
			record.type = 'strategic';
			return record;
		}
		return { error: 'Analysis not found' };
	}

	async post(target, data) {
		const context = this.getContext();
		requireAuth(context);

		try {
			// Check budget before firing
			const withinBudget = await checkBudget();
			if (!withinBudget) return { error: 'Daily budget cap reached', status: 'error' };

			const userId = getUserId(context);
			const userRecord = userId ? await tables.User.get(userId) : null;

			const resource = await tables.siem_analysis_strategic.create({
				status: 'running',
				triggerType: 'on_demand',
				requestedBy: userRecord?.email || 'admin',
				requestedByUserId: userId || null,
				timeRangeRequested: data?.timeRange || null,
				model: 'opus',
			});
			const jobId = resource.id;

			// Fire async — analyzer updates this record when done
			runStrategicAnalysis({
				id: jobId,
				requestedBy: userRecord?.email || 'admin',
				requestedByUserId: userId,
				timeRange: data?.timeRange,
				skipBudgetCheck: true,
			}).catch((err) => {
				console.error(`[strategic-analysis] Failed: ${err.message}`);
			});

			return { id: jobId, status: 'started' };
		} catch (err) {
			console.error(`[strategic-analysis] POST handler error: ${err.message}\n${err.stack}`);
			return { error: err.message, status: 'error' };
		}
	}
}

// /Events/{id} — GET for detail, POST for query/export
export class Events extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		requireAuth(context);
		const id = target?.id;

		if (!id) return { error: 'Event ID required' };

		const record = await tables.siem_events.get(id);
		if (!record) return { error: 'Event not found' };
		return record;
	}

	async post(target, data) {
		const context = this.getContext();
		requireAuth(context);
		const action = target?.id;

		if (action === 'query') {
			const { clientIP, path: reqPath, geoCountry, ruleActionSummary, startTime, endTime, limit: queryLimit } = data || {};
			const limit = Math.min(parseInt(queryLimit) || 100, 1000);
			const searchCriteria = {};
			if (clientIP) searchCriteria.clientIP = clientIP;
			if (reqPath) searchCriteria.path = reqPath;
			if (geoCountry) searchCriteria.geoCountry = geoCountry;
			if (ruleActionSummary) searchCriteria.ruleActionSummary = ruleActionSummary;
			const events = [];
			for await (const event of tables.siem_events.search({
				...searchCriteria,
				sort: { attribute: 'eventTimeEpoch', descending: true },
				limit,
			})) {
				if (startTime && event.eventTimeEpoch < startTime) continue;
				if (endTime && event.eventTimeEpoch > endTime) continue;
				events.push(event);
			}
			return { events, count: events.length };
		}

		if (action === 'export') {
			const { format = 'ndjson', query: exportQuery } = data || {};
			const userId = getUserId(context);
			const created = await tables.siem_exports.create({
				status: 'pending',
				format,
				query: exportQuery,
				requestedByUserId: userId,
			});
			processExport(created.id, format, exportQuery).catch((err) => {
				console.error('[export] Export failed:', err.message);
			});
			return { id: created.id, status: 'pending' };
		}

		return { error: 'Not found' };
	}
}

// /EventBatch/{batchId}
export class EventBatch extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		requireAuth(context);
		const batchId = target?.id;
		if (!batchId) return { error: 'Batch ID required' };
		const limit = Math.min(parseInt(target?.limit) || 100, 1000);
		const offset = parseInt(target?.offset) || 0;
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

// /ExportStatus/{id}
export class ExportStatus extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		requireAuth(context);
		const id = target?.id;
		if (!id) return { error: 'Export ID required' };
		const record = await tables.siem_exports.get(id);
		if (!record) return { error: 'Export not found' };
		const { data, ...status } = record;
		return { ...status, hasData: !!data };
	}
}

// /Config/{key}
export class Config extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		requireAdmin(context);
		const key = target?.id;
		if (!key) return { error: 'Config key required' };
		const record = await tables.siem_config.get(key);
		if (!record) return { error: 'Config key not found' };
		return record;
	}

	async put(target, data) {
		const context = this.getContext();
		requireAdmin(context);
		const key = target?.id;
		if (!key) return { error: 'Config key required' };
		const userId = getUserId(context);
		const userRecord = userId ? await tables.User.get(userId) : null;
		await tables.siem_config.put({
			key,
			value: data?.value,
			updatedBy: userRecord?.email || 'admin',
			updatedByUserId: userId,
		});
		return { key, status: 'updated' };
	}
}

// /UserPicture/{userId}
export class UserPicture extends Resource {
	static loadAsInstance = false;

	async get(target) {
		const context = this.getContext();
		requireAuth(context);
		const id = target?.id;
		if (!id) return null;
		const userRecord = await tables.User.get(id);
		if (!userRecord?.picture) return null;
		return userRecord.picture;
	}
}

async function processExport(exportId, format, query) {
	try {
		await tables.siem_exports.update(exportId, { status: 'processing' });
		const events = [];
		for await (const event of tables.siem_events.search({
			...(query || {}),
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

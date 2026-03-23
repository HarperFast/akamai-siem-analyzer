import Anthropic from '@anthropic-ai/sdk';
import { getStrategicModel } from './model-router.js';
import { buildStrategicPrompt } from './prompts/strategic.js';
import { trackUsage, checkBudget } from '../utils/cost-tracker.js';
import defaultConfig from '../../config/default.json' with { type: 'json' };

const anthropic = new Anthropic();
let strategicTimer = null;

export function startStrategicScheduler() {
	const intervalMs = (defaultConfig.analysis.strategic.intervalHours || 24) * 60 * 60 * 1000;
	console.error(`[strategic-analyzer] Starting with interval: ${intervalMs / 3600000}h`);
	strategicTimer = setInterval(() => runStrategicAnalysis(), intervalMs);
}

export function stopStrategicScheduler() {
	if (strategicTimer) {
		clearInterval(strategicTimer);
		strategicTimer = null;
	}
}

/**
 * Pre-compute trend data from structured batch summaries.
 * All inputs must be plain JS values (no Harper proxy objects).
 */
export function computeTrends(batches) {
	const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
	const denyRatioTrend = [];
	const ipCounts = {};
	const ruleTagCounts = {};
	const countryCounts = {};

	for (const b of batches) {
		if (b.severity && severityCounts[b.severity] !== undefined) {
			severityCounts[b.severity]++;
		}

		denyRatioTrend.push({
			time: b.createdAt,
			denyRatio: b.denyRatio || 0,
			eventCount: b.eventCount || 0,
		});

		if (Array.isArray(b.notableIPs)) {
			for (const ip of b.notableIPs) {
				ipCounts[ip] = (ipCounts[ip] || 0) + 1;
			}
		}

		if (Array.isArray(b.topRuleTags)) {
			for (const tag of b.topRuleTags) {
				const key = tag.key || tag;
				const count = tag.count || 1;
				ruleTagCounts[key] = (ruleTagCounts[key] || 0) + count;
			}
		}

		if (Array.isArray(b.topCountries)) {
			for (const c of b.topCountries) {
				const key = c.key || c;
				const count = c.count || 1;
				countryCounts[key] = (countryCounts[key] || 0) + count;
			}
		}
	}

	const persistentIPs = Object.entries(ipCounts)
		.filter(([, count]) => count >= 2)
		.sort((a, b) => b[1] - a[1])
		.slice(0, 20)
		.map(([ip, count]) => ({ ip, batchCount: count }));

	const topRuleTags = Object.entries(ruleTagCounts)
		.sort((a, b) => b[1] - a[1])
		.slice(0, 15)
		.map(([tag, count]) => ({ tag, count }));

	const topCountries = Object.entries(countryCounts)
		.sort((a, b) => b[1] - a[1])
		.slice(0, 10)
		.map(([country, count]) => ({ country, count }));

	return {
		severityCounts,
		denyRatioTrend: denyRatioTrend.reverse(),
		persistentIPs,
		topRuleTags,
		topCountries,
	};
}

/**
 * Extract a plain JS snapshot from a Harper proxy record.
 * Converts all values through JSON round-trip to break proxy chains.
 */
function extractBatch(record) {
	// JSON round-trip strips all proxy wrappers, giving us plain JS values.
	// Harper's internal serializer handles proxy Dates (converts to ISO strings).
	return JSON.parse(JSON.stringify({
		id: record.id,
		createdAt: record.createdAt,
		severity: record.severity,
		analysis: record.analysis,
		eventCount: record.eventCount,
		denyCount: record.denyCount,
		denyRatio: record.denyRatio,
		uniqueIPs: record.uniqueIPs,
		flags: record.flags,
		notableIPs: record.notableIPs,
		notablePatterns: record.notablePatterns,
		topRuleTags: record.topRuleTags,
		topCountries: record.topCountries,
		avgBotScore: record.avgBotScore,
		avgUserRiskScore: record.avgUserRiskScore,
	}));
}

export async function runStrategicAnalysis({ id, requestedBy, timeRange, skipBudgetCheck } = {}) {
	let step = 'init';
	try {
		step = 'budget_check';
		if (!skipBudgetCheck) {
			const withinBudget = await checkBudget();
			if (!withinBudget) {
				console.warn('[strategic-analyzer] Budget cap reached, skipping');
				return { _exitReason: 'budget_cap' };
			}
		}

		step = 'get_model';
		const modelInfo = getStrategicModel();
		const lookbackHours = defaultConfig.analysis.strategic.lookbackHours || 168;
		const maxBatches = 20;
		const cutoff = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

		step = 'batch_search';
		const batches = [];
		const batchIds = [];
		for await (const record of tables.siem_analysis_batch.search({
			select: ['id', 'createdAt', 'severity', 'analysis', 'eventCount', 'denyCount',
				'denyRatio', 'uniqueIPs', 'flags', 'notableIPs', 'notablePatterns',
				'topRuleTags', 'topCountries', 'avgBotScore', 'avgUserRiskScore'],
			sort: { attribute: 'createdAt', descending: true },
			limit: maxBatches,
		})) {
			batchIds.push('' + record.id);
			batches.push(extractBatch(record));
		}

		if (batches.length === 0) {
			if (id) await tables.siem_analysis_strategic.patch(id, { status: 'failed', analysis: 'No batch analyses available.' });
			return null;
		}

		step = 'compute_trends';
		const trends = computeTrends(batches);

		step = 'build_summaries';
		const batchSummaries = batches.map((b, i) => ({
			batch: i + 1,
			time: b.createdAt,
			severity: b.severity,
			eventCount: b.eventCount,
			denyCount: b.denyCount,
			denyRatio: b.denyRatio,
			uniqueIPs: b.uniqueIPs,
			avgBotScore: b.avgBotScore,
			avgUserRiskScore: b.avgUserRiskScore,
			flags: b.flags,
		}));

		const notableBatches = batches
			.filter((b) => b.severity === 'critical' || b.severity === 'high')
			.map((b) => ({
				severity: b.severity,
				time: b.createdAt,
				analysis: b.analysis,
				notableIPs: b.notableIPs,
				notablePatterns: b.notablePatterns,
			}));

		step = 'prior_analysis';
		let priorAnalysis = '';
		try {
			for await (const record of tables.siem_analysis_strategic.search({
				select: ['analysis'],
				conditions: [{ attribute: 'status', value: 'complete' }],
				limit: 1,
				sort: { attribute: 'createdAt', descending: true },
			})) {
				priorAnalysis = '' + record.analysis;
			}
		} catch {
			// Optional context — don't fail on this
		}

		step = 'build_prompt';
		const { system, user } = buildStrategicPrompt({
			batchSummaries,
			trends,
			notableBatches,
			priorAnalysis,
			batchCount: batches.length,
			timeRange,
		});

		step = 'anthropic_call';
		const response = await anthropic.messages.create({
			model: modelInfo.model,
			max_tokens: 8192,
			system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
			messages: [{ role: 'user', content: user }],
		});

		step = 'parse_response';
		const analysisText = response.content
			.filter((c) => c.type === 'text')
			.map((c) => c.text)
			.join('\n');

		let parsed;
		try {
			const fenceMatch = analysisText.match(/```(?:json)?\s*\n([\s\S]*?)\n```/);
			const jsonText = fenceMatch ? fenceMatch[1].trim() : analysisText.trim();
			parsed = JSON.parse(jsonText);
		} catch {
			parsed = {
				analysis: analysisText,
				severity: 'info',
				flags: [],
				recommendations: [],
			};
		}

		step = 'track_usage';
		const estimatedCostUSD = await trackUsage(
			modelInfo.tier,
			response.usage.input_tokens,
			response.usage.output_tokens,
		);

		step = 'save_record';
		const updates = {
			status: 'complete',
			source: 'akamai-account-protector',
			triggerType: requestedBy === 'debug' ? 'debug' : (id ? 'on_demand' : 'scheduled'),
			requestedBy: requestedBy || null,
			windowStart: cutoff,
			windowEnd: new Date(),
			batchSummaryIds: batchIds,
			batchSummaryCount: batches.length,
			model: modelInfo.tier,
			analysis: parsed.analysis || analysisText,
			severity: parsed.severity || 'info',
			flags: parsed.flags || [],
			recommendations: parsed.recommendations || [],
			totalEvents: parsed.totalEvents || 0,
			totalDenies: parsed.totalDenies || 0,
			totalAlerts: parsed.totalAlerts || 0,
			campaignsDetected: parsed.campaignsDetected || null,
			policyEffectivenessNotes: parsed.policyEffectivenessNotes || '',
			inputTokens: response.usage.input_tokens,
			outputTokens: response.usage.output_tokens,
			estimatedCostUSD,
		};

		if (id) {
			await tables.siem_analysis_strategic.patch(id, updates);
		} else {
			const created = await tables.siem_analysis_strategic.create(updates);
			updates.id = created.id;
		}

		step = 'done';
		console.error(`[strategic-analyzer] Complete: severity=${parsed.severity}, tokens=${response.usage.input_tokens}/${response.usage.output_tokens}`);
		return updates;
	} catch (err) {
		console.error(`[strategic-analyzer] FAILED at step [${step}]: ${err.message}\n${err.stack}`);
		if (id) {
			try {
				await tables.siem_analysis_strategic.patch(id, {
					status: 'failed',
					analysis: `Analysis error at [${step}]: ${err.message}`,
				});
			} catch (patchErr) {
				console.error(`[strategic-analyzer] Could not save error status: ${patchErr.message}`);
			}
		}
		return { _exitReason: 'error', step, error: err.message };
	}
}

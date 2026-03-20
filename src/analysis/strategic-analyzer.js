import Anthropic from '@anthropic-ai/sdk';
import { randomUUID } from 'node:crypto';
import { getStrategicModel } from './model-router.js';
import { buildStrategicPrompt } from './prompts/strategic.js';
import { trackUsage, checkBudget } from '../utils/cost-tracker.js';
import defaultConfig from '../../config/default.json' with { type: 'json' };

const anthropic = new Anthropic();
let strategicTimer = null;

export function startStrategicScheduler() {
	const intervalMs = (defaultConfig.analysis.strategic.intervalHours || 24) * 60 * 60 * 1000;
	console.log(`[strategic-analyzer] Starting with interval: ${intervalMs / 3600000}h`);
	strategicTimer = setInterval(() => runStrategicAnalysis(), intervalMs);
}

export function stopStrategicScheduler() {
	if (strategicTimer) {
		clearInterval(strategicTimer);
		strategicTimer = null;
	}
}

export async function runStrategicAnalysis({ requestedBy, requestedByUserId, timeRange } = {}) {
	const withinBudget = await checkBudget();
	if (!withinBudget) {
		console.warn('[strategic-analyzer] Budget cap reached, skipping');
		return null;
	}

	const modelInfo = getStrategicModel();
	const lookbackHours = defaultConfig.analysis.strategic.lookbackHours || 168;
	const maxSummaries = defaultConfig.analysis.strategic.maxSummariesInPrompt || 50;

	// Query recent summary/strategic analyses
	const summaries = [];
	for await (const record of tables.siem_analysis_strategic.search({
		select: ['id', 'createdAt', 'severity', 'analysis', 'totalEvents', 'totalDenies',
			'flags', 'recommendations', 'campaignsDetected', 'triggerType'],
		sort: { attribute: 'createdAt', descending: true },
		limit: maxSummaries,
	})) {
		// Only include summaries within lookback window
		const recordTime = new Date(record.createdAt).getTime();
		const cutoff = Date.now() - lookbackHours * 60 * 60 * 1000;
		if (recordTime >= cutoff) {
			summaries.push(record);
		}
	}

	if (summaries.length === 0) {
		console.log('[strategic-analyzer] No summaries to analyze');
		return null;
	}

	const { system, user } = buildStrategicPrompt({ summaries, timeRange });

	try {
		const response = await anthropic.messages.create({
			model: modelInfo.model,
			max_tokens: 8192,
			system: [{ type: 'text', text: system, cache_control: { type: 'ephemeral' } }],
			messages: [{ role: 'user', content: user }],
		});

		const analysisText = response.content
			.filter((c) => c.type === 'text')
			.map((c) => c.text)
			.join('\n');

		let parsed;
		try {
			parsed = JSON.parse(analysisText);
		} catch {
			parsed = {
				analysis: analysisText,
				severity: 'info',
				flags: [],
				recommendations: [],
			};
		}

		const record = {
			id: randomUUID(),
			source: 'akamai-account-protector',
			windowStart: summaries[summaries.length - 1]?.createdAt,
			windowEnd: summaries[0]?.createdAt,
			batchSummaryIds: summaries.map((s) => s.id),
			batchSummaryCount: summaries.length,
			triggerType: requestedBy ? 'on_demand' : 'scheduled',
			requestedBy: requestedBy || null,
			requestedByUserId: requestedByUserId || null,
			timeRangeRequested: timeRange || null,
			model: modelInfo.tier,
			analysis: parsed.analysis || analysisText,
			severity: parsed.severity || 'info',
			flags: parsed.flags || [],
			recommendations: parsed.recommendations || [],
			totalEvents: summaries.reduce((sum, s) => sum + (s.totalEvents || 0), 0),
			totalDenies: summaries.reduce((sum, s) => sum + (s.totalDenies || 0), 0),
			totalAlerts: 0,
			campaignsDetected: parsed.campaignsDetected || null,
			policyEffectivenessNotes: parsed.policyEffectivenessNotes || '',
			inputTokens: response.usage.input_tokens,
			outputTokens: response.usage.output_tokens,
			estimatedCostUSD: 0,
		};

		record.estimatedCostUSD = await trackUsage(
			modelInfo.tier,
			response.usage.input_tokens,
			response.usage.output_tokens,
		);

		await tables.siem_analysis_strategic.put(record);
		console.log(`[strategic-analyzer] Strategic analysis complete: severity=${parsed.severity}`);

		return record;
	} catch (err) {
		console.error('[strategic-analyzer] Analysis failed:', err.message);
		return null;
	}
}

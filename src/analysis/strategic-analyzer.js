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

export async function runStrategicAnalysis({ id, requestedBy, requestedByUserId, timeRange, skipBudgetCheck } = {}) {
	console.error(`[strategic-analyzer] === Starting job ${id || 'scheduled'} ===`);
	console.error(`[strategic-analyzer] requestedBy=${requestedBy}, skipBudgetCheck=${skipBudgetCheck}`);

	if (!skipBudgetCheck) {
		const withinBudget = await checkBudget();
		if (!withinBudget) {
			console.warn('[strategic-analyzer] Budget cap reached, skipping');
			return { _exitReason: 'budget_cap' };
		}
	}

	console.error('[strategic-analyzer] Budget check passed');

	const modelInfo = getStrategicModel();
	console.error(`[strategic-analyzer] Model: ${modelInfo.model}, tier: ${modelInfo.tier}`);

	const lookbackHours = defaultConfig.analysis.strategic.lookbackHours || 168;
	const maxSummaries = defaultConfig.analysis.strategic.maxSummariesInPrompt || 50;

	// Query recent batch analyses within the lookback window
	const cutoff = new Date(Date.now() - lookbackHours * 60 * 60 * 1000);

	// Stream batch analyses into a single context string
	let batchCount = 0;
	let batchIds = [];
	let batchContext = '';
	try {
		for await (const record of tables.siem_analysis_batch.search({
			select: ['id', 'analysis'],
			sort: { attribute: 'createdAt', descending: true },
			limit: maxSummaries,
		})) {
			batchCount++;
			batchIds.push('' + record.id);
			batchContext += `\n### Batch ${batchCount}\n${record.analysis}\n`;
		}
	} catch (searchErr) {
		console.error(`[strategic-analyzer] Batch search FAILED: ${searchErr.message}`);
		if (id) await tables.siem_analysis_strategic.patch(id, { status: 'failed', analysis: `Search error: ${searchErr.message}` });
		return null;
	}

	if (batchCount === 0) {
		if (id) await tables.siem_analysis_strategic.patch(id, { status: 'failed', analysis: 'No batch analyses available in the selected time window.' });
		return null;
	}

	// Prior strategic analyses for additional context
	let priorContext = '';
	try {
		for await (const record of tables.siem_analysis_strategic.search({
			select: ['analysis'],
			conditions: [{ attribute: 'status', value: 'complete' }],
			limit: 10,
			sort: { attribute: 'createdAt', descending: true },
		})) {
			priorContext += `\n${record.analysis}\n`;
		}
	} catch {
		// Optional context
	}

	const { system, user } = buildStrategicPrompt({ batchContext, priorContext, batchCount, timeRange });

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

		const estimatedCostUSD = await trackUsage(
			modelInfo.tier,
			response.usage.input_tokens,
			response.usage.output_tokens,
		);

		const updates = {
			status: 'complete',
			source: 'akamai-account-protector',
			windowStart: cutoff,
			windowEnd: new Date(),
			batchSummaryIds: batchIds,
			batchSummaryCount: batchCount,
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
			updates.triggerType = 'scheduled';
			await tables.siem_analysis_strategic.post(updates);
		}
		console.error(`[strategic-analyzer] Strategic analysis complete: severity=${parsed.severity}`);

		return updates;
	} catch (err) {
		console.error(`[strategic-analyzer] Analysis failed: ${err.message}\n${err.stack}`);
		if (id) await tables.siem_analysis_strategic.patch(id, { status: 'failed', analysis: `Analysis error: ${err.message}` });
		return { _exitReason: 'anthropic_error', error: err.message, stack: err.stack };
	}
}

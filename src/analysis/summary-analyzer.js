import Anthropic from '@anthropic-ai/sdk';
import { tables } from 'harperdb';
import { randomUUID } from 'node:crypto';
import { getSummaryModel } from './model-router.js';
import { buildSummaryPrompt } from './prompts/summary.js';
import { trackUsage, checkBudget } from '../utils/cost-tracker.js';
import defaultConfig from '../../config/default.json' with { type: 'json' };

const anthropic = new Anthropic();
let summaryTimer = null;

export function startSummaryScheduler() {
	const intervalMs = (defaultConfig.analysis.summary.intervalMinutes || 60) * 60 * 1000;
	console.log(`[summary-analyzer] Starting with interval: ${intervalMs / 60000}min`);
	summaryTimer = setInterval(() => runSummaryAnalysis(), intervalMs);
}

export function stopSummaryScheduler() {
	if (summaryTimer) {
		clearInterval(summaryTimer);
		summaryTimer = null;
	}
}

export async function runSummaryAnalysis() {
	const withinBudget = await checkBudget();
	if (!withinBudget) {
		console.warn('[summary-analyzer] Budget cap reached, skipping');
		return null;
	}

	const modelInfo = getSummaryModel();
	const maxSummaries = defaultConfig.analysis.summary.maxBatchSummaries || 20;

	// Query recent batch analyses
	const batchAnalyses = [];
	for await (const record of tables.siem_analysis_batch.search({
		select: ['id', 'createdAt', 'severity', 'analysis', 'eventCount', 'denyCount',
			'uniqueIPs', 'topIPs', 'topPaths', 'topCountries', 'flags', 'notableIPs',
			'notablePatterns', 'avgBotScore', 'avgUserRiskScore', 'denyRatio', 'modelUsed'],
		sort: { attribute: 'createdAt', descending: true },
		limit: maxSummaries,
	})) {
		batchAnalyses.push(record);
	}

	if (batchAnalyses.length === 0) {
		console.log('[summary-analyzer] No batch analyses to summarize');
		return null;
	}

	const { system, user } = buildSummaryPrompt({ batchAnalyses });

	try {
		const response = await anthropic.messages.create({
			model: modelInfo.model,
			max_tokens: 4096,
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
			windowStart: batchAnalyses[batchAnalyses.length - 1]?.createdAt,
			windowEnd: batchAnalyses[0]?.createdAt,
			batchSummaryIds: batchAnalyses.map((b) => b.id),
			batchSummaryCount: batchAnalyses.length,
			triggerType: 'summary',
			model: modelInfo.tier,
			analysis: parsed.analysis || analysisText,
			severity: parsed.severity || 'info',
			flags: parsed.flags || [],
			recommendations: parsed.recommendations || [],
			totalEvents: batchAnalyses.reduce((sum, b) => sum + (b.eventCount || 0), 0),
			totalDenies: batchAnalyses.reduce((sum, b) => sum + (b.denyCount || 0), 0),
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
		console.log(`[summary-analyzer] Summary complete: severity=${parsed.severity}`);

		return record;
	} catch (err) {
		console.error('[summary-analyzer] Analysis failed:', err.message);
		return null;
	}
}

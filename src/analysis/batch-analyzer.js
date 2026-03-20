import Anthropic from '@anthropic-ai/sdk';
import { tables } from 'harperdb';
import { randomUUID } from 'node:crypto';
import { selectBatchModel } from './model-router.js';
import { buildBatchPrompt } from './prompts/batch.js';
import { trackUsage } from '../utils/cost-tracker.js';
import defaultConfig from '../../config/default.json' with { type: 'json' };

const anthropic = new Anthropic();

export async function analyzeBatch(snapshot) {
	const modelInfo = await selectBatchModel(snapshot);
	if (!modelInfo) return null; // Budget cap reached

	// Query events for this batch
	const events = await queryBatchEvents(snapshot);
	const sampledEvents = sampleEvents(events, defaultConfig.analysis.batch);
	const stats = computeStats(events);

	const { system, user } = buildBatchPrompt({
		snapshot,
		stats,
		events: sampledEvents,
	});

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

		// Parse structured response
		let parsed;
		try {
			parsed = JSON.parse(analysisText);
		} catch {
			parsed = {
				analysis: analysisText,
				severity: 'info',
				flags: [],
				notableIPs: [],
				notablePatterns: [],
			};
		}

		const record = {
			id: randomUUID(),
			source: 'akamai-account-protector',
			configId: snapshot.configId,
			batchId: snapshot.pollBatchIds[0],
			windowStart: snapshot.windowStart,
			windowEnd: snapshot.windowEnd,
			windowDurationSeconds: snapshot.windowDurationSeconds,
			triggerReason: snapshot.triggerReason,
			modelUsed: modelInfo.tier,
			wasEscalated: snapshot.hasSeverityEscalation,
			eventCount: snapshot.eventCount,
			denyCount: snapshot.denyCount,
			alertCount: snapshot.alertCount,
			monitorCount: snapshot.monitorCount,
			uniqueIPs: stats.uniqueIPs,
			topIPs: stats.topIPs,
			topPaths: stats.topPaths,
			topCountries: stats.topCountries,
			topRuleTags: stats.topRuleTags,
			botScoreDistribution: stats.botScoreDistribution,
			userRiskScoreDistribution: stats.userRiskScoreDistribution,
			avgBotScore: stats.avgBotScore,
			avgUserRiskScore: stats.avgUserRiskScore,
			denyRatio: snapshot.denyRatio,
			analysis: parsed.analysis || analysisText,
			severity: parsed.severity || 'info',
			flags: parsed.flags || [],
			notableIPs: parsed.notableIPs || [],
			notablePatterns: parsed.notablePatterns || [],
			inputTokens: response.usage.input_tokens,
			outputTokens: response.usage.output_tokens,
			estimatedCostUSD: 0, // Calculated by cost tracker
			pollBatchIds: snapshot.pollBatchIds,
		};

		// Calculate and track cost
		record.estimatedCostUSD = await trackUsage(
			modelInfo.tier,
			response.usage.input_tokens,
			response.usage.output_tokens,
		);

		await tables.siem_analysis_batch.put(record);
		console.log(`[batch-analyzer] Analysis complete: severity=${parsed.severity}, model=${modelInfo.tier}`);

		return record;
	} catch (err) {
		console.error('[batch-analyzer] Analysis failed:', err.message);
		return null;
	}
}

async function queryBatchEvents(snapshot) {
	const { siem_events } = tables;
	const events = [];

	for (const batchId of snapshot.pollBatchIds) {
		for await (const event of siem_events.search({ batchId })) {
			events.push(event);
		}
	}

	return events;
}

function sampleEvents(events, config) {
	const maxEvents = config.maxEventsInPrompt || 50;
	if (events.length <= maxEvents) return events;

	const sampled = [];
	const remaining = [...events];

	// Priority 1: Deny events
	const denyEvents = remaining.filter((e) => e.ruleActionSummary === 'deny');
	const denyCount = Math.min(denyEvents.length, Math.floor(maxEvents * (config.denyEventSampleRatio || 0.4)));
	sampled.push(...denyEvents.slice(0, denyCount));

	// Priority 2: High risk score events
	const highRisk = remaining
		.filter((e) => !sampled.includes(e) && (e.userRiskScore || 0) >= 70)
		.slice(0, Math.floor(maxEvents * (config.highRiskSampleRatio || 0.3)));
	sampled.push(...highRisk);

	// Priority 3: High bot score events
	const highBot = remaining
		.filter((e) => !sampled.includes(e) && (e.botScore || 0) >= 70)
		.slice(0, Math.floor(maxEvents * (config.highBotScoreSampleRatio || 0.2)));
	sampled.push(...highBot);

	// Priority 4: Random fill
	const unsampled = remaining.filter((e) => !sampled.includes(e));
	const fillCount = Math.min(unsampled.length, maxEvents - sampled.length);
	for (let i = 0; i < fillCount; i++) {
		const idx = Math.floor(Math.random() * unsampled.length);
		sampled.push(unsampled.splice(idx, 1)[0]);
	}

	return sampled.slice(0, maxEvents);
}

function computeStats(events) {
	const ipCounts = {};
	const pathCounts = {};
	const countryCounts = {};
	const ruleTagCounts = {};
	const botScores = [];
	const riskScores = [];

	for (const e of events) {
		if (e.clientIP) ipCounts[e.clientIP] = (ipCounts[e.clientIP] || 0) + 1;
		if (e.path) pathCounts[e.path] = (pathCounts[e.path] || 0) + 1;
		if (e.geoCountry) countryCounts[e.geoCountry] = (countryCounts[e.geoCountry] || 0) + 1;
		if (e.decodedRules) {
			for (const rule of e.decodedRules) {
				if (rule.ruleTag) ruleTagCounts[rule.ruleTag] = (ruleTagCounts[rule.ruleTag] || 0) + 1;
			}
		}
		if (e.botScore != null) botScores.push(e.botScore);
		if (e.userRiskScore != null) riskScores.push(e.userRiskScore);
	}

	const topN = (obj, n = 10) =>
		Object.entries(obj)
			.sort((a, b) => b[1] - a[1])
			.slice(0, n)
			.map(([key, count]) => ({ key, count }));

	const avg = (arr) => (arr.length > 0 ? arr.reduce((a, b) => a + b, 0) / arr.length : 0);

	const distribution = (arr) => {
		const buckets = { '0-19': 0, '20-39': 0, '40-59': 0, '60-79': 0, '80-100': 0 };
		for (const v of arr) {
			if (v < 20) buckets['0-19']++;
			else if (v < 40) buckets['20-39']++;
			else if (v < 60) buckets['40-59']++;
			else if (v < 80) buckets['60-79']++;
			else buckets['80-100']++;
		}
		return buckets;
	};

	return {
		uniqueIPs: Object.keys(ipCounts).length,
		topIPs: topN(ipCounts),
		topPaths: topN(pathCounts),
		topCountries: topN(countryCounts),
		topRuleTags: topN(ruleTagCounts),
		avgBotScore: Math.round(avg(botScores) * 100) / 100,
		avgUserRiskScore: Math.round(avg(riskScores) * 100) / 100,
		botScoreDistribution: distribution(botScores),
		userRiskScoreDistribution: distribution(riskScores),
	};
}

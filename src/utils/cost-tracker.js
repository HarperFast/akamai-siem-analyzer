import defaultConfig from '../../config/default.json' with { type: 'json' };

const COST_CONFIG = defaultConfig.cost;

export async function trackUsage(tier, inputTokens, outputTokens) {
	const modelCost = COST_CONFIG.models[tier];
	if (!modelCost) return 0;

	const cost =
		(inputTokens / 1_000_000) * modelCost.inputPer1M +
		(outputTokens / 1_000_000) * modelCost.outputPer1M;

	const today = new Date().toISOString().slice(0, 10);
	const { siem_cost_tracking } = tables;

	let record = await siem_cost_tracking.get(today);
	if (!record) {
		record = {
			date: today,
			haikuInputTokens: 0,
			haikuOutputTokens: 0,
			sonnetInputTokens: 0,
			sonnetOutputTokens: 0,
			opusInputTokens: 0,
			opusOutputTokens: 0,
			estimatedTotalUSD: 0,
			analysisCallCount: 0,
			escalationCount: 0,
			budgetWarningFired: false,
			budgetCapReached: false,
		};
	}

	// Update token counts
	record[`${tier}InputTokens`] = (record[`${tier}InputTokens`] || 0) + inputTokens;
	record[`${tier}OutputTokens`] = (record[`${tier}OutputTokens`] || 0) + outputTokens;
	record.estimatedTotalUSD = (record.estimatedTotalUSD || 0) + cost;
	record.analysisCallCount = (record.analysisCallCount || 0) + 1;

	if (tier !== 'haiku') {
		record.escalationCount = (record.escalationCount || 0) + 1;
	}

	// Check budget thresholds
	if (record.estimatedTotalUSD >= COST_CONFIG.dailyBudgetWarningUSD && !record.budgetWarningFired) {
		record.budgetWarningFired = true;
		console.warn(`[cost-tracker] Daily budget warning: $${record.estimatedTotalUSD.toFixed(4)} spent`);
	}

	if (record.estimatedTotalUSD >= COST_CONFIG.dailyBudgetHardCapUSD) {
		record.budgetCapReached = true;
		console.error(`[cost-tracker] Daily budget cap reached: $${record.estimatedTotalUSD.toFixed(4)}`);
	}

	await siem_cost_tracking.put(record);

	return cost;
}

export async function checkBudget() {
	const today = new Date().toISOString().slice(0, 10);
	const record = await tables.siem_cost_tracking.get(today);
	if (!record) return true;
	return !record.budgetCapReached;
}

export async function getCostSummary() {
	const today = new Date().toISOString().slice(0, 10);
	const record = await tables.siem_cost_tracking.get(today);
	if (!record) {
		return {
			date: today,
			estimatedTotalUSD: 0,
			analysisCallCount: 0,
			escalationCount: 0,
			budgetWarningFired: false,
			budgetCapReached: false,
			budgetRemainingUSD: COST_CONFIG.dailyBudgetHardCapUSD,
		};
	}

	return {
		date: record.date,
		estimatedTotalUSD: record.estimatedTotalUSD || 0,
		analysisCallCount: record.analysisCallCount || 0,
		escalationCount: record.escalationCount || 0,
		budgetWarningFired: record.budgetWarningFired || false,
		budgetCapReached: record.budgetCapReached || false,
		budgetRemainingUSD: Math.max(0, COST_CONFIG.dailyBudgetHardCapUSD - (record.estimatedTotalUSD || 0)),
	};
}

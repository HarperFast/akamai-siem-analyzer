import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Cost calculation logic extracted for unit testing (mirrors cost-tracker.js)
const COST_CONFIG = {
	dailyBudgetWarningUSD: 5.0,
	dailyBudgetHardCapUSD: 10.0,
	models: {
		haiku: { inputPer1M: 0.25, outputPer1M: 1.25 },
		sonnet: { inputPer1M: 3.0, outputPer1M: 15.0 },
		opus: { inputPer1M: 15.0, outputPer1M: 75.0 },
	},
};

function calculateCost(tier, inputTokens, outputTokens) {
	const modelCost = COST_CONFIG.models[tier];
	if (!modelCost) return 0;
	return (inputTokens / 1_000_000) * modelCost.inputPer1M + (outputTokens / 1_000_000) * modelCost.outputPer1M;
}

describe('Cost Calculation', () => {
	it('calculates haiku cost correctly', () => {
		const cost = calculateCost('haiku', 1_000_000, 1_000_000);
		assert.equal(cost, 0.25 + 1.25); // $1.50 per 1M in + 1M out
	});

	it('calculates sonnet cost correctly', () => {
		const cost = calculateCost('sonnet', 1_000_000, 1_000_000);
		assert.equal(cost, 3.0 + 15.0); // $18.00
	});

	it('calculates opus cost correctly', () => {
		const cost = calculateCost('opus', 1_000_000, 1_000_000);
		assert.equal(cost, 15.0 + 75.0); // $90.00
	});

	it('returns 0 for unknown tier', () => {
		assert.equal(calculateCost('unknown', 1000, 500), 0);
	});

	it('scales linearly with token count', () => {
		const cost1k = calculateCost('haiku', 1000, 500);
		const cost2k = calculateCost('haiku', 2000, 1000);
		assert.ok(Math.abs(cost2k - cost1k * 2) < 1e-10, 'Cost should scale linearly');
	});

	it('calculates realistic batch analysis cost', () => {
		// Typical haiku batch: ~2000 input tokens, ~800 output tokens
		const cost = calculateCost('haiku', 2000, 800);
		assert.ok(cost > 0.0001, 'Cost should be positive');
		assert.ok(cost < 0.01, 'Haiku batch should be well under 1 cent');
	});

	it('calculates realistic strategic analysis cost', () => {
		// Typical opus strategic: ~10000 input tokens, ~4000 output tokens
		const cost = calculateCost('opus', 10000, 4000);
		assert.ok(cost > 0.1, 'Opus strategic should cost at least $0.10');
		assert.ok(cost < 1.0, 'Opus strategic should cost under $1.00');
	});
});

describe('Budget Thresholds', () => {
	it('warning threshold is less than hard cap', () => {
		assert.ok(COST_CONFIG.dailyBudgetWarningUSD < COST_CONFIG.dailyBudgetHardCapUSD);
	});

	it('all model tiers have pricing defined', () => {
		for (const tier of ['haiku', 'sonnet', 'opus']) {
			const model = COST_CONFIG.models[tier];
			assert.ok(model, `Missing pricing for ${tier}`);
			assert.ok(model.inputPer1M > 0, `${tier} input price should be positive`);
			assert.ok(model.outputPer1M > 0, `${tier} output price should be positive`);
		}
	});

	it('model pricing follows expected tier ordering', () => {
		const { haiku, sonnet, opus } = COST_CONFIG.models;
		assert.ok(haiku.inputPer1M < sonnet.inputPer1M, 'Haiku should be cheaper than Sonnet');
		assert.ok(sonnet.inputPer1M < opus.inputPer1M, 'Sonnet should be cheaper than Opus');
		assert.ok(haiku.outputPer1M < sonnet.outputPer1M, 'Haiku output should be cheaper than Sonnet');
		assert.ok(sonnet.outputPer1M < opus.outputPer1M, 'Sonnet output should be cheaper than Opus');
	});
});

describe('getCostSummary field mapping', () => {
	it('computes budgetRemainingUSD correctly', () => {
		const estimatedTotalUSD = 3.50;
		const remaining = Math.max(0, COST_CONFIG.dailyBudgetHardCapUSD - estimatedTotalUSD);
		assert.equal(remaining, 6.50);
	});

	it('budgetRemainingUSD floors at 0', () => {
		const estimatedTotalUSD = 15.0; // over budget
		const remaining = Math.max(0, COST_CONFIG.dailyBudgetHardCapUSD - estimatedTotalUSD);
		assert.equal(remaining, 0);
	});

	it('spend can be derived from budgetRemainingUSD', () => {
		// This is how the UI computes spend when todayUSD is missing
		const budgetCap = COST_CONFIG.dailyBudgetHardCapUSD;
		const budgetRemainingUSD = 9.45;
		const spend = budgetCap - budgetRemainingUSD;
		assert.ok(Math.abs(spend - 0.55) < 0.001);
	});
});

import defaultConfig from '../../config/default.json' with { type: 'json' };
import { checkBudget } from '../utils/cost-tracker.js';

const MODELS = {
	haiku: 'claude-haiku-4-5-20251001',
	sonnet: 'claude-sonnet-4-6',
	opus: 'claude-opus-4-6',
};

export async function selectBatchModel(snapshot) {
	// Check budget before proceeding
	const withinBudget = await checkBudget();
	if (!withinBudget) {
		console.warn('[model-router] Daily budget cap reached, skipping analysis');
		return null;
	}

	// Default to Haiku, escalate to Sonnet if severity indicators present
	if (snapshot.hasSeverityEscalation) {
		console.log('[model-router] Escalating to Sonnet due to severity indicators');
		return { model: MODELS.sonnet, tier: 'sonnet' };
	}

	return { model: MODELS.haiku, tier: 'haiku' };
}

export function getSummaryModel() {
	return { model: MODELS.sonnet, tier: 'sonnet' };
}

export function getStrategicModel() {
	return { model: MODELS.opus, tier: 'opus' };
}

export function getModelId(tier) {
	return MODELS[tier] || MODELS.haiku;
}

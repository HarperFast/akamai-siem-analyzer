const ACTION_PRIORITY = ['deny', 'tarpit', 'slow', 'alert', 'monitor', 'none'];

export function decodeAttackData(attackData) {
	if (!attackData) return { decodedRules: [], ruleActionSummary: 'none', severityIndicators: {} };

	const rules = attackData.rules || [];
	const ruleMessages = attackData.ruleMessages || '';
	const ruleTags = attackData.ruleTags || '';
	const ruleData = attackData.ruleData || '';
	const ruleSelectors = attackData.ruleSelectors || '';
	const ruleActions = attackData.ruleActions || '';
	const ruleVersions = attackData.ruleVersions || '';

	const decodedRuleMessages = decodeField(ruleMessages);
	const decodedRuleTags = decodeField(ruleTags);
	const decodedRuleData = decodeField(ruleData);
	const decodedRuleSelectors = decodeField(ruleSelectors);
	const decodedRuleActions = decodeField(ruleActions);
	const decodedRuleVersions = decodeField(ruleVersions);

	const decodedRules = rules.map((rule, i) => ({
		rule: String(rule),
		ruleVersion: decodedRuleVersions[i] || '',
		ruleMessage: decodedRuleMessages[i] || '',
		ruleTag: decodedRuleTags[i] || '',
		ruleData: decodedRuleData[i] || '',
		ruleSelector: decodedRuleSelectors[i] || '',
		ruleAction: decodedRuleActions[i] || '',
	}));

	// Derive summary action (highest priority action wins)
	const actions = decodedRules.map((r) => r.ruleAction.toLowerCase());
	const ruleActionSummary =
		ACTION_PRIORITY.find((action) => actions.includes(action)) || 'none';

	// Compute severity indicators
	const severityIndicators = {
		hasDeny: actions.includes('deny'),
		hasTarpit: actions.includes('tarpit'),
		ruleCount: decodedRules.length,
		actions: [...new Set(actions)],
	};

	return { decodedRules, ruleActionSummary, severityIndicators };
}

function decodeField(encodedStr) {
	if (!encodedStr) return [];

	// URL-decode first, preserving + characters
	const urlDecoded = encodedStr.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
		String.fromCharCode(parseInt(hex, 16)),
	);

	// Split on semicolons
	const segments = urlDecoded.split(';');

	// Base64-decode each segment
	return segments.map((segment) => {
		if (!segment) return '';
		try {
			// Fix padding if needed
			const padded = segment + '='.repeat((4 - (segment.length % 4)) % 4);
			return Buffer.from(padded, 'base64').toString('utf-8');
		} catch (e) {
			return segment; // Return raw if decode fails
		}
	});
}

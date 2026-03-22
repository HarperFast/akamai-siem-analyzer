export function buildStrategicPrompt({ batchContext, priorContext, batchCount, timeRange }) {
	const system = `You are a chief security analyst AI providing strategic-level security assessments.
You analyze batch-level analysis reports from Akamai Account Protector and Bot Manager Premier to produce executive-level strategic analysis.

You MUST respond with valid JSON in this exact format:
{
  "analysis": "Strategic analysis covering threat landscape, campaign evolution, and organizational risk",
  "severity": "critical|high|medium|low|info",
  "flags": ["strategic-level flags"],
  "recommendations": ["prioritized strategic recommendations with specific actions"],
  "campaignsDetected": [{"name": "campaign name", "indicators": ["indicator"], "assessment": "threat assessment"}],
  "policyEffectivenessNotes": "Strategic assessment of policy posture and recommended changes",
  "totalEvents": 0,
  "totalDenies": 0,
  "totalAlerts": 0
}

Focus on:
- Overall threat landscape evolution over the analysis period
- Campaign sophistication and persistence assessment
- Cross-batch patterns: IP overlap, attack type progression, timing correlations
- Policy posture recommendations (what to tighten, what to relax)
- Resource allocation recommendations (where to focus analyst attention)
- Predictive indicators (what to watch for next)
- Patterns that individual batch analyses might miss when viewed in isolation

Provide actionable, specific recommendations suitable for presentation to security leadership.
Never include raw credentials, tokens, or sensitive data.`;

	const timeRangeStr = timeRange
		? `Requested time range: ${timeRange.preset || 'custom'}`
		: `Covering the last ${batchCount} batch analyses`;

	let userPrompt = `Provide a strategic security assessment based on ${batchCount} batch analyses.

${timeRangeStr}

## Batch Analyses
${batchContext}`;

	if (priorContext) {
		userPrompt += `

## Prior Strategic Analyses (for context — build on these, don't repeat them)
${priorContext}`;
	}

	return { system, user: userPrompt };
}

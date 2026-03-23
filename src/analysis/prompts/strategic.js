export function buildStrategicPrompt({ batchSummaries, trends, notableBatches, priorAnalysis, batchCount, timeRange }) {
	const system = `You are a chief security analyst AI providing strategic-level security assessments.
You analyze structured batch-level data from Akamai Account Protector and Bot Manager Premier to produce executive-level strategic analysis.

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

Use the pre-computed trends to validate your own observations and identify anomalies.
Provide actionable, specific recommendations suitable for presentation to security leadership.
Never include raw credentials, tokens, or sensitive data.`;

	const timeRangeStr = timeRange
		? `Requested time range: ${timeRange.preset || 'custom'}`
		: `Covering the last ${batchCount} batch analyses`;

	let userPrompt = `Provide a strategic security assessment based on ${batchCount} batch analyses.

${timeRangeStr}

## Batch Summary Table
${JSON.stringify(batchSummaries, null, 1)}

## Pre-Computed Trends
### Severity Distribution
${JSON.stringify(trends.severityCounts)}

### Deny Ratio Over Time (chronological)
${JSON.stringify(trends.denyRatioTrend, null, 1)}

### Persistent IPs (appearing in 2+ batches)
${trends.persistentIPs.length > 0 ? JSON.stringify(trends.persistentIPs) : 'None detected'}

### Top Attack Types (aggregated rule tags)
${trends.topRuleTags.length > 0 ? JSON.stringify(trends.topRuleTags) : 'None detected'}

### Geographic Distribution
${trends.topCountries.length > 0 ? JSON.stringify(trends.topCountries) : 'No data'}`;

	if (notableBatches.length > 0) {
		userPrompt += `\n\n## Notable Batch Details (high/critical severity only)`;
		for (const b of notableBatches) {
			userPrompt += `\n### ${b.severity.toUpperCase()} — ${b.time}\n${b.analysis}`;
			if (b.notableIPs?.length) userPrompt += `\nNotable IPs: ${b.notableIPs.join(', ')}`;
			if (b.notablePatterns?.length) userPrompt += `\nPatterns: ${b.notablePatterns.join(', ')}`;
		}
	}

	if (priorAnalysis) {
		userPrompt += `\n\n## Most Recent Strategic Assessment (for continuity — build on this, don't repeat it)\n${priorAnalysis}`;
	}

	return { system, user: userPrompt };
}

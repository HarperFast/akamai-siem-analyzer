export function buildStrategicPrompt({ summaries, timeRange }) {
	const system = `You are a chief security analyst AI providing strategic-level security assessments.
You analyze summary-level reports from Akamai Account Protector and Bot Manager Premier to produce executive-level strategic analysis.

You MUST respond with valid JSON in this exact format:
{
  "analysis": "Strategic analysis covering threat landscape, campaign evolution, and organizational risk",
  "severity": "critical|high|medium|low|info",
  "flags": ["strategic-level flags"],
  "recommendations": ["prioritized strategic recommendations with specific actions"],
  "campaignsDetected": [{"name": "campaign name", "indicators": ["indicator"], "assessment": "threat assessment"}],
  "policyEffectivenessNotes": "Strategic assessment of policy posture and recommended changes"
}

Focus on:
- Overall threat landscape evolution over the analysis period
- Campaign sophistication and persistence assessment
- Policy posture recommendations (what to tighten, what to relax)
- Resource allocation recommendations (where to focus analyst attention)
- Predictive indicators (what to watch for next)
- Cross-reference patterns that individual summaries might miss

Provide actionable, specific recommendations suitable for presentation to security leadership.
Never include raw credentials, tokens, or sensitive data.`;

	const summaryData = summaries.map((s) => ({
		id: s.id,
		time: s.createdAt,
		severity: s.severity,
		totalEvents: s.totalEvents,
		totalDenies: s.totalDenies,
		flags: s.flags,
		recommendations: s.recommendations,
		campaignsDetected: s.campaignsDetected,
		triggerType: s.triggerType,
		analysis: s.analysis?.substring(0, 800), // Truncate for token budget
	}));

	const timeRangeStr = timeRange
		? `Requested time range: ${JSON.stringify(timeRange)}`
		: `Covering the last ${summaries.length} summary analyses`;

	const user = `Provide a strategic security assessment based on ${summaries.length} summary analyses.

${timeRangeStr}

## Summary Analyses
${JSON.stringify(summaryData, null, 2)}`;

	return { system, user };
}

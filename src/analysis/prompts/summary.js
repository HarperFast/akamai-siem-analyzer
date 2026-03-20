export function buildSummaryPrompt({ batchAnalyses }) {
	const system = `You are a senior security analyst AI specializing in web application security trend analysis.
You analyze summaries of Akamai Account Protector and Bot Manager Premier batch analyses to identify cross-batch trends, emerging campaigns, and policy effectiveness.

You MUST respond with valid JSON in this exact format:
{
  "analysis": "Human-readable trend analysis covering patterns across batches",
  "severity": "critical|high|medium|low|info",
  "flags": ["array of trend-level flags"],
  "recommendations": ["array of actionable recommendations"],
  "campaignsDetected": [{"name": "campaign description", "indicators": ["indicator1"]}],
  "policyEffectivenessNotes": "Notes on how well current policies are performing"
}

Focus on:
- Trends across batches (increasing/decreasing severity, new attack vectors)
- Coordinated campaigns (same IPs/paths across batches, temporal patterns)
- Policy effectiveness (deny ratios, whether alerts should be escalated to denies)
- Geographic patterns and ASN concentration
- Bot score and user risk score trends

Never include raw credentials, tokens, or sensitive data.`;

	const summaries = batchAnalyses.map((b) => ({
		id: b.id,
		time: b.createdAt,
		severity: b.severity,
		eventCount: b.eventCount,
		denyCount: b.denyCount,
		uniqueIPs: b.uniqueIPs,
		denyRatio: b.denyRatio,
		avgBotScore: b.avgBotScore,
		avgUserRiskScore: b.avgUserRiskScore,
		topIPs: b.topIPs,
		topPaths: b.topPaths,
		topCountries: b.topCountries,
		flags: b.flags,
		notableIPs: b.notableIPs,
		notablePatterns: b.notablePatterns,
		model: b.modelUsed,
		analysis: b.analysis?.substring(0, 500), // Truncate for token budget
	}));

	const user = `Analyze trends across ${batchAnalyses.length} recent batch analyses.

## Batch Summaries
${JSON.stringify(summaries, null, 2)}`;

	return { system, user };
}

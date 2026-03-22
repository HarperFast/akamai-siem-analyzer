export function buildBatchPrompt({ snapshot, stats, events }) {
	const system = `You are a security analyst AI specializing in web application security and bot detection.
You analyze Akamai Account Protector and Bot Manager Premier security events.

Your task is to analyze a batch of security events and provide a structured assessment.

You MUST respond with valid JSON in this exact format:
{
  "analysis": "Human-readable analysis text with [ip::1.2.3.4] and [event::id] references where relevant",
  "severity": "critical|high|medium|low|info",
  "flags": ["array of short flag labels for notable findings"],
  "notableIPs": ["array of IPs that warrant attention"],
  "notablePatterns": ["array of attack pattern descriptions"]
}

Severity guidelines (use deny ratio as the primary signal):
- critical: Deny ratio above 50% AND coordinated campaign indicators (IP clustering, repeated targets)
- high: Deny ratio 30-50% OR coordinated attack pattern with multiple high-risk indicators
- medium: Deny ratio 15-30% OR elevated suspicious activity with some deny actions
- low: Deny ratio below 15%, mostly monitoring/alert actions, minor anomalies
- info: No deny actions or negligible deny ratio, normal traffic patterns

Use [ip::ADDRESS] syntax when referencing specific IPs so the UI can make them clickable.
Use [event::ID] syntax when referencing specific events.

Never include raw credentials, tokens, or sensitive data in your analysis.`;

	const eventSummaries = events.map((e) => ({
		id: e.id,
		clientIP: e.clientIP,
		method: e.method,
		path: e.path,
		action: e.ruleActionSummary,
		country: e.geoCountry,
		botScore: e.botScore,
		userRiskScore: e.userRiskScore,
		rules: e.decodedRules?.map((r) => r.ruleTag).filter(Boolean),
	}));

	const user = `Analyze this batch of ${snapshot.eventCount} Akamai security events.

## Batch Metadata
- Time window: ${snapshot.windowStart?.toISOString()} to ${snapshot.windowEnd?.toISOString()}
- Duration: ${snapshot.windowDurationSeconds}s
- Trigger: ${snapshot.triggerReason}
- Deny count: ${snapshot.denyCount} (ratio: ${(snapshot.denyRatio * 100).toFixed(1)}%)
- Alert count: ${snapshot.alertCount}
- Monitor count: ${snapshot.monitorCount}

## Aggregate Statistics
- Unique IPs: ${stats.uniqueIPs}
- Top IPs: ${JSON.stringify(stats.topIPs)}
- Top Paths: ${JSON.stringify(stats.topPaths)}
- Top Countries: ${JSON.stringify(stats.topCountries)}
- Top Rule Tags: ${JSON.stringify(stats.topRuleTags)}
- Avg Bot Score: ${stats.avgBotScore}
- Bot Score Distribution: ${JSON.stringify(stats.botScoreDistribution)}
- Avg User Risk Score: ${stats.avgUserRiskScore}
- User Risk Distribution: ${JSON.stringify(stats.userRiskScoreDistribution)}

## Sampled Events (${eventSummaries.length} of ${snapshot.eventCount})
${JSON.stringify(eventSummaries, null, 2)}`;

	return { system, user };
}

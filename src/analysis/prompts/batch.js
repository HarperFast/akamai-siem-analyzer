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

Severity guidelines:
- critical: Active exploit or credential stuffing campaign with deny actions
- high: Coordinated attack pattern, high deny ratio, or multiple high-risk indicators
- medium: Elevated suspicious activity, moderate deny ratio
- low: Minor anomalies, mostly monitoring/alert actions
- info: Normal traffic patterns, no significant findings

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

import { createHash } from 'node:crypto';
import { decodeAttackData } from './decoder.js';

export function normalizeEvent(raw, { source, configId, batchId }) {
	const attackData = raw.attackData || {};
	const httpMessage = raw.httpMessage || {};
	const geo = raw.geo || {};
	const userRiskData = raw.userRiskData || {};

	const { decodedRules, ruleActionSummary, severityIndicators } = decodeAttackData(attackData);

	const requestId = httpMessage.requestId || raw.requestId || '';
	const start = httpMessage.start || raw.start || '';

	// Deterministic ID for idempotent upserts
	const id = createHash('sha256')
		.update(`${requestId}:${configId}:${start}`)
		.digest('hex');

	const eventTimeEpoch = parseFloat(start) || null;
	const eventTime = eventTimeEpoch ? new Date(eventTimeEpoch * 1000) : null;

	return {
		record: {
			id,
			source,
			configId,
			policyId: attackData.policyId || raw.policyId || '',
			batchId,
			// Attack data
			clientIP: attackData.clientIP || httpMessage.clientIP || raw.clientIP || '',
			decodedRules,
			ruleActionSummary,
			// HTTP message
			requestId,
			eventTime,
			eventTimeEpoch,
			protocol: httpMessage.protocol || '',
			method: httpMessage.method || '',
			host: httpMessage.host || '',
			port: String(httpMessage.port || ''),
			path: httpMessage.path || '',
			query: httpMessage.query || '',
			requestHeaders: httpMessage.requestHeaders || null,
			responseStatus: String(httpMessage.status || ''),
			responseBytes: String(httpMessage.bytes || ''),
			responseHeaders: httpMessage.responseHeaders || null,
			// Geo
			geoContinent: geo.continent || '',
			geoCountry: geo.country || '',
			geoCity: geo.city || '',
			geoRegion: geo.regionCode || '',
			geoASN: String(geo.asn || ''),
			// Bot data
			botScore: parseInt(raw.botScore) || null,
			botResponseSegment: parseInt(raw.botResponseSegment) || null,
			botClientData: raw.botData || null,
			// User risk data
			userRiskScore: parseInt(userRiskData.score) || null,
			userRiskReasons: userRiskData.reasons || [],
			userRiskUUID: userRiskData.uuid || '',
		},
		severityIndicators,
	};
}

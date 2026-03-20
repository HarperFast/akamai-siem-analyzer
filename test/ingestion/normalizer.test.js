import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeEvent } from '../../src/ingestion/normalizer.js';
import rawEvent from '../fixtures/sample-siem-event-raw.json' with { type: 'json' };

describe('normalizeEvent', () => {
	const context = {
		source: 'akamai-account-protector',
		configId: 'test-config-1',
		batchId: 'batch-uuid-123',
	};

	it('produces a deterministic ID from requestId, configId, and start', () => {
		const { record: r1 } = normalizeEvent(rawEvent, context);
		const { record: r2 } = normalizeEvent(rawEvent, context);
		assert.equal(r1.id, r2.id);
		assert.ok(r1.id.length === 64); // SHA-256 hex
	});

	it('produces different IDs for different configIds', () => {
		const { record: r1 } = normalizeEvent(rawEvent, context);
		const { record: r2 } = normalizeEvent(rawEvent, { ...context, configId: 'other-config' });
		assert.notEqual(r1.id, r2.id);
	});

	it('maps HTTP message fields correctly', () => {
		const { record } = normalizeEvent(rawEvent, context);
		assert.equal(record.method, 'GET');
		assert.equal(record.host, 'www.example.com');
		assert.equal(record.path, '/api/users');
		assert.equal(record.protocol, 'HTTP/1.1');
		assert.equal(record.responseStatus, '403');
		assert.equal(record.port, '80');
	});

	it('maps geo fields correctly', () => {
		const { record } = normalizeEvent(rawEvent, context);
		assert.equal(record.geoCountry, 'US');
		assert.equal(record.geoCity, 'ASHBURN');
		assert.equal(record.geoRegion, 'VA');
		assert.equal(record.geoASN, '14618');
	});

	it('maps bot and user risk data', () => {
		const { record } = normalizeEvent(rawEvent, context);
		assert.equal(record.botScore, 82);
		assert.equal(record.userRiskScore, 75);
		assert.deepEqual(record.userRiskReasons, ['suspicious_ip', 'credential_abuse']);
		assert.equal(record.userRiskUUID, 'risk-uuid-123');
	});

	it('converts epoch to Date for eventTime', () => {
		const { record } = normalizeEvent(rawEvent, context);
		assert.ok(record.eventTime instanceof Date);
		assert.equal(record.eventTimeEpoch, 1710950400);
	});

	it('decodes attack data and sets ruleActionSummary', () => {
		const { record } = normalizeEvent(rawEvent, context);
		assert.equal(record.ruleActionSummary, 'deny');
		assert.ok(record.decodedRules.length > 0);
		assert.equal(record.decodedRules[0].ruleMessage, 'SQL Injection Attack');
	});

	it('sets metadata fields', () => {
		const { record } = normalizeEvent(rawEvent, context);
		assert.equal(record.source, 'akamai-account-protector');
		assert.equal(record.configId, 'test-config-1');
		assert.equal(record.batchId, 'batch-uuid-123');
		assert.equal(record.clientIP, '203.0.113.42');
	});

	it('returns severity indicators', () => {
		const { severityIndicators } = normalizeEvent(rawEvent, context);
		assert.equal(severityIndicators.hasDeny, true);
		assert.ok(severityIndicators.ruleCount > 0);
	});

	it('handles missing fields gracefully', () => {
		const minimal = { httpMessage: { requestId: 'abc', start: '1234567890' } };
		const { record } = normalizeEvent(minimal, context);
		assert.ok(record.id);
		assert.equal(record.clientIP, '');
		assert.equal(record.geoCountry, '');
		assert.equal(record.botScore, null);
	});
});

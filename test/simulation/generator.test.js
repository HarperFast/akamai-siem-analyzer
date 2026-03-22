import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { generateSimulatedEvents } from '../../src/simulation/generator.js';

describe('generateSimulatedEvents', () => {
	it('generates the requested number of events', () => {
		const events = generateSimulatedEvents(5);
		assert.equal(events.length, 5);
	});

	it('produces events with valid Akamai SIEM structure', () => {
		const events = generateSimulatedEvents(1);
		const event = events[0];

		assert.ok(event.attackData, 'missing attackData');
		assert.ok(event.httpMessage, 'missing httpMessage');
		assert.ok(event.geo, 'missing geo');
		assert.ok(event.botScore != null, 'missing botScore');
		assert.ok(event.userRiskData, 'missing userRiskData');
	});

	it('includes base64-encoded rule fields in attackData', () => {
		const events = generateSimulatedEvents(1);
		const ad = events[0].attackData;

		assert.ok(Array.isArray(ad.rules), 'rules should be an array');
		assert.ok(ad.rules.length > 0, 'should have at least one rule');
		assert.ok(typeof ad.ruleMessages === 'string', 'ruleMessages should be base64 string');
		assert.ok(typeof ad.ruleTags === 'string', 'ruleTags should be base64 string');
		assert.ok(typeof ad.ruleActions === 'string', 'ruleActions should be base64 string');
	});

	it('includes valid httpMessage fields', () => {
		const events = generateSimulatedEvents(1);
		const http = events[0].httpMessage;

		assert.ok(http.requestId.startsWith('sim-'), 'requestId should start with sim-');
		assert.ok(['GET', 'POST', 'HEAD'].includes(http.method), 'method should be valid');
		assert.equal(http.host, 'www.example.com');
		assert.ok(http.path.startsWith('/'), 'path should start with /');
		assert.ok(http.status, 'should have status');
	});

	it('includes valid geo data', () => {
		const events = generateSimulatedEvents(1);
		const geo = events[0].geo;

		assert.ok(geo.continent, 'missing continent');
		assert.ok(geo.country, 'missing country');
		assert.ok(geo.city, 'missing city');
		assert.ok(geo.asn, 'missing asn');
	});

	it('generates events with scenario-specific attack types', () => {
		// Light scenario should have mostly clean/bot_scanner events
		const lightEvents = generateSimulatedEvents(50, { scenario: 'light' });
		const lightStatuses = lightEvents.map((e) => e.httpMessage.status);
		const okCount = lightStatuses.filter((s) => s === '200' || s === '201').length;
		// Light scenario should have a majority of 200s
		assert.ok(okCount > 20, `Expected >20 OK responses in light scenario, got ${okCount}`);
	});

	it('uses campaign IPs for credential stuffing in heavy/peak scenarios', () => {
		const heavyEvents = generateSimulatedEvents(50, { scenario: 'heavy' });
		const campaignIPs = ['198.51.100.14', '198.51.100.87', '198.51.100.203', '198.51.100.45'];
		const campaignCount = heavyEvents.filter((e) => campaignIPs.includes(e.attackData.clientIP)).length;
		// Heavy scenario is 60% credential_stuffing, so campaign IPs should appear frequently
		assert.ok(campaignCount > 15, `Expected >15 campaign IPs in heavy scenario, got ${campaignCount}`);
	});

	it('generates events with bot scores in expected ranges', () => {
		const events = generateSimulatedEvents(20);
		for (const event of events) {
			const score = parseInt(event.botScore);
			assert.ok(score >= 0 && score <= 100, `botScore ${score} out of range`);
		}
	});

	it('generates events with user risk data', () => {
		const events = generateSimulatedEvents(10);
		for (const event of events) {
			const score = parseInt(event.userRiskData.score);
			assert.ok(score >= 0 && score <= 100, `userRiskScore ${score} out of range`);
			assert.ok(event.userRiskData.uuid.startsWith('risk-'), 'uuid should start with risk-');
			assert.ok(Array.isArray(event.userRiskData.reasons), 'reasons should be array');
		}
	});

	it('generates zero events when count is 0', () => {
		const events = generateSimulatedEvents(0);
		assert.equal(events.length, 0);
	});
});

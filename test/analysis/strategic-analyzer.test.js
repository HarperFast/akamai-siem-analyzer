import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { computeTrends } from '../../src/analysis/strategic-analyzer.js';
import { buildStrategicPrompt } from '../../src/analysis/prompts/strategic.js';

const makeBatch = (overrides = {}) => ({
	createdAt: new Date('2026-03-20T10:00:00Z'),
	severity: 'medium',
	analysis: 'Sample batch analysis text.',
	eventCount: 100,
	denyCount: 20,
	denyRatio: 0.2,
	uniqueIPs: 15,
	flags: ['credential-stuffing'],
	notableIPs: ['1.2.3.4'],
	notablePatterns: ['brute-force login'],
	topRuleTags: [{ key: 'CMD-INJ', count: 5 }, { key: 'SQLI', count: 3 }],
	topCountries: [{ key: 'US', count: 40 }, { key: 'CN', count: 20 }],
	avgBotScore: 65,
	avgUserRiskScore: 45,
	...overrides,
});

describe('computeTrends', () => {
	it('counts severity distribution', () => {
		const batches = [
			makeBatch({ severity: 'critical' }),
			makeBatch({ severity: 'high' }),
			makeBatch({ severity: 'medium' }),
			makeBatch({ severity: 'medium' }),
			makeBatch({ severity: 'info' }),
		];
		const trends = computeTrends(batches);
		assert.deepEqual(trends.severityCounts, {
			critical: 1, high: 1, medium: 2, low: 0, info: 1,
		});
	});

	it('computes deny ratio trend in chronological order', () => {
		const batches = [
			makeBatch({ createdAt: new Date('2026-03-20T12:00:00Z'), denyRatio: 0.5, eventCount: 200 }),
			makeBatch({ createdAt: new Date('2026-03-20T11:00:00Z'), denyRatio: 0.3, eventCount: 150 }),
			makeBatch({ createdAt: new Date('2026-03-20T10:00:00Z'), denyRatio: 0.1, eventCount: 100 }),
		];
		const trends = computeTrends(batches);
		// Should be reversed to chronological (oldest first)
		assert.equal(trends.denyRatioTrend.length, 3);
		assert.equal(trends.denyRatioTrend[0].denyRatio, 0.1);
		assert.equal(trends.denyRatioTrend[2].denyRatio, 0.5);
	});

	it('detects persistent IPs across batches', () => {
		const batches = [
			makeBatch({ notableIPs: ['1.2.3.4', '5.6.7.8'] }),
			makeBatch({ notableIPs: ['1.2.3.4', '9.10.11.12'] }),
			makeBatch({ notableIPs: ['1.2.3.4', '5.6.7.8'] }),
		];
		const trends = computeTrends(batches);
		const persistent = trends.persistentIPs;
		assert.ok(persistent.length >= 1);
		assert.equal(persistent[0].ip, '1.2.3.4');
		assert.equal(persistent[0].batchCount, 3);
		// 5.6.7.8 appears in 2 batches
		const second = persistent.find((p) => p.ip === '5.6.7.8');
		assert.ok(second);
		assert.equal(second.batchCount, 2);
	});

	it('aggregates rule tags across batches', () => {
		const batches = [
			makeBatch({ topRuleTags: [{ key: 'SQLI', count: 10 }, { key: 'XSS', count: 5 }] }),
			makeBatch({ topRuleTags: [{ key: 'SQLI', count: 8 }, { key: 'CMD-INJ', count: 3 }] }),
		];
		const trends = computeTrends(batches);
		const sqli = trends.topRuleTags.find((t) => t.tag === 'SQLI');
		assert.ok(sqli);
		assert.equal(sqli.count, 18);
	});

	it('aggregates geographic distribution', () => {
		const batches = [
			makeBatch({ topCountries: [{ key: 'US', count: 50 }] }),
			makeBatch({ topCountries: [{ key: 'US', count: 30 }, { key: 'DE', count: 10 }] }),
		];
		const trends = computeTrends(batches);
		const us = trends.topCountries.find((c) => c.country === 'US');
		assert.ok(us);
		assert.equal(us.count, 80);
	});

	it('handles empty batches', () => {
		const trends = computeTrends([]);
		assert.deepEqual(trends.severityCounts, {
			critical: 0, high: 0, medium: 0, low: 0, info: 0,
		});
		assert.equal(trends.denyRatioTrend.length, 0);
		assert.equal(trends.persistentIPs.length, 0);
	});

	it('handles batches with missing optional fields', () => {
		const batches = [makeBatch({
			notableIPs: null,
			topRuleTags: null,
			topCountries: null,
			denyRatio: undefined,
		})];
		const trends = computeTrends(batches);
		assert.equal(trends.persistentIPs.length, 0);
		assert.equal(trends.topRuleTags.length, 0);
		assert.equal(trends.denyRatioTrend[0].denyRatio, 0);
	});
});

describe('buildStrategicPrompt', () => {
	it('includes structured batch summaries as JSON', () => {
		const batchSummaries = [
			{ batch: 1, time: '2026-03-20T10:00:00Z', severity: 'medium', eventCount: 100, denyCount: 20 },
		];
		const trends = {
			severityCounts: { critical: 0, high: 0, medium: 1, low: 0, info: 0 },
			denyRatioTrend: [{ time: '2026-03-20T10:00:00Z', denyRatio: 0.2, eventCount: 100 }],
			persistentIPs: [],
			topRuleTags: [],
			topCountries: [],
		};
		const { system, user } = buildStrategicPrompt({
			batchSummaries, trends, notableBatches: [], priorAnalysis: '', batchCount: 1,
		});

		assert.ok(system.includes('chief security analyst'));
		assert.ok(user.includes('Batch Summary Table'));
		assert.ok(user.includes('"eventCount": 100'));
		assert.ok(user.includes('Severity Distribution'));
		assert.ok(user.includes('Deny Ratio Over Time'));
	});

	it('includes full analysis text only for high/critical batches', () => {
		const notableBatches = [
			{ severity: 'critical', time: '2026-03-20T12:00:00Z', analysis: 'Critical finding here.', notableIPs: ['1.2.3.4'], notablePatterns: [] },
		];
		const { user } = buildStrategicPrompt({
			batchSummaries: [], trends: { severityCounts: {}, denyRatioTrend: [], persistentIPs: [], topRuleTags: [], topCountries: [] },
			notableBatches, priorAnalysis: '', batchCount: 1,
		});

		assert.ok(user.includes('Notable Batch Details'));
		assert.ok(user.includes('CRITICAL'));
		assert.ok(user.includes('Critical finding here.'));
	});

	it('includes prior strategic analysis when provided', () => {
		const { user } = buildStrategicPrompt({
			batchSummaries: [], trends: { severityCounts: {}, denyRatioTrend: [], persistentIPs: [], topRuleTags: [], topCountries: [] },
			notableBatches: [], priorAnalysis: 'Previous strategic assessment.', batchCount: 1,
		});

		assert.ok(user.includes('Most Recent Strategic Assessment'));
		assert.ok(user.includes('Previous strategic assessment.'));
	});

	it('omits prior strategic section when empty', () => {
		const { user } = buildStrategicPrompt({
			batchSummaries: [], trends: { severityCounts: {}, denyRatioTrend: [], persistentIPs: [], topRuleTags: [], topCountries: [] },
			notableBatches: [], priorAnalysis: '', batchCount: 1,
		});

		assert.ok(!user.includes('Most Recent Strategic Assessment'));
	});

	it('shows time range preset when provided', () => {
		const { user } = buildStrategicPrompt({
			batchSummaries: [], trends: { severityCounts: {}, denyRatioTrend: [], persistentIPs: [], topRuleTags: [], topCountries: [] },
			notableBatches: [], priorAnalysis: '', batchCount: 5, timeRange: { preset: '24h' },
		});

		assert.ok(user.includes('Requested time range: 24h'));
	});
});

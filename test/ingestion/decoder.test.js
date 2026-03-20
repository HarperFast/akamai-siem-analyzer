import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { decodeAttackData } from '../../src/ingestion/decoder.js';

describe('decodeAttackData', () => {
	it('decodes base64-encoded rule fields correctly', () => {
		const attackData = {
			rules: ['950002', '959073'],
			ruleMessages: 'U1FMIEluamVjdGlvbiBBdHRhY2s=;Q3Jvc3MtU2l0ZSBTY3JpcHRpbmc=',
			ruleTags: 'T1dBU1AvU1FMaQ==;T1dBU1AvWFNT',
			ruleData: 'c2VsZWN0;PHNjcmlwdD4=',
			ruleSelectors: 'QVJHU19HRVQ6cQ==;QVJHU19HRVQ6cQ==',
			ruleActions: 'ZGVueQ==;YWxlcnQ=',
			ruleVersions: 'NA==;NA==',
		};

		const result = decodeAttackData(attackData);

		assert.equal(result.decodedRules.length, 2);
		assert.equal(result.decodedRules[0].ruleMessage, 'SQL Injection Attack');
		assert.equal(result.decodedRules[0].ruleTag, 'OWASP/SQLi');
		assert.equal(result.decodedRules[0].ruleAction, 'deny');
		assert.equal(result.decodedRules[1].ruleMessage, 'Cross-Site Scripting');
		assert.equal(result.decodedRules[1].ruleAction, 'alert');
	});

	it('derives ruleActionSummary with correct priority', () => {
		const withDeny = {
			rules: ['1', '2'],
			ruleActions: 'ZGVueQ==;YWxlcnQ=', // deny;alert
			ruleMessages: ';',
			ruleTags: ';',
			ruleData: ';',
			ruleSelectors: ';',
			ruleVersions: ';',
		};
		assert.equal(decodeAttackData(withDeny).ruleActionSummary, 'deny');

		const withAlert = {
			rules: ['1'],
			ruleActions: 'YWxlcnQ=', // alert
			ruleMessages: '',
			ruleTags: '',
			ruleData: '',
			ruleSelectors: '',
			ruleVersions: '',
		};
		assert.equal(decodeAttackData(withAlert).ruleActionSummary, 'alert');
	});

	it('handles null/empty attackData', () => {
		const result = decodeAttackData(null);
		assert.deepEqual(result.decodedRules, []);
		assert.equal(result.ruleActionSummary, 'none');
	});

	it('handles empty rules array', () => {
		const result = decodeAttackData({ rules: [] });
		assert.deepEqual(result.decodedRules, []);
		assert.equal(result.ruleActionSummary, 'none');
	});

	it('handles malformed base64 gracefully', () => {
		const attackData = {
			rules: ['1'],
			ruleMessages: '!!!invalid!!!',
			ruleTags: '',
			ruleData: '',
			ruleSelectors: '',
			ruleActions: '',
			ruleVersions: '',
		};
		const result = decodeAttackData(attackData);
		assert.equal(result.decodedRules.length, 1);
		// Should not throw, returns raw or decoded best-effort
	});

	it('preserves + characters in URL-encoded strings', () => {
		// + should NOT be converted to space during URL decoding
		const attackData = {
			rules: ['1'],
			ruleMessages: 'dGVzdCt2YWx1ZQ==', // "test+value" in base64
			ruleTags: '',
			ruleData: '',
			ruleSelectors: '',
			ruleActions: '',
			ruleVersions: '',
		};
		const result = decodeAttackData(attackData);
		assert.equal(result.decodedRules[0].ruleMessage, 'test+value');
	});

	it('sets severity indicators correctly', () => {
		const withDeny = {
			rules: ['1'],
			ruleActions: 'ZGVueQ==',
			ruleMessages: '',
			ruleTags: '',
			ruleData: '',
			ruleSelectors: '',
			ruleVersions: '',
		};
		const result = decodeAttackData(withDeny);
		assert.equal(result.severityIndicators.hasDeny, true);
		assert.equal(result.severityIndicators.ruleCount, 1);
	});
});

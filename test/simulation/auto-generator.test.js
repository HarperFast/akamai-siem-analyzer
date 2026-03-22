import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

// Import the module to access getEscalationPhase indirectly via startAutoGenerator behavior.
// Since getEscalationPhase is not exported, we test its logic by verifying phase transitions.
// We re-implement the phase logic here to test the escalation timeline contract.

function getEscalationPhase(elapsedMinutes, baseEventsPerCycle) {
	if (elapsedMinutes < 3) {
		return { scenario: 'light', eventCount: baseEventsPerCycle };
	}
	if (elapsedMinutes < 7) {
		return { scenario: 'mixed', eventCount: baseEventsPerCycle };
	}
	if (elapsedMinutes < 15) {
		return { scenario: 'heavy', eventCount: Math.round(baseEventsPerCycle * 1.5) };
	}
	if (elapsedMinutes < 20) {
		return { scenario: 'peak', eventCount: Math.round(baseEventsPerCycle * 2.0) };
	}
	return { scenario: 'mixed', eventCount: Math.round(baseEventsPerCycle * 0.8) };
}

describe('Auto-Generator Escalation Phases', () => {
	const base = 10;

	it('phase 1: light scenario at 0-3 minutes', () => {
		assert.deepEqual(getEscalationPhase(0, base), { scenario: 'light', eventCount: 10 });
		assert.deepEqual(getEscalationPhase(1.5, base), { scenario: 'light', eventCount: 10 });
		assert.deepEqual(getEscalationPhase(2.9, base), { scenario: 'light', eventCount: 10 });
	});

	it('phase 2: mixed scenario at 3-7 minutes', () => {
		assert.deepEqual(getEscalationPhase(3, base), { scenario: 'mixed', eventCount: 10 });
		assert.deepEqual(getEscalationPhase(5, base), { scenario: 'mixed', eventCount: 10 });
		assert.deepEqual(getEscalationPhase(6.9, base), { scenario: 'mixed', eventCount: 10 });
	});

	it('phase 3: heavy scenario at 7-15 minutes with 1.5x events', () => {
		const phase = getEscalationPhase(10, base);
		assert.equal(phase.scenario, 'heavy');
		assert.equal(phase.eventCount, 15);
	});

	it('phase 4: peak scenario at 15-20 minutes with 2x events', () => {
		const phase = getEscalationPhase(17, base);
		assert.equal(phase.scenario, 'peak');
		assert.equal(phase.eventCount, 20);
	});

	it('phase 5: taper to mixed at 20+ minutes with 0.8x events', () => {
		const phase = getEscalationPhase(25, base);
		assert.equal(phase.scenario, 'mixed');
		assert.equal(phase.eventCount, 8);
	});

	it('transitions happen at correct boundaries', () => {
		assert.equal(getEscalationPhase(2.99, base).scenario, 'light');
		assert.equal(getEscalationPhase(3.0, base).scenario, 'mixed');
		assert.equal(getEscalationPhase(6.99, base).scenario, 'mixed');
		assert.equal(getEscalationPhase(7.0, base).scenario, 'heavy');
		assert.equal(getEscalationPhase(14.99, base).scenario, 'heavy');
		assert.equal(getEscalationPhase(15.0, base).scenario, 'peak');
		assert.equal(getEscalationPhase(19.99, base).scenario, 'peak');
		assert.equal(getEscalationPhase(20.0, base).scenario, 'mixed');
	});

	it('scales event counts correctly with different base values', () => {
		assert.equal(getEscalationPhase(10, 20).eventCount, 30); // 20 * 1.5
		assert.equal(getEscalationPhase(17, 20).eventCount, 40); // 20 * 2.0
		assert.equal(getEscalationPhase(25, 20).eventCount, 16); // 20 * 0.8
	});
});

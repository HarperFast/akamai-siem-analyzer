import { describe, it, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

// We need to test the accumulator logic directly
// Import the module to get the getAccumulator function
import { getAccumulator } from '../../src/analysis/accumulator.js';

describe('Accumulator', () => {
	let accumulator;
	let triggered;

	beforeEach(() => {
		accumulator = getAccumulator();
		accumulator.stopTimer();
		accumulator.reset();
		triggered = null;
		accumulator.onTrigger = (snapshot) => {
			triggered = snapshot;
		};
	});

	afterEach(() => {
		accumulator.stopTimer();
	});

	it('triggers on event_count threshold', () => {
		// Default threshold is 500 events
		accumulator.addBatch({
			batchId: 'batch-1',
			configId: 'config-1',
			eventCount: 600,
			severityIndicators: Array(600).fill({ hasDeny: false, actions: ['monitor'], ruleCount: 1 }),
		});

		assert.ok(triggered, 'Should have triggered');
		assert.equal(triggered.triggerReason, 'event_count');
		assert.equal(triggered.eventCount, 600);
	});

	it('triggers on time_ceiling via timer tick', () => {
		// Add a batch to accumulate data
		accumulator.addBatch({
			batchId: 'batch-1',
			configId: 'config-1',
			eventCount: 10,
			severityIndicators: [{ hasDeny: false, actions: ['monitor'], ruleCount: 1 }],
		});

		assert.ok(!triggered, 'Should not trigger immediately');

		// Simulate timer tick — should trigger since there is accumulated data
		accumulator.onTimerTick();

		assert.ok(triggered, 'Should have triggered on timer tick');
		assert.equal(triggered.triggerReason, 'time_ceiling');
		assert.equal(triggered.eventCount, 10);
		assert.equal(accumulator.eventCount, 0, 'Should reset after trigger');
	});

	it('triggers severity_escalation on high deny ratio', () => {
		// Default deny ratio threshold is 0.3
		// denyCount increments per severityIndicator with hasDeny=true
		// ratio = denyCount / eventCount, threshold is 0.3
		// 200 deny + 400 monitor = 600 indicators, eventCount = 600, ratio = 200/600 = 0.33
		const denyIndicators = Array(200).fill({ hasDeny: true, actions: ['deny'], ruleCount: 1 });
		const monitorIndicators = Array(400).fill({ hasDeny: false, actions: ['monitor'], ruleCount: 1 });

		accumulator.addBatch({
			batchId: 'batch-1',
			configId: 'config-1',
			eventCount: 600,
			severityIndicators: [...denyIndicators, ...monitorIndicators],
		});

		assert.ok(triggered, 'Should have triggered');
		assert.equal(triggered.hasSeverityEscalation, true);
	});

	it('resets after trigger', () => {
		accumulator.addBatch({
			batchId: 'batch-1',
			configId: 'config-1',
			eventCount: 600,
			severityIndicators: [{ hasDeny: false, actions: ['monitor'], ruleCount: 1 }],
		});

		assert.ok(triggered);
		assert.equal(accumulator.eventCount, 0);
		assert.equal(accumulator.pollBatchIds.length, 0);
	});

	it('accumulates across multiple batches', () => {
		// Each batch is 200 events, need 3 to cross 500 threshold
		for (let i = 0; i < 2; i++) {
			accumulator.addBatch({
				batchId: `batch-${i}`,
				configId: 'config-1',
				eventCount: 200,
				severityIndicators: [{ hasDeny: false, actions: ['monitor'], ruleCount: 1 }],
			});
		}
		assert.ok(!triggered, 'Should not trigger yet');
		assert.equal(accumulator.eventCount, 400);

		accumulator.addBatch({
			batchId: 'batch-2',
			configId: 'config-1',
			eventCount: 200,
			severityIndicators: [{ hasDeny: false, actions: ['monitor'], ruleCount: 1 }],
		});
		assert.ok(triggered, 'Should trigger after crossing threshold');
		assert.equal(triggered.pollBatchIds.length, 3);
	});

	it('does not trigger without onTrigger handler', () => {
		accumulator.onTrigger = null;

		// Should not throw
		accumulator.addBatch({
			batchId: 'batch-1',
			configId: 'config-1',
			eventCount: 600,
			severityIndicators: [{ hasDeny: false, actions: ['monitor'], ruleCount: 1 }],
		});
	});
});

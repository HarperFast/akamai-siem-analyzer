import defaultConfig from '../../config/default.json' with { type: 'json' };

let instance = null;

export function getAccumulator() {
	if (!instance) {
		instance = new Accumulator();
	}
	return instance;
}

class Accumulator {
	constructor() {
		this.reset();
		this.baselineEventRate = 0; // Rolling 1-hour average events/minute
		this.baselineWindow = [];
		this.onTrigger = null;
	}

	reset() {
		this.eventCount = 0;
		this.denyCount = 0;
		this.alertCount = 0;
		this.monitorCount = 0;
		this.uniqueIPs = new Set();
		this.pollBatchIds = [];
		this.windowStart = null;
		this.windowEnd = null;
		this.hasSeverityEscalation = false;
		this.ruleTagCounts = {};
		this.countryCounts = {};
		this.pathCounts = {};
		this.botScores = [];
		this.userRiskScores = [];
	}

	addBatch({ batchId, configId, eventCount, severityIndicators }) {
		const now = new Date();
		if (!this.windowStart) this.windowStart = now;
		this.windowEnd = now;

		this.pollBatchIds.push(batchId);
		this.eventCount += eventCount;

		// Update baseline tracking
		this.baselineWindow.push({ time: now.getTime(), count: eventCount });
		const oneHourAgo = now.getTime() - 60 * 60 * 1000;
		this.baselineWindow = this.baselineWindow.filter((e) => e.time > oneHourAgo);
		if (this.baselineWindow.length > 0) {
			const totalInWindow = this.baselineWindow.reduce((sum, e) => sum + e.count, 0);
			const windowMinutes = (now.getTime() - this.baselineWindow[0].time) / (1000 * 60) || 1;
			this.baselineEventRate = totalInWindow / windowMinutes;
		}

		// Aggregate severity indicators
		for (const si of severityIndicators) {
			if (si.hasDeny) this.denyCount++;
			if (si.actions?.includes('alert')) this.alertCount++;
			if (si.actions?.includes('monitor')) this.monitorCount++;
		}

		// Check trigger conditions
		this.checkTrigger(configId);
	}

	checkTrigger(configId) {
		const config = defaultConfig.analysis.batch;
		const escalation = defaultConfig.analysis.escalation;

		let triggerReason = null;

		// Event count threshold
		if (this.eventCount >= config.eventCountThreshold) {
			triggerReason = 'event_count';
		}

		// Time ceiling
		if (this.windowStart && this.windowEnd) {
			const durationSeconds = (this.windowEnd.getTime() - this.windowStart.getTime()) / 1000;
			if (durationSeconds >= config.timeCeilingSeconds) {
				triggerReason = triggerReason || 'time_ceiling';
			}
		}

		// Severity escalation
		const denyRatio = this.eventCount > 0 ? this.denyCount / this.eventCount : 0;
		if (denyRatio >= escalation.denyRatioThreshold) {
			triggerReason = 'severity_escalation';
			this.hasSeverityEscalation = true;
		}

		// IP spike detection
		if (this.baselineEventRate > 0) {
			const currentRate = this.eventCount / Math.max(1, (this.windowEnd - this.windowStart) / (1000 * 60));
			if (currentRate > this.baselineEventRate * escalation.uniqueIPSpikeMultiplier) {
				triggerReason = triggerReason || 'severity_escalation';
				this.hasSeverityEscalation = true;
			}
		}

		if (triggerReason && this.onTrigger) {
			const snapshot = this.getSnapshot(triggerReason, configId);
			this.reset();
			this.onTrigger(snapshot);
		}
	}

	getSnapshot(triggerReason, configId) {
		return {
			configId,
			triggerReason,
			eventCount: this.eventCount,
			denyCount: this.denyCount,
			alertCount: this.alertCount,
			monitorCount: this.monitorCount,
			uniqueIPs: this.uniqueIPs.size,
			pollBatchIds: [...this.pollBatchIds],
			windowStart: this.windowStart,
			windowEnd: this.windowEnd,
			windowDurationSeconds: this.windowStart && this.windowEnd
				? Math.round((this.windowEnd.getTime() - this.windowStart.getTime()) / 1000)
				: 0,
			hasSeverityEscalation: this.hasSeverityEscalation,
			denyRatio: this.eventCount > 0 ? this.denyCount / this.eventCount : 0,
		};
	}
}

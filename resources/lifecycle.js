import { startPoller, stopPoller } from '../src/ingestion/poller.js';
import { getAccumulator } from '../src/analysis/accumulator.js';
import { analyzeBatch } from '../src/analysis/batch-analyzer.js';
import { startSummaryScheduler, stopSummaryScheduler } from '../src/analysis/summary-analyzer.js';
import { startStrategicScheduler, stopStrategicScheduler } from '../src/analysis/strategic-analyzer.js';

// Wire accumulator to batch analyzer
const accumulator = getAccumulator();
accumulator.onTrigger = async (snapshot) => {
	try {
		await analyzeBatch(snapshot);
	} catch (err) {
		console.error('[lifecycle] Batch analysis error:', err.message);
	}
};

// Start all background processes
if (process.env.SIMULATION_MODE === 'true') {
	const { startSimPoller } = await import('../src/simulation/sim-poller.js');
	startSimPoller();
} else if (process.env.AKAMAI_CONFIG_ID) {
	startPoller();
}

if (process.env.ANTHROPIC_API_KEY) {
	startSummaryScheduler();
	startStrategicScheduler();
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
	stopPoller();
	stopSummaryScheduler();
	stopStrategicScheduler();
});

process.on('SIGINT', () => {
	stopPoller();
	stopSummaryScheduler();
	stopStrategicScheduler();
});

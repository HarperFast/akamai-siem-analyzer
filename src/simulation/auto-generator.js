import { randomUUID } from 'node:crypto';
import { generateSimulatedEvents } from './generator.js';

let generatorTimer = null;
let startTime = null;

/**
 * Get the escalation phase based on elapsed minutes since start.
 * Returns { scenario, eventCount } for the current phase.
 */
function getEscalationPhase(elapsedMinutes, baseEventsPerCycle) {
	if (elapsedMinutes < 3) {
		// Phase 1: Normal background traffic — same volume, low deny ratio → Haiku
		return {
			scenario: 'light',
			eventCount: baseEventsPerCycle,
		};
	}
	if (elapsedMinutes < 7) {
		// Phase 2: First credential stuffing probes — mixed, deny ratio climbs
		return {
			scenario: 'mixed',
			eventCount: baseEventsPerCycle,
		};
	}
	if (elapsedMinutes < 15) {
		// Phase 3: Full-scale credential stuffing campaign
		return {
			scenario: 'heavy',
			eventCount: Math.round(baseEventsPerCycle * 1.5),
		};
	}
	if (elapsedMinutes < 20) {
		// Phase 4: Campaign intensity peaks
		return {
			scenario: 'peak',
			eventCount: Math.round(baseEventsPerCycle * 2.0),
		};
	}
	// Phase 5: Attack tapers, elevated baseline
	return {
		scenario: 'mixed',
		eventCount: Math.round(baseEventsPerCycle * 0.8),
	};
}

/**
 * Start continuous event generation.
 * @param {object} options
 * @param {number} options.intervalSeconds - Seconds between generations (default: 25)
 * @param {number} options.eventsPerCycle - Base events per cycle (default: 10)
 * @param {'credential_stuffing'|'flat'} options.scenario - 'credential_stuffing' uses escalating phases, 'flat' uses fixed mixed
 */
export function startAutoGenerator({
	intervalSeconds = 25,
	eventsPerCycle = 10,
	scenario = 'credential_stuffing',
} = {}) {
	if (generatorTimer) {
		console.log('[auto-generator] Already running, stopping first');
		stopAutoGenerator();
	}

	startTime = Date.now();
	const intervalMs = intervalSeconds * 1000;

	console.log(
		`[auto-generator] Starting: ${eventsPerCycle} events every ${intervalSeconds}s, scenario: ${scenario}`
	);

	async function generate() {
		try {
			const { siem_simulated_events } = tables;
			let genScenario = 'mixed';
			let genCount = eventsPerCycle;

			if (scenario === 'credential_stuffing') {
				const elapsedMinutes = (Date.now() - startTime) / (1000 * 60);
				const phase = getEscalationPhase(elapsedMinutes, eventsPerCycle);
				genScenario = phase.scenario;
				genCount = phase.eventCount;
				console.log(
					`[auto-generator] Phase at ${elapsedMinutes.toFixed(1)}min: scenario=${genScenario}, count=${genCount}`
				);
			}

			const events = generateSimulatedEvents(genCount, { scenario: genScenario });

			for (const raw of events) {
				await siem_simulated_events.put({
					id: randomUUID(),
					raw,
				});
			}

			console.log(`[auto-generator] Generated ${events.length} events`);
		} catch (err) {
			console.error('[auto-generator] Error:', err.message);
		}
	}

	// Generate first batch immediately
	generate();
	generatorTimer = setInterval(generate, intervalMs);
}

export function stopAutoGenerator() {
	if (generatorTimer) {
		clearInterval(generatorTimer);
		generatorTimer = null;
		startTime = null;
		console.log('[auto-generator] Stopped');
	}
}

export function isAutoGeneratorRunning() {
	return generatorTimer !== null;
}

export function getAutoGeneratorInfo() {
	if (!generatorTimer) return { running: false };
	const elapsedMinutes = (Date.now() - startTime) / (1000 * 60);
	return {
		running: true,
		elapsedMinutes: Math.round(elapsedMinutes * 10) / 10,
		startedAt: new Date(startTime).toISOString(),
	};
}

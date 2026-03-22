import { randomUUID } from 'node:crypto';
import { generateSimulatedEvents } from '../src/simulation/generator.js';
import {
	startAutoGenerator,
	stopAutoGenerator,
	isAutoGeneratorRunning,
	getAutoGeneratorInfo,
} from '../src/simulation/auto-generator.js';

function requireSimulationMode() {
	if (process.env.SIMULATION_MODE !== 'true') {
		const err = new Error('Simulation mode is not enabled');
		err.statusCode = 403;
		throw err;
	}
}

// /Simulation/{action}
export class Simulation extends Resource {
	static loadAsInstance = false;

	async get(target) {
		requireSimulationMode();
		const action = target?.id;

		if (action === 'status') {
			const isSimMode = process.env.SIMULATION_MODE === 'true';
			let pendingEvents = 0;
			if (isSimMode) {
				for await (const _ of tables.siem_simulated_events.search()) {
					pendingEvents++;
				}
			}
			return {
				simulationMode: isSimMode,
				pendingEvents,
				autoGenerator: getAutoGeneratorInfo(),
			};
		}

		return { error: 'Not found' };
	}

	async post(target, data) {
		requireSimulationMode();
		const action = target?.id;

		if (action === 'generate') {
			const count = Math.min(data?.count || 20, 500);
			const scenario = data?.scenario || 'mixed';
			const events = generateSimulatedEvents(count, { scenario });

			for (const raw of events) {
				await tables.siem_simulated_events.put({
					id: randomUUID(),
					raw,
				});
			}

			return { generated: events.length, scenario, status: 'loaded' };
		}

		if (action === 'auto-start') {
			const intervalSeconds = data?.intervalSeconds || 25;
			const eventsPerCycle = data?.eventsPerCycle || 10;
			const scenario = data?.scenario || 'credential_stuffing';
			startAutoGenerator({ intervalSeconds, eventsPerCycle, scenario });
			return { status: 'auto-generator started', intervalSeconds, eventsPerCycle, scenario };
		}

		if (action === 'auto-stop') {
			stopAutoGenerator();
			return { status: 'auto-generator stopped' };
		}

		if (action === 'clear') {
			let deleted = 0;
			for await (const record of tables.siem_simulated_events.search()) {
				await tables.siem_simulated_events.delete(record.id);
				deleted++;
			}
			return { status: 'cleared', deleted };
		}

		return { error: 'Not found' };
	}
}

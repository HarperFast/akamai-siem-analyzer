import EdgeGrid from 'akamai-edgegrid';

const SIEM_API_PATH = '/siem/v1/configs';

export class AkamaiClient {
	constructor({ host, clientToken, clientSecret, accessToken }) {
		this.eg = new EdgeGrid(clientToken, clientSecret, accessToken, host);
		this.host = host;
		this.lastCallTime = 0;
		this.minSpacingMs = 1000;
	}

	async fetchEvents(configId, { offset, from, limit = 600000, timeout = 120000 }) {
		// Enforce minimum spacing between calls
		const elapsed = Date.now() - this.lastCallTime;
		if (elapsed < this.minSpacingMs) {
			await new Promise((r) => setTimeout(r, this.minSpacingMs - elapsed));
		}

		let path = `${SIEM_API_PATH}/${configId}?limit=${limit}`;
		if (offset) {
			path += `&offset=${offset}`;
		} else if (from) {
			path += `&from=${from}`;
		}

		this.eg.auth({
			path,
			method: 'GET',
			headers: { Accept: 'application/json' },
		});

		this.lastCallTime = Date.now();

		return new Promise((resolve, reject) => {
			const timer = setTimeout(() => {
				reject(new Error(`Akamai SIEM API timeout after ${timeout}ms`));
			}, timeout);

			this.eg.send((err, response, body) => {
				clearTimeout(timer);
				if (err) return reject(err);

				if (response.statusCode === 429) {
					return reject(new Error('RATE_LIMITED'));
				}
				if (response.statusCode >= 500) {
					return reject(new Error(`AKAMAI_SERVER_ERROR: ${response.statusCode}`));
				}
				if (response.statusCode !== 200) {
					return reject(new Error(`Akamai API error: ${response.statusCode} ${body}`));
				}

				resolve(body);
			});
		});
	}

	parseNDJSON(body) {
		const lines = body.split('\n').filter((line) => line.trim());
		const events = [];
		let metadata = null;

		for (const line of lines) {
			try {
				const parsed = JSON.parse(line);
				// The last line is metadata with offset info
				if (parsed.total !== undefined && parsed.offset !== undefined) {
					metadata = parsed;
				} else {
					events.push(parsed);
				}
			} catch (e) {
				// Skip malformed lines
			}
		}

		return { events, metadata };
	}
}

export function createClient() {
	return new AkamaiClient({
		host: process.env.AKAMAI_HOST,
		clientToken: process.env.AKAMAI_CLIENT_TOKEN,
		clientSecret: process.env.AKAMAI_CLIENT_SECRET,
		accessToken: process.env.AKAMAI_ACCESS_TOKEN,
	});
}

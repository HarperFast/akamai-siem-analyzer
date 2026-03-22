import { randomBytes, randomInt } from 'node:crypto';

// === Base64 encoding helper (matches Akamai SIEM format) ===
function encodeField(values) {
	return values.map((v) => Buffer.from(v).toString('base64')).join(';');
}

function randomHex(bytes) {
	return randomBytes(bytes).toString('hex');
}

function pick(arr) {
	return arr[randomInt(arr.length)];
}

function weightedPick(items) {
	const total = items.reduce((sum, i) => sum + i.weight, 0);
	let r = Math.random() * total;
	for (const item of items) {
		r -= item.weight;
		if (r <= 0) return item;
	}
	return items[items.length - 1];
}

function randomInRange(min, max) {
	return min + Math.floor(Math.random() * (max - min + 1));
}

// === Campaign IPs (persistent credential stuffing botnet) ===
const CAMPAIGN_IPS = [
	{ ip: '198.51.100.14', geo: { continent: 'EU', country: 'RU', city: 'MOSCOW', regionCode: 'MOW', asn: '12389' } },
	{ ip: '198.51.100.87', geo: { continent: 'AS', country: 'CN', city: 'BEIJING', regionCode: 'BJ', asn: '4134' } },
	{ ip: '198.51.100.203', geo: { continent: 'EU', country: 'RU', city: 'SAINT PETERSBURG', regionCode: 'SPE', asn: '31213' } },
	{ ip: '198.51.100.45', geo: { continent: 'AS', country: 'CN', city: 'SHANGHAI', regionCode: 'SH', asn: '4812' } },
];

// === Background IPs (varied sources) ===
const BACKGROUND_IPS = [
	{ ip: '203.0.113.10', geo: { continent: 'NA', country: 'US', city: 'ASHBURN', regionCode: 'VA', asn: '14618' } },
	{ ip: '203.0.113.55', geo: { continent: 'SA', country: 'BR', city: 'SAO PAULO', regionCode: 'SP', asn: '28573' } },
	{ ip: '203.0.113.120', geo: { continent: 'EU', country: 'DE', city: 'FRANKFURT', regionCode: 'HE', asn: '24940' } },
	{ ip: '203.0.113.200', geo: { continent: 'AS', country: 'KR', city: 'SEOUL', regionCode: '11', asn: '4766' } },
	{ ip: '203.0.113.77', geo: { continent: 'AS', country: 'IN', city: 'MUMBAI', regionCode: 'MH', asn: '9498' } },
	{ ip: '192.0.2.33', geo: { continent: 'EU', country: 'GB', city: 'LONDON', regionCode: 'ENG', asn: '5089' } },
	{ ip: '192.0.2.100', geo: { continent: 'NA', country: 'US', city: 'SEATTLE', regionCode: 'WA', asn: '16509' } },
	{ ip: '192.0.2.201', geo: { continent: 'OC', country: 'AU', city: 'SYDNEY', regionCode: 'NSW', asn: '13335' } },
];

// === Attack Scenario Definitions ===

const SCENARIOS = {
	credential_stuffing: {
		rules: ['920350', '920420'],
		ruleMessages: ['Credential Stuffing Attempt', 'Brute Force Login Detected'],
		ruleTags: ['CUSTOM/CRED', 'CUSTOM/BRUTE'],
		ruleData: ['login_attempt', 'failed_auth'],
		ruleSelectors: ['ARGS_POST:username', 'ARGS_POST:password'],
		ruleActions: ['deny', 'alert'],
		ruleVersions: ['4', '4'],
		policyId: 'qik1_26545',
		paths: ['/api/login', '/api/login', '/api/login', '/api/auth/token', '/oauth/token'],
		methods: ['POST', 'POST', 'POST', 'POST', 'POST', 'POST', 'POST', 'POST', 'POST', 'GET'],
		statuses: ['403', '403', '401', '429', '403'],
		botScoreRange: [65, 85],
		userRiskScoreRange: [60, 90],
		userRiskReasons: ['credential_abuse', 'velocity_anomaly', 'suspicious_ip', 'impossible_travel'],
	},

	sqli: {
		rules: ['950002', '959073', '981243'],
		ruleMessages: ['SQL Injection Attack', 'SQL Injection Attack - Common DB Names', 'SQL Injection Evasion Attempt'],
		ruleTags: ['OWASP/SQLi', 'OWASP/SQLi', 'OWASP/SQLi'],
		ruleData: ['select', 'union', 'information_schema'],
		ruleSelectors: ['ARGS_GET:q', 'ARGS_GET:id', 'ARGS_GET:search'],
		ruleActions: ['deny', 'deny', 'deny'],
		ruleVersions: ['4', '4', '4'],
		policyId: 'qik1_26545',
		paths: ['/api/users', '/search', '/api/products', '/api/v2/account'],
		methods: ['GET', 'GET', 'POST', 'GET'],
		statuses: ['403', '403', '400', '403'],
		botScoreRange: [20, 50],
		userRiskScoreRange: [30, 60],
		userRiskReasons: ['suspicious_ip'],
	},

	xss: {
		rules: ['941100', '941110'],
		ruleMessages: ['XSS Attack Detected', 'Cross-Site Scripting via Script Tag'],
		ruleTags: ['OWASP/XSS', 'OWASP/XSS'],
		ruleData: ['<script>', 'onerror'],
		ruleSelectors: ['ARGS_GET:q', 'ARGS_POST:comment'],
		ruleActions: ['deny', 'deny'],
		ruleVersions: ['4', '4'],
		policyId: 'qik1_26545',
		paths: ['/search', '/api/comments', '/forum/post', '/feedback'],
		methods: ['GET', 'POST', 'POST', 'POST'],
		statuses: ['403', '403', '400', '403'],
		botScoreRange: [15, 45],
		userRiskScoreRange: [25, 55],
		userRiskReasons: ['suspicious_ip'],
	},

	path_traversal: {
		rules: ['930100', '930110'],
		ruleMessages: ['Path Traversal Attack', 'Directory Traversal Attempt'],
		ruleTags: ['OWASP/LFI', 'OWASP/LFI'],
		ruleData: ['../', '/etc/passwd'],
		ruleSelectors: ['REQUEST_URI', 'ARGS_GET:file'],
		ruleActions: ['deny', 'deny'],
		ruleVersions: ['4', '4'],
		policyId: 'qik1_26545',
		paths: ['/admin', '/.env', '/wp-config.php', '/../../../etc/passwd', '/api/../config'],
		methods: ['GET', 'GET', 'GET', 'GET', 'GET'],
		statuses: ['403', '403', '404', '403', '403'],
		botScoreRange: [30, 60],
		userRiskScoreRange: [20, 50],
		userRiskReasons: ['suspicious_ip'],
	},

	bot_scanner: {
		rules: ['BOT001'],
		ruleMessages: ['Automated Bot Detected'],
		ruleTags: ['BOT/GENERIC'],
		ruleData: ['scanner'],
		ruleSelectors: ['REQUEST_HEADERS:User-Agent'],
		ruleActions: ['monitor'],
		ruleVersions: ['1'],
		policyId: 'qik1_26545',
		paths: ['/robots.txt', '/.git', '/wp-admin', '/.well-known', '/sitemap.xml', '/api/health'],
		methods: ['GET', 'GET', 'GET', 'GET', 'GET', 'HEAD'],
		statuses: ['200', '404', '403', '200', '200', '200'],
		botScoreRange: [70, 95],
		userRiskScoreRange: [10, 30],
		userRiskReasons: [],
	},

	clean: {
		rules: ['920100'],
		ruleMessages: ['Request Anomaly Detected'],
		ruleTags: ['OWASP/ANOMALY'],
		ruleData: ['missing_header'],
		ruleSelectors: ['REQUEST_HEADERS:Accept'],
		ruleActions: ['alert'],
		ruleVersions: ['4'],
		policyId: 'qik1_26545',
		paths: ['/', '/api/users', '/api/products', '/about', '/contact', '/api/v2/account'],
		methods: ['GET', 'GET', 'POST', 'GET', 'GET', 'GET'],
		statuses: ['200', '200', '201', '200', '200', '200'],
		botScoreRange: [5, 25],
		userRiskScoreRange: [5, 20],
		userRiskReasons: [],
	},
};

const USER_AGENTS = [
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0',
	'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 Safari/17.2',
	'Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0',
	'python-requests/2.31.0',
	'curl/8.4.0',
	'Go-http-client/2.0',
	'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
];

function generateSingleEvent(scenario, ipSource) {
	const s = SCENARIOS[scenario];
	const ipEntry = ipSource || pick(BACKGROUND_IPS);

	// Pick a subset of rules (1 to all)
	const ruleCount = randomInRange(1, s.rules.length);
	const ruleIndices = [];
	const available = [...Array(s.rules.length).keys()];
	for (let i = 0; i < ruleCount; i++) {
		const idx = randomInt(available.length);
		ruleIndices.push(available.splice(idx, 1)[0]);
	}
	ruleIndices.sort();

	const rules = ruleIndices.map((i) => s.rules[i]);
	const ruleMessages = encodeField(ruleIndices.map((i) => s.ruleMessages[i]));
	const ruleTags = encodeField(ruleIndices.map((i) => s.ruleTags[i]));
	const ruleData = encodeField(ruleIndices.map((i) => s.ruleData[i]));
	const ruleSelectors = encodeField(ruleIndices.map((i) => s.ruleSelectors[i]));
	const ruleActions = encodeField(ruleIndices.map((i) => s.ruleActions[i]));
	const ruleVersions = encodeField(ruleIndices.map((i) => s.ruleVersions[i]));

	const botScore = randomInRange(...s.botScoreRange);
	const userRiskScore = randomInRange(...s.userRiskScoreRange);
	const riskReasons =
		s.userRiskReasons.length > 0
			? s.userRiskReasons.slice(0, randomInRange(1, Math.min(3, s.userRiskReasons.length)))
			: [];

	const jitterSeconds = randomInRange(0, 60);
	const startEpoch = Math.floor(Date.now() / 1000) - jitterSeconds;

	return {
		attackData: {
			clientIP: ipEntry.ip,
			rules,
			ruleMessages,
			ruleTags,
			ruleData,
			ruleSelectors,
			ruleActions,
			ruleVersions,
			policyId: s.policyId,
		},
		httpMessage: {
			requestId: `sim-${randomHex(4)}`,
			start: String(startEpoch),
			protocol: 'HTTP/1.1',
			method: pick(s.methods),
			host: 'www.example.com',
			port: '443',
			path: pick(s.paths),
			query: scenario === 'sqli' ? `id=1%20OR%201%3D1&q=${randomHex(3)}` : '',
			requestHeaders: {
				'User-Agent': pick(USER_AGENTS),
				Accept: '*/*',
				'Content-Type': 'application/json',
			},
			status: pick(s.statuses),
			bytes: String(randomInRange(200, 5000)),
			responseHeaders: { 'Content-Type': 'application/json' },
			clientIP: ipEntry.ip,
		},
		geo: ipEntry.geo,
		botScore: String(botScore),
		botResponseSegment: String(botScore >= 70 ? 3 : botScore >= 40 ? 2 : 1),
		botData: botScore >= 60 ? { anomalies: ['browser_fingerprint', 'headless_browser'] } : {},
		userRiskData: {
			score: String(userRiskScore),
			reasons: riskReasons,
			uuid: `risk-${randomHex(6)}`,
		},
	};
}

// === Weighted scenario selection ===

const SCENARIO_WEIGHTS_DEFAULT = [
	{ scenario: 'credential_stuffing', weight: 40 },
	{ scenario: 'sqli', weight: 15 },
	{ scenario: 'xss', weight: 10 },
	{ scenario: 'path_traversal', weight: 10 },
	{ scenario: 'bot_scanner', weight: 15 },
	{ scenario: 'clean', weight: 10 },
];

const SCENARIO_WEIGHTS_LIGHT = [
	{ scenario: 'credential_stuffing', weight: 5 },
	{ scenario: 'sqli', weight: 10 },
	{ scenario: 'xss', weight: 5 },
	{ scenario: 'path_traversal', weight: 5 },
	{ scenario: 'bot_scanner', weight: 30 },
	{ scenario: 'clean', weight: 45 },
];

const SCENARIO_WEIGHTS_HEAVY = [
	{ scenario: 'credential_stuffing', weight: 60 },
	{ scenario: 'sqli', weight: 10 },
	{ scenario: 'xss', weight: 5 },
	{ scenario: 'path_traversal', weight: 5 },
	{ scenario: 'bot_scanner', weight: 10 },
	{ scenario: 'clean', weight: 10 },
];

const SCENARIO_WEIGHTS_PEAK = [
	{ scenario: 'credential_stuffing', weight: 70 },
	{ scenario: 'sqli', weight: 8 },
	{ scenario: 'xss', weight: 5 },
	{ scenario: 'path_traversal', weight: 5 },
	{ scenario: 'bot_scanner', weight: 7 },
	{ scenario: 'clean', weight: 5 },
];

/**
 * Generate simulated SIEM events in raw Akamai format.
 * @param {number} count - Number of events to generate
 * @param {object} options
 * @param {'credential_stuffing'|'mixed'|'light'|'heavy'|'peak'} options.scenario - Weight profile
 * @returns {Array<object>} Raw Akamai-format event objects
 */
export function generateSimulatedEvents(count, { scenario = 'mixed' } = {}) {
	let weights;
	switch (scenario) {
		case 'light':
			weights = SCENARIO_WEIGHTS_LIGHT;
			break;
		case 'heavy':
			weights = SCENARIO_WEIGHTS_HEAVY;
			break;
		case 'peak':
			weights = SCENARIO_WEIGHTS_PEAK;
			break;
		default:
			weights = SCENARIO_WEIGHTS_DEFAULT;
			break;
	}

	const events = [];
	for (let i = 0; i < count; i++) {
		const { scenario: attackType } = weightedPick(weights);
		const ipSource = attackType === 'credential_stuffing' ? pick(CAMPAIGN_IPS) : pick(BACKGROUND_IPS);
		events.push(generateSingleEvent(attackType, ipSource));
	}
	return events;
}

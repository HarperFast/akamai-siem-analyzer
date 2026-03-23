/**
 * Dual-line SVG sparkline showing event volume and deny count over time.
 */

const SPARKLINE_WIDTH = 200;
const SPARKLINE_HEIGHT = 40;
const PADDING = 2;

/**
 * Render a dual-line sparkline into a container element.
 * @param {HTMLElement} container - Target element
 * @param {{ events: number[], denies: number[] }} data - Two arrays of equal length
 */
export function renderSparkline(container, { events, denies }) {
	if (!events.length) {
		container.innerHTML = '';
		return;
	}

	const maxVal = Math.max(1, ...events, ...denies);
	const w = SPARKLINE_WIDTH;
	const h = SPARKLINE_HEIGHT;
	const drawW = w - PADDING * 2;
	const drawH = h - PADDING * 2;

	const toPoints = (values) =>
		values
			.map((v, i) => {
				const x = PADDING + (values.length === 1 ? drawW / 2 : (i / (values.length - 1)) * drawW);
				const y = PADDING + drawH - (v / maxVal) * drawH;
				return `${x.toFixed(1)},${y.toFixed(1)}`;
			})
			.join(' ');

	const eventPoints = toPoints(events);
	const denyPoints = toPoints(denies);

	// Fill path (area under event line)
	const firstX = PADDING;
	const lastX = PADDING + drawW;
	const bottom = PADDING + drawH;
	const eventFill = `M${firstX},${bottom} L${eventPoints.replace(/ /g, ' L')} L${lastX},${bottom} Z`;

	container.innerHTML = `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg">
		<path d="${eventFill}" fill="rgba(88,166,255,0.12)" />
		<polyline points="${eventPoints}" fill="none" stroke="#58a6ff" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />
		<polyline points="${denyPoints}" fill="none" stroke="#f85149" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round" />
	</svg>`;
}

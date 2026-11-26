// Drives real terminal components without starting a terminal renderer.
import { getKeybindings } from "@earendil-works/pi-tui";

export const theme = { fg: (_color, text) => text, bold: (text) => text };

export function createTerminalUI() {
	let component;
	let completions = 0;
	let renders = 0;
	let show;
	const ready = new Promise((resolve) => {
		show = resolve;
	});
	const tui = { terminal: { rows: 30 }, requestRender: () => renders++ };
	return {
		tui,
		ready,
		custom(factory) {
			return new Promise((resolve) => {
				let settled = false;
				const complete = (value) => {
					if (settled) return;
					settled = true;
					completions++;
					resolve(value);
				};
				component = factory(tui, theme, getKeybindings(), complete);
				show(component);
			});
		},
		get component() {
			return component;
		},
		get completions() {
			return completions;
		},
		get renders() {
			return renders;
		},
	};
}

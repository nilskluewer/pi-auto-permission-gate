import type { Theme } from "@earendil-works/pi-coding-agent";
import {
	type Component,
	Key,
	type KeybindingsManager,
	matchesKey,
	SelectList,
	stripTerminalSequences,
	Text,
	type TUI,
	truncateToWidth,
} from "@earendil-works/pi-tui";

export interface TerminalApprovalView {
	summary: string;
	facts: string;
	details: { label: string; text: string }[];
}

export function createApprovalComponent(
	tui: Pick<TUI, "requestRender" | "terminal">,
	theme: Theme,
	keybindings: KeybindingsManager,
	view: TerminalApprovalView,
	options: string[],
	done: (result: string | null) => void,
): Component {
	let expanded = -1;
	let selectedIndex = view.details.length;
	let scrollTop = 0;
	let detailHeight = 8;
	let detailLines: string[] = [];
	let visibleItems = options.length + view.details.length;
	const clean = (text: string) =>
		stripTerminalSequences(text).replace(/\p{Cc}/gu, (character) =>
			character === "\n" || character === "\t" ? character : "",
		);
	const summaryText = new Text(clean(view.summary), 0, 0);
	const detailText = view.details.map((detail) => new Text(clean(detail.text), 0, 0));
	const detailItems = view.details.map((detail, index) => ({ value: `details:${index}`, label: `▸ ${detail.label}` }));
	const choiceItems = options.map((option) => ({ value: option, label: clean(option) }));
	const items = [...detailItems, ...choiceItems];
	const toggleDetails = (index: number) => {
		expanded = expanded === index ? -1 : index;
		scrollTop = 0;
		for (let index = 0; index < view.details.length; index++)
			detailItems[index].label = `${expanded === index ? "▾" : "▸"} ${view.details[index].label}`;
	};
	const renderMenu = (menuItems: typeof items, offset: number, maxVisible: number, width: number) => {
		const focused = selectedIndex >= offset && selectedIndex < offset + menuItems.length;
		const selectList = new SelectList(menuItems, maxVisible, {
			selectedPrefix: (text) => (focused ? theme.fg("accent", text) : "  "),
			selectedText: (text) => (focused ? theme.fg("accent", text) : text.replace(/^→ /, "  ")),
			description: (text) => theme.fg("muted", text),
			scrollInfo: (text) => theme.fg("dim", text),
			noMatch: (text) => theme.fg("warning", text),
		});
		selectList.setSelectedIndex(focused ? selectedIndex - offset : 0);
		return selectList.render(width);
	};

	return {
		render(width: number): string[] {
			// Leave room for Pi's status/footer, and reduce the menu on short terminals.
			const height = Math.max(1, tui.terminal.rows - 2);
			const [risk, ...facts] = clean(view.facts).split("\n");
			const factLines = [
				...new Text(theme.fg("muted", risk), 0, 0).render(width),
				...facts.map((line) => theme.fg("muted", truncateToWidth(line, width))),
			].slice(0, Math.max(1, height - 6));
			const summary = summaryText.render(width);
			const summaryLimit = Math.min(4, Math.max(1, height - factLines.length - 5));
			const lines = [...summary.slice(0, summaryLimit), ...factLines];
			if (height >= 22) lines.push("", theme.fg("muted", "Details"));
			lines.push(...renderMenu(detailItems, 0, detailItems.length, width));
			const separator =
				height >= 22 ? ["", "Allow this command to run? (You can also answer in the browser queue.)"] : [];
			const menuBudget = Math.max(1, height - lines.length - separator.length - 1);
			const visibleChoices = Math.min(
				options.length,
				Math.max(1, menuBudget < options.length ? menuBudget - 1 : menuBudget),
			);
			visibleItems = selectedIndex < detailItems.length ? detailItems.length : visibleChoices;
			const choices = renderMenu(choiceItems, detailItems.length, visibleChoices, width);
			const selected = items[selectedIndex];
			const scope =
				selectedIndex >= detailItems.length && clean(selected.value).length > width - 4
					? new Text(clean(selected.value), 0, 0).render(width)
					: [];
			const scopeLines = scope.slice(0, Math.max(0, height - lines.length - separator.length - choices.length - 1));
			const available = height - lines.length - separator.length - choices.length - scopeLines.length - 1;
			if (expanded >= 0 && available >= 3) {
				detailHeight = Math.min(8, available - 2);
				detailLines = detailText[expanded].render(width);
				scrollTop = Math.min(scrollTop, Math.max(0, detailLines.length - detailHeight));
				lines.push(
					theme.fg("accent", `▾ ${view.details[expanded].label}`),
					...detailLines.slice(scrollTop, scrollTop + detailHeight),
					theme.fg(
						"dim",
						`${scrollTop + 1}–${Math.min(scrollTop + detailHeight, detailLines.length)} of ${detailLines.length} lines · pgup/pgdn scroll`,
					),
				);
			}
			lines.push(...separator, ...choices, ...scopeLines);
			const hint =
				expanded >= 0 && available < 3
					? "Enlarge the terminal to view details · esc deny"
					: summary.length > summaryLimit
						? "Full summary in command details · ↑/↓ navigate · enter select · esc deny"
						: "↑/↓ navigate · enter select/toggle · space toggle details · esc deny";
			lines.push(theme.fg("dim", hint));
			return lines.slice(0, height).map((line) => truncateToWidth(line, Math.max(0, width)));
		},
		handleInput(data: string): void {
			// Use the injected bindings, including when Space is a configured action.
			if (keybindings.matches(data, "tui.select.up")) {
				selectedIndex = (selectedIndex - 1 + items.length) % items.length;
			} else if (keybindings.matches(data, "tui.select.down")) {
				selectedIndex = (selectedIndex + 1) % items.length;
			} else if (keybindings.matches(data, "tui.select.pageUp")) {
				if (expanded >= 0) scrollTop = Math.max(0, scrollTop - detailHeight);
				else selectedIndex = Math.max(0, selectedIndex - visibleItems);
			} else if (keybindings.matches(data, "tui.select.pageDown")) {
				if (expanded >= 0)
					scrollTop = Math.min(Math.max(0, detailLines.length - detailHeight), scrollTop + detailHeight);
				else selectedIndex = Math.min(items.length - 1, selectedIndex + visibleItems);
			} else if (keybindings.matches(data, "tui.select.cancel")) {
				done(null);
			} else if (keybindings.matches(data, "tui.select.confirm")) {
				if (selectedIndex < detailItems.length) toggleDetails(selectedIndex);
				else done(items[selectedIndex].value);
			} else if (matchesKey(data, Key.space) && selectedIndex < detailItems.length) {
				toggleDetails(selectedIndex);
			}
			tui.requestRender();
		},
		invalidate(): void {
			summaryText.invalidate();
			for (const text of detailText) text.invalidate();
		},
	};
}

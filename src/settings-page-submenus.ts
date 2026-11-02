import type { Theme } from "@earendil-works/pi-coding-agent";
import { type Component, Container, type SelectItem, SelectList, Text } from "@earendil-works/pi-tui";
import {
	formatPreferenceCount,
	MAX_VISIBLE_SETTINGS,
	type PermissionSettingsView,
	type SettingsTui,
} from "./settings-page-model.ts";

export function createSelectComponent(
	tui: SettingsTui,
	theme: Theme,
	title: string,
	items: readonly SelectItem[],
	onSelect: (value: string) => void,
	onCancel: () => void,
): Component {
	const selectItems = items.map((item) => ({ ...item }));
	const container = new Container();
	container.addChild(new Text(theme.fg("accent", theme.bold(title)), 1, 0));

	const selectList = new SelectList(selectItems, Math.min(Math.max(selectItems.length, 1), MAX_VISIBLE_SETTINGS), {
		selectedPrefix: (text) => theme.fg("accent", text),
		selectedText: (text) => theme.fg("accent", text),
		description: (text) => theme.fg("muted", text),
		scrollInfo: (text) => theme.fg("dim", text),
		noMatch: (text) => theme.fg("warning", text),
	});
	selectList.onSelect = (item) => onSelect(item.value);
	selectList.onCancel = onCancel;
	container.addChild(selectList);
	container.addChild(new Text(theme.fg("dim", "↑/↓ navigate · enter select · esc back"), 1, 0));

	return {
		render(width: number): string[] {
			return container.render(width);
		},
		handleInput(data: string): void {
			selectList.handleInput(data);
			tui.requestRender();
		},
		invalidate(): void {
			container.invalidate();
		},
	};
}

export function createRulesComponent(
	tui: SettingsTui,
	theme: Theme,
	state: PermissionSettingsView,
	onSelect: (value: "edit" | "list" | "reset") => void,
	onCancel: () => void,
): Component {
	const items: SelectItem[] = [];
	for (const pattern of state.allowedCommands) {
		items.push({
			value: "edit",
			label: `Allowed  ${pattern}`,
			description: "User-defined allow pattern. Select to edit all command rules.",
		});
	}
	for (const pattern of state.disallowedCommands) {
		items.push({
			value: "edit",
			label: `Denied   ${pattern}`,
			description: "User-defined deny pattern. Select to edit all command rules.",
		});
	}
	if (items.length === 0) {
		items.push({
			value: "info:no-rules",
			label: "No user-defined command patterns",
			description: "Only the built-in permission gate rules are active.",
		});
	}
	items.push(
		{
			value: "edit",
			label: "Edit command patterns",
			description: "Edit allowedCommands and disallowedCommands, then choose where to save them.",
		},
		{
			value: "list",
			label: "Show full rule report",
			description: "Display user rules plus built-in soft-deny and hard-deny categories.",
		},
		{
			value: "reset",
			label: "Reset current rules",
			description: `Restore the built-in allowlist for the active ${state.ruleScope} scope.`,
		},
	);

	return createSelectComponent(
		tui,
		theme,
		`Command rules (${state.ruleScope})`,
		items,
		(value) => {
			if (value === "edit" || value === "list" || value === "reset") onSelect(value);
		},
		onCancel,
	);
}

export function createPreferencesComponent(
	tui: SettingsTui,
	theme: Theme,
	state: PermissionSettingsView,
	onSelect: (value: "edit" | "add" | "list" | "clear") => void,
	onCancel: () => void,
): Component {
	const items: SelectItem[] = [];
	const notes = state.preferences
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean);
	for (const note of notes) {
		items.push({
			value: "edit",
			label: note,
			description: "User-authored classifier policy note. Select to edit all preference notes.",
		});
	}
	if (items.length === 0) {
		items.push({
			value: "info:no-preferences",
			label: "No classifier preferences configured",
			description: "The classifier is using the built-in safety policy only.",
		});
	}
	items.push(
		{
			value: "edit",
			label: "Edit preference notes",
			description: "Edit the complete preference note file.",
		},
		{
			value: "add",
			label: "Add a preference note",
			description: "Append a new user-authored policy note.",
		},
		{
			value: "list",
			label: "View preference notes",
			description: "Open the notes without saving changes.",
		},
		{
			value: "clear",
			label: "Clear preference notes",
			description: "Remove all user-authored classifier preference notes.",
		},
	);

	return createSelectComponent(
		tui,
		theme,
		`Classifier preferences (${formatPreferenceCount(state.preferences)})`,
		items,
		(value) => {
			if (value === "edit" || value === "add" || value === "list" || value === "clear") onSelect(value);
		},
		onCancel,
	);
}

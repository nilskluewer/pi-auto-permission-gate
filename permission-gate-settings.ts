import { getSettingsListTheme, type ExtensionContext, type Theme } from "@earendil-works/pi-coding-agent";
import {
	Container,
	SelectList,
	SettingsList,
	Text,
	type Component,
	type SelectItem,
	type SettingItem,
} from "@earendil-works/pi-tui";

export type PermissionSettingsAction =
	| { type: "auto-mode"; value: "on" | "off" }
	| { type: "classifier-model"; value: string }
	| { type: "classifier-thinking"; value: string }
	| { type: "command-rules"; value: "edit" | "list" | "reset" }
	| { type: "preferences"; value: "edit" | "add" | "list" | "clear" }
	| { type: "prompt" };

export type PermissionSettingsOption = SelectItem;

export interface PermissionSettingsView {
	autoModeEnabled: boolean;
	classifierModel: string;
	classifierModelOptions: readonly PermissionSettingsOption[];
	classifierThinking: string;
	classifierThinkingOptions: readonly PermissionSettingsOption[];
	ruleScope: string;
	allowedCommands: readonly string[];
	disallowedCommands: readonly string[];
	preferences: string;
}

type Tui = { requestRender: () => void };

const MAX_VISIBLE_SETTINGS = 12;

export async function openPermissionSettings(
	ctx: Pick<ExtensionContext, "mode" | "hasUI" | "ui">,
	state: PermissionSettingsView,
): Promise<PermissionSettingsAction | undefined> {
	if (!ctx.hasUI) return undefined;

	if (ctx.mode === "tui") {
		const result = await ctx.ui.custom<PermissionSettingsAction | null>((tui, theme, _keybindings, done) =>
			createSettingsComponent(tui, theme, state, done),
		);
		return result ?? undefined;
	}

	return openPermissionSettingsWithDialogs(ctx, state);
}

function createSettingsComponent(
	tui: Tui,
	theme: Theme,
	state: PermissionSettingsView,
	done: (result: PermissionSettingsAction | null) => void,
): Component {
	const items: SettingItem[] = [
		{
			id: "auto-mode",
			label: "Automatic safety decisions",
			description: "Let the configured classifier decide whether soft-deny bash commands may run.",
			currentValue: state.autoModeEnabled ? "on" : "off",
			values: ["on", "off"],
		},
		{
			id: "classifier-model",
			label: "Classifier model",
			description: "Choose the authenticated text model used for automatic safety decisions.",
			currentValue: state.classifierModel,
			submenu: (_currentValue, submenuDone) =>
				createSelectComponent(
					tui,
					theme,
					"Select the auto-mode classifier model",
					state.classifierModelOptions,
					(value) => value !== "info:no-models" && submenuDone(value),
					() => submenuDone(),
				),
		},
		{
			id: "classifier-thinking",
			label: "Classifier thinking",
			description: "Configure reasoning effort independently from Pi's active conversation model.",
			currentValue: state.classifierThinking,
			submenu: (_currentValue, submenuDone) =>
				createSelectComponent(
					tui,
					theme,
					"Select the auto-mode classifier thinking level",
					state.classifierThinkingOptions,
					(value) => submenuDone(value),
					() => submenuDone(),
				),
		},
		{
			id: "command-rules",
			label: "Command rules",
			description: `View and edit user-defined allow and deny patterns (${state.ruleScope} scope).`,
			currentValue: `${state.allowedCommands.length} allowed / ${state.disallowedCommands.length} denied`,
			submenu: (_currentValue, submenuDone) =>
				createRulesComponent(tui, theme, state, (value) => submenuDone(value), () => submenuDone()),
		},
		{
			id: "preferences",
			label: "Classifier preferences",
			description: "Add user-authored policy notes that refine soft-deny decisions without overriding hard denies.",
			currentValue: formatPreferenceCount(state.preferences),
			submenu: (_currentValue, submenuDone) =>
				createPreferencesComponent(tui, theme, state, (value) => submenuDone(value), () => submenuDone()),
		},
		{
			id: "prompt",
			label: "View classifier prompt",
			description: "Open the complete system prompt and user prompt template used by auto mode.",
			currentValue: "open",
			values: ["open"],
		},
	];

	const container = new Container();
	container.addChild(new Text(theme.fg("accent", theme.bold("Permission Gate Settings")), 1, 0));
	container.addChild(
		new Text(
			theme.fg(
				"muted",
				"Configure the safety gate from one place. Select a row to change it or open its subpage.",
			),
			1,
			0,
		),
	);

	const settingsList = new SettingsList(
		items,
		Math.min(items.length, MAX_VISIBLE_SETTINGS),
		getSettingsListTheme(),
		(id, value) => {
			if (id === "auto-mode" && (value === "on" || value === "off")) {
				done({ type: "auto-mode", value });
			} else if (id === "classifier-model" && value !== "info:no-models") {
				done({ type: "classifier-model", value });
			} else if (id === "classifier-thinking") {
				done({ type: "classifier-thinking", value });
			} else if (id === "command-rules" && isCommandRulesAction(value)) {
				done({ type: "command-rules", value });
			} else if (id === "preferences" && isPreferencesAction(value)) {
				done({ type: "preferences", value });
			} else if (id === "prompt" && value === "open") {
				done({ type: "prompt" });
			}
		},
		() => done(null),
		{ enableSearch: true },
	);
	container.addChild(settingsList);
	container.addChild(
		new Text(
			theme.fg("dim", "↑/↓ navigate · type to search · enter/space change or open · esc close"),
			1,
			0,
		),
	);

	return {
		render(width: number): string[] {
			return container.render(width);
		},
		handleInput(data: string): void {
			settingsList.handleInput(data);
			tui.requestRender();
		},
		invalidate(): void {
			container.invalidate();
		},
	};
}

function createSelectComponent(
	tui: Tui,
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

function createRulesComponent(
	tui: Tui,
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

function createPreferencesComponent(
	tui: Tui,
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

async function openPermissionSettingsWithDialogs(
	ctx: Pick<ExtensionContext, "ui">,
	state: PermissionSettingsView,
): Promise<PermissionSettingsAction | undefined> {
	const cancel = "Cancel";
	const mainOptions = [
		`Automatic safety decisions - ${state.autoModeEnabled ? "on" : "off"}`,
		`Classifier model - ${state.classifierModel}`,
		`Classifier thinking - ${state.classifierThinking}`,
		`Command rules - ${state.allowedCommands.length} allowed / ${state.disallowedCommands.length} denied`,
		`Classifier preferences - ${formatPreferenceCount(state.preferences)}`,
		"View classifier prompt",
		cancel,
	];

	const choice = await ctx.ui.select("Permission Gate Settings", mainOptions);
	if (!choice || choice === cancel) return undefined;
	const index = mainOptions.indexOf(choice);
	if (index === 0) {
		const selected = await ctx.ui.select("Automatic safety decisions", [
			state.autoModeEnabled ? "on" : "off",
			state.autoModeEnabled ? "off" : "on",
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		return { type: "auto-mode", value: selected as "on" | "off" };
	}
	if (index === 1) {
		const selected = await ctx.ui.select("Select the auto-mode classifier model", [
			...state.classifierModelOptions.map((option) => option.label),
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		const option = state.classifierModelOptions.find((item) => item.label === selected);
		return option && option.value !== "info:no-models" ? { type: "classifier-model", value: option.value } : undefined;
	}
	if (index === 2) {
		const selected = await ctx.ui.select("Select the auto-mode classifier thinking level", [
			...state.classifierThinkingOptions.map((option) => option.label),
			cancel,
		]);
		if (!selected || selected === cancel) return undefined;
		const option = state.classifierThinkingOptions.find((item) => item.label === selected);
		return option ? { type: "classifier-thinking", value: option.value } : undefined;
	}
	if (index === 3) return openRulesWithDialogs(ctx, state, cancel);
	if (index === 4) return openPreferencesWithDialogs(ctx, state, cancel);
	if (index === 5) return { type: "prompt" };
	return undefined;
}

async function openRulesWithDialogs(
	ctx: Pick<ExtensionContext, "ui">,
	state: PermissionSettingsView,
	cancel: string,
): Promise<PermissionSettingsAction | undefined> {
	const visibleRules = [
		...state.allowedCommands.map((pattern) => `Allowed - ${pattern}`),
		...state.disallowedCommands.map((pattern) => `Denied - ${pattern}`),
	];
	const selected = await ctx.ui.select(`Command rules (${state.ruleScope})`, [
		...(visibleRules.length > 0 ? visibleRules : ["No user-defined command patterns"]),
		"Edit command patterns",
		"Show full rule report",
		"Reset current rules",
		cancel,
	]);
	if (!selected || selected === cancel || selected === "No user-defined command patterns") return undefined;
	if (selected === "Edit command patterns" || selected.startsWith("Allowed - ") || selected.startsWith("Denied - ")) {
		return { type: "command-rules", value: "edit" };
	}
	if (selected === "Show full rule report") return { type: "command-rules", value: "list" };
	if (selected === "Reset current rules") return { type: "command-rules", value: "reset" };
	return undefined;
}

async function openPreferencesWithDialogs(
	ctx: Pick<ExtensionContext, "ui">,
	state: PermissionSettingsView,
	cancel: string,
): Promise<PermissionSettingsAction | undefined> {
	const selected = await ctx.ui.select(`Classifier preferences (${formatPreferenceCount(state.preferences)})`, [
		...(state.preferences ? ["View current preference notes"] : ["No classifier preferences configured"]),
		"Edit preference notes",
		"Add a preference note",
		"Clear preference notes",
		cancel,
	]);
	if (!selected || selected === cancel || selected === "No classifier preferences configured") return undefined;
	if (selected === "View current preference notes") return { type: "preferences", value: "list" };
	if (selected === "Edit preference notes") return { type: "preferences", value: "edit" };
	if (selected === "Add a preference note") return { type: "preferences", value: "add" };
	if (selected === "Clear preference notes") return { type: "preferences", value: "clear" };
	return undefined;
}

function isCommandRulesAction(value: string): value is "edit" | "list" | "reset" {
	return value === "edit" || value === "list" || value === "reset";
}

function isPreferencesAction(value: string): value is "edit" | "add" | "list" | "clear" {
	return value === "edit" || value === "add" || value === "list" || value === "clear";
}

function formatPreferenceCount(preferences: string): string {
	const lines = preferences
		.split(/\r?\n/)
		.map((line) => line.trim())
		.filter(Boolean);
	if (lines.length === 0) return "none";
	return `${lines.length} note${lines.length === 1 ? "" : "s"}`;
}

import { getSettingsListTheme, type Theme } from "@earendil-works/pi-coding-agent";
import { type Component, Container, type SettingItem, SettingsList, Text } from "@earendil-works/pi-tui";
import {
	formatPreferenceCount,
	GATE_OFF_DESCRIPTION,
	MAX_VISIBLE_SETTINGS,
	type PermissionSettingsAction,
	type PermissionSettingsView,
	type SettingsTui,
} from "./settings-page-model.ts";
import { createPreferencesComponent, createRulesComponent, createSelectComponent } from "./settings-page-submenus.ts";

export function createSettingsComponent(
	tui: SettingsTui,
	theme: Theme,
	state: PermissionSettingsView,
	done: (result: PermissionSettingsAction | null) => void,
): Component {
	const items: SettingItem[] = [
		{
			id: "gate",
			label: "Permission gate",
			description: GATE_OFF_DESCRIPTION,
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
			id: "history-messages",
			label: "Context history messages",
			description: "Configure how many recent messages from the conversation the classifier receives.",
			currentValue: `${state.classifierHistoryMessages} message${state.classifierHistoryMessages === 1 ? "" : "s"}`,
			submenu: (_currentValue, submenuDone) =>
				createSelectComponent(
					tui,
					theme,
					"Select the number of context history messages for the classifier",
					state.classifierHistoryMessageOptions,
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
				createRulesComponent(
					tui,
					theme,
					state,
					(value) => submenuDone(value),
					() => submenuDone(),
				),
		},
		{
			id: "preferences",
			label: "Classifier preferences",
			description: "Add user-authored policy notes that refine soft-deny decisions without overriding hard denies.",
			currentValue: formatPreferenceCount(state.preferences),
			submenu: (_currentValue, submenuDone) =>
				createPreferencesComponent(
					tui,
					theme,
					state,
					(value) => submenuDone(value),
					() => submenuDone(),
				),
		},
		{
			id: "production-patterns",
			label: "Production patterns",
			description: "Project, bucket, and context patterns. Unknown targets stay critical.",
			currentValue: (state.productionPatterns ?? []).join(", "),
			values: ["edit"],
		},
		{
			id: "approval-wait",
			label: "Approval wait",
			description: "Stop waiting and leave the browser request open for a late answer.",
			currentValue: String(state.approvalWaitSeconds ?? 300),
			values: ["60", "120", "300", "600", "900", "1800"],
		},
		{
			id: "intent-grants",
			label: "Session intent grants",
			description: "List or revoke human-approved grants for this session.",
			currentValue: `${state.activeGrantCount ?? 0} active`,
			values: ["open"],
		},
		{
			id: "statistics",
			label: "Approval statistics",
			description: "Show prompt rates and grant savings over the last 14 days.",
			currentValue: "open",
			values: ["open"],
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
			theme.fg("muted", "Configure the safety gate from one place. Select a row to change it or open its subpage."),
			1,
			0,
		),
	);

	const settingsList = new SettingsList(
		items,
		Math.min(items.length, MAX_VISIBLE_SETTINGS),
		getSettingsListTheme(),
		(id, value) => {
			if (id === "gate" && (value === "on" || value === "off")) {
				done({ type: "gate", value });
			} else if (id === "classifier-model" && value !== "info:no-models") {
				done({ type: "classifier-model", value });
			} else if (id === "classifier-thinking") {
				done({ type: "classifier-thinking", value });
			} else if (id === "history-messages") {
				const count = Number.parseInt(value, 10);
				if (!Number.isNaN(count)) done({ type: "history-messages", value: count });
			} else if (id === "command-rules" && isCommandRulesAction(value)) {
				done({ type: "command-rules", value });
			} else if (id === "preferences" && isPreferencesAction(value)) {
				done({ type: "preferences", value });
			} else if (id === "approval-wait") {
				done({ type: "approval-wait", value: Number(value) });
			} else if (id === "production-patterns" || id === "intent-grants" || id === "statistics") {
				done({ type: id });
			} else if (id === "prompt" && value === "open") {
				done({ type: "prompt" });
			}
		},
		() => done(null),
		{ enableSearch: true },
	);
	// SettingsList renders its own key hint line.
	container.addChild(settingsList);

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

function isCommandRulesAction(value: string): value is "edit" | "list" | "reset" {
	return value === "edit" || value === "list" || value === "reset";
}

function isPreferencesAction(value: string): value is "edit" | "add" | "list" | "clear" {
	return value === "edit" || value === "add" || value === "list" || value === "clear";
}

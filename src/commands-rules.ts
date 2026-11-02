import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { notify } from "./gate-display.ts";
import type { GateState } from "./gate-state.ts";
import {
	cloneDefaultCommandRuleConfig,
	formatCommandRules,
	parseCommandRuleConfig,
	saveCommandRules,
} from "./persistence.ts";
import type { CommandRuleConfig } from "./types.ts";

export type PermissionRulesAction = "edit" | "list" | "reset";
export async function handlePermissionRulesCommand(
	gate: GateState,
	action: PermissionRulesAction,
	ctx: ExtensionContext,
): Promise<void> {
	if (action === "list") {
		notify(ctx, formatCommandRules(gate.ruleConfig, gate.ruleScope), "info");
		return;
	}

	if (action === "reset") {
		if (gate.ruleScope === "session") {
			gate.ruleConfig = cloneDefaultCommandRuleConfig();
			notify(ctx, "Permission gate session command rules reset.", "info");
			return;
		}

		const scope = gate.ruleScope;
		if (scope === "project" && !ctx.isProjectTrusted()) {
			notify(ctx, "Permission gate: project rules require a trusted project.", "error");
			return;
		}
		const resetConfig = cloneDefaultCommandRuleConfig();
		try {
			await saveCommandRules(gate.dependencies, scope, ctx.cwd, resetConfig);
		} catch (error) {
			notify(
				ctx,
				`Permission gate: could not reset ${scope} rules: ${error instanceof Error ? error.message : String(error)}`,
				"error",
			);
			return;
		}
		gate.ruleConfig = resetConfig;
		notify(ctx, `Permission gate ${scope} command rules reset.`, "info");
		return;
	}

	if (!ctx.hasUI) {
		notify(ctx, "/automode-settings needs an interactive UI to edit command rules.", "error");
		return;
	}

	let edited: string | undefined;
	try {
		edited = await ctx.ui.editor(
			"Permission gate rules JSON. Use shell-style * and ? patterns.",
			JSON.stringify(gate.ruleConfig, null, 2),
		);
	} catch (error) {
		notify(
			ctx,
			`Permission gate: rule editor failed: ${error instanceof Error ? error.message : String(error)}`,
			"error",
		);
		return;
	}
	if (edited === undefined) return;

	let nextConfig: CommandRuleConfig | undefined;
	try {
		nextConfig = parseCommandRuleConfig(JSON.parse(edited));
	} catch (error) {
		notify(
			ctx,
			`Permission gate: invalid rules JSON: ${error instanceof Error ? error.message : String(error)}`,
			"error",
		);
		return;
	}
	if (!nextConfig) {
		notify(
			ctx,
			"Permission gate: rules must contain string arrays named allowedCommands and disallowedCommands.",
			"error",
		);
		return;
	}

	const saveOptions = ["Apply to this session only", "Save as global default"];
	if (ctx.isProjectTrusted()) saveOptions.push("Save as project default");
	saveOptions.push("Cancel");
	const choice = await ctx.ui.select("Save permission gate rules:", saveOptions);
	if (!choice || choice === "Cancel") return;
	if (choice === "Apply to this session only") {
		gate.ruleConfig = nextConfig;
		gate.ruleScope = "session";
		notify(ctx, "Permission gate command rules applied to this session only.", "info");
		return;
	}

	const scope = choice === "Save as project default" ? "project" : "global";
	if (scope === "project" && !ctx.isProjectTrusted()) {
		notify(ctx, "Permission gate: project rules require a trusted project.", "error");
		return;
	}
	try {
		await saveCommandRules(gate.dependencies, scope, ctx.cwd, nextConfig);
	} catch (error) {
		notify(
			ctx,
			`Permission gate: could not save ${scope} rules: ${error instanceof Error ? error.message : String(error)}`,
			"error",
		);
		return;
	}
	gate.ruleConfig = nextConfig;
	gate.ruleScope = scope;
	notify(ctx, `Permission gate command rules saved as the ${scope} default.`, "info");
}

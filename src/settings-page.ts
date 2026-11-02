import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { createSettingsComponent } from "./settings-page-component.ts";
import { openPermissionSettingsWithDialogs } from "./settings-page-dialogs.ts";
import type { PermissionSettingsAction, PermissionSettingsView } from "./settings-page-model.ts";

export type {
	PermissionSettingsAction,
	PermissionSettingsOption,
	PermissionSettingsView,
} from "./settings-page-model.ts";

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

import { type ExtensionContext, isToolCallEventType } from "@earendil-works/pi-coding-agent";
import type { GateState } from "./gate-state.ts";
import { reviewBash } from "./review.ts";

export function registerToolCallHook(gate: GateState): void {
	gate.pi.on("tool_call", async (event, outerContext) => {
		if (!gate.gateEnabled || !isToolCallEventType("bash", event)) return undefined;
		const controller = new AbortController();
		gate.activeReviews.add(controller);
		const signal = outerContext.signal ? AbortSignal.any([outerContext.signal, controller.signal]) : controller.signal;
		const ctx: ExtensionContext & { signal: AbortSignal } = { ...outerContext, signal };
		const disabled = () => controller.signal.reason === gate.disabledReason;

		let onDisabled: () => void = () => {};
		const cancelled = new Promise<undefined>((resolve) => {
			onDisabled = () => resolve(undefined);
			controller.signal.addEventListener("abort", onDisabled, { once: true });
		});
		try {
			const result = await Promise.race([reviewBash(gate, event, ctx, () => controller.signal.aborted), cancelled]);
			return disabled()
				? undefined
				: signal.aborted
					? { block: true, reason: "Blocked by the permission gate: the request was cancelled." }
					: result;
		} finally {
			controller.signal.removeEventListener("abort", onDisabled);
			gate.activeReviews.delete(controller);
		}
	});
}

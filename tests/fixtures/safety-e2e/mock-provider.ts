// Trusted E2E fixture only. No HTTP client, generated code, or alternate bash implementation.
import { readFileSync, appendFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { Type, createAssistantMessageEventStream } from "@earendil-works/pi-ai";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  const root = process.env.PI_SAFETY_E2E_ROOT;
  if (!root || readFileSync(join(root, "fixture-marker"), "utf8") !== "isolated safety acceptance\n" ||
      resolve(process.cwd()) !== join(root, "repo") ||
      !process.env.PI_CODING_AGENT_DIR?.startsWith(root + "/")) {
    throw new Error("Safety fixture requires the harness's disposable workspace/config");
  }
  const actions = JSON.parse(readFileSync(process.env.PI_SAFETY_E2E_ACTIONS!, "utf8"));
  const audit = (data: unknown) => appendFileSync(process.env.PI_SAFETY_E2E_AUDIT!, JSON.stringify(data) + "\n");
  const issued = new Set<string>();
  pi.on("session_start", (_event, ctx) => {
    const state = JSON.parse(readFileSync(join(process.env.PI_CODING_AGENT_DIR!, "permission-gate.json"), "utf8"));
    if (state.autoModeEnabled !== false || state.dcg?.mode !== "off") throw new Error("Fixture requires manual mode and DCG off");
    audit({ type: "startup", mode: ctx.mode, hasUI: ctx.hasUI, cwd: ctx.cwd });
  });
  pi.registerTool({
    name: "safety_orchestrate",
    label: "Safety E2E orchestration",
    description: "Test fixture: delegates one canned command through the public nested-tool boundary.",
    parameters: Type.Object({ command: Type.String() }),
    async execute(_id, args, signal, _onUpdate, ctx) {
      if (!Object.values(actions).some((action: any) => action.nested && action.command === args.command)) {
        throw new Error("Not a canned nested action");
      }
      audit({ type: "nested", command: args.command });
      // Same boundary codemode uses; deliberately no eval and no hidden subprocess bypass.
      return await ctx.executeTool("bash", { command: args.command }, { signal });
    },
  });
  pi.registerProvider("safety-e2e", {
    baseUrl: "https://fixture.invalid",
    apiKey: "fixture-not-a-credential",
    api: "safety-e2e-canned",
    models: [{ id: "canned", name: "Offline safety fixture", reasoning: false, input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }, contextWindow: 64000, maxTokens: 1024 }],
    streamSimple(model, context, options) {
      const stream = createAssistantMessageEventStream();
      void (async () => {
        const message: any = { role: "assistant", api: model.api, provider: model.provider, model: model.id,
          timestamp: Date.now(), content: [], stopReason: "pending",
          usage: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, totalTokens: 0,
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } } };
        try {
          const user = [...context.messages].reverse().find((entry) => entry.role === "user");
          const text = typeof user?.content === "string" ? user.content :
            (user?.content as any[])?.filter((part) => part.type === "text").map((part) => part.text).join("");
          const match = /^safety-e2e:([a-z-]+):([a-z0-9-]+)$/.exec(text ?? "");
          if (!match || !actions[match[1]]) throw new Error("Unknown fixture prompt (classifier calls are forbidden)");
          const key = match[0];
          const action = actions[match[1]];
          let payload: any = { action: match[1], followup: issued.has(key) };
          payload = (await options?.onPayload?.(payload, model)) ?? payload;
          await options?.onResponse?.({ status: 200, headers: new Headers() }, model);
          audit({ type: "provider", action: match[1], followup: issued.has(key), payload });
          if (options?.signal?.aborted) throw new Error("aborted");
          stream.push({ type: "start", partial: message });
          if (!issued.has(key)) {
            issued.add(key);
            const call = { type: "toolCall" as const, id: `fixture-${match[2]}`, name: action.nested ? "safety_orchestrate" : "bash",
              arguments: { command: action.command } };
            message.content.push({ ...call, arguments: {} });
            stream.push({ type: "toolcall_start", contentIndex: 0, partial: message });
            message.content[0] = call;
            stream.push({ type: "toolcall_delta", contentIndex: 0, delta: JSON.stringify(call.arguments), partial: message });
            stream.push({ type: "toolcall_end", contentIndex: 0, toolCall: call, partial: message });
            message.stopReason = "toolUse";
          } else {
            message.content.push({ type: "text", text: "" });
            stream.push({ type: "text_start", contentIndex: 0, partial: message });
            message.content[0].text = "fixture complete";
            stream.push({ type: "text_delta", contentIndex: 0, delta: "fixture complete", partial: message });
            stream.push({ type: "text_end", contentIndex: 0, content: "fixture complete", partial: message });
            message.stopReason = "stop";
          }
          await options?.onProviderStreamEvent?.({ fixture: match[1] }, model);
          stream.push({ type: "done", reason: message.stopReason, message });
        } catch (error) {
          message.stopReason = options?.signal?.aborted ? "aborted" : "error";
          message.errorMessage = String(error);
          stream.push({ type: "error", reason: message.stopReason, error: message });
        } finally { stream.end(); }
      })();
      return stream;
    },
  });
}

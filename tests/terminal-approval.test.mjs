// Covers compact approval rendering, disclosure, and terminal/RPC interaction.
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import test from "node:test";
import { getKeybindings, KeybindingsManager, TUI_KEYBINDINGS, visibleWidth } from "@earendil-works/pi-tui";
import { selectTerminalApproval } from "../src/terminal-approval.ts";
import { createApprovalComponent } from "../src/terminal-approval-component.ts";
import { createTerminalUI, theme } from "./helpers/terminal-ui.mjs";

const DOWN = "\x1b[B";
const UP = "\x1b[A";
const ENTER = "\r";
const ESCAPE = "\x1b";
const PAGE_DOWN = "\x1b[6~";
const PAGE_UP = "\x1b[5~";
const view = {
	summary: "Execution summary: Runs local verification code.",
	facts:
		"Recommended: deny · Permission gate: MEDIUM risk\nProject: project\nStatic references only; 1 inspection note.",
	details: [
		{ label: "Files and paths", text: Array.from({ length: 100 }, (_, i) => `file-${i}.py`).join("\n") },
		{ label: "Command / inline code", text: Array.from({ length: 100 }, (_, i) => `print(${i})`).join("\n") },
	],
};
const request = {
	tldr: "Runs local verification code.",
	risk: "medium",
	recommendation: "deny",
	command: `${"print('verification')\n".repeat(100)}END_OF_COMMAND`,
	paths: [{ path: "/tmp/project/main.py", role: "code", inspected: true }],
	pathNotes: ["Dynamic code loading was found."],
};

function createComponent(options = ["No", "Yes", "Redirect…"], state = view, keybindings = getKeybindings()) {
	const ui = createTerminalUI();
	const answers = [];
	const component = createApprovalComponent(ui.tui, theme, keybindings, state, options, (value) => answers.push(value));
	return { component, answers, ui };
}

function keys(component, ...data) {
	for (const key of data) component.handleInput(key);
}

test("the default view is compact, details are collapsed, and Enter denies", () => {
	const { component, answers } = createComponent();
	const lines = component.render(90);
	assert.ok(lines.length < 20);
	assert.match(lines.join("\n"), /Runs local verification code/);
	assert.match(lines.join("\n"), /MEDIUM risk/);
	assert.match(lines.join("\n"), /▸ Files and paths/);
	assert.match(lines.join("\n"), /▸ Command \/ inline code/);
	assert.doesNotMatch(lines.join("\n"), /file-0|print\(0\)/);
	const filesIndex = lines.findIndex((line) => line.includes("▸ Files and paths"));
	const commandIndex = lines.findIndex((line) => line.includes("▸ Command / inline code"));
	const questionIndex = lines.findIndex((line) => line.startsWith("Allow this command to run?"));
	const noIndex = lines.findIndex((line) => line.startsWith("→ No"));
	assert.ok(filesIndex < commandIndex && commandIndex < questionIndex && questionIndex < noIndex);
	assert.equal(lines.filter((line) => line.startsWith("→ ")).length, 1);
	component.handleInput(ENTER);
	assert.deepEqual(answers, ["No"]);
});

test("disclosures toggle with Enter and Space, scroll completely, and keep choices visible", () => {
	const { component, answers, ui } = createComponent();
	keys(component, UP, UP, ENTER);
	let output = component.render(90).join("\n");
	assert.match(output, /▾ Files and paths/);
	assert.match(output, /file-0\.py/);
	assert.match(output, /Yes/);
	assert.ok(output.indexOf("file-0.py") < output.indexOf("Allow this command to run?"));
	assert.equal(output.split("\n").filter((line) => line.startsWith("→ ")).length, 1);
	assert.deepEqual(answers, []);
	for (let i = 0; i < 20; i++) {
		component.handleInput(PAGE_DOWN);
		component.render(90);
	}
	output = component.render(90).join("\n");
	assert.match(output, /file-99\.py/);
	assert.doesNotMatch(output, /file-0\.py/);
	component.handleInput(PAGE_UP);
	assert.doesNotMatch(component.render(90).join("\n"), /file-99\.py/);
	keys(component, " ");
	assert.doesNotMatch(component.render(90).join("\n"), /file-\d+\.py/);
	keys(component, DOWN, ENTER);
	output = component.render(90).join("\n");
	assert.match(output, /print\(0\)/);
	assert.ok(output.indexOf("print(0)") < output.indexOf("Allow this command to run?"));
	assert.doesNotMatch(output, /file-\d+\.py/);
	keys(component, DOWN, DOWN, ENTER);
	assert.deepEqual(answers, ["Yes"]);
	assert.ok(ui.renders > 0);
});

test("approval scopes and redirect retain their exact values; Escape never approves", () => {
	const options = ["No", "Yes", "Yes, and lift lockdown", "Yes, for this session: local tests", "Redirect…"];
	for (let index = 0; index < options.length; index++) {
		const { component, answers } = createComponent(options);
		for (let i = 0; i < index; i++) component.handleInput(DOWN);
		component.handleInput(ENTER);
		assert.deepEqual(answers, [options[index]]);
	}
	const { component, answers } = createComponent();
	keys(component, DOWN, ESCAPE);
	assert.deepEqual(answers, [null]);
});

test("rendering fits narrow and Unicode widths, bounds long summaries, and survives resize", () => {
	const { component } = createComponent(undefined, {
		...view,
		summary: `Execution summary: ${"検証 🙂 ".repeat(100)}`,
	});
	for (const width of [90, 40, 12]) {
		const lines = component.render(width);
		assert.ok(lines.every((line) => visibleWidth(line) <= width));
	}
	keys(component, UP, UP, ENTER);
	for (const width of [90, 40, 12, 90]) {
		component.invalidate();
		assert.ok(component.render(width).every((line) => visibleWidth(line) <= width));
	}
});

test("short terminals keep the selected choice and risk visible before and after resize", () => {
	const options = [
		"No",
		"Yes",
		"Yes, and lift lockdown",
		"Yes, for this session: local verification commands",
		"Redirect…",
	];
	const { component, ui } = createComponent(options);
	for (const rows of [12, 24, 30, 12]) {
		ui.tui.terminal.rows = rows;
		for (let index = 0; index < options.length + view.details.length; index++) {
			const lines = component.render(40);
			assert.ok(lines.length <= rows - 2);
			assert.match(lines.join("\n"), /MEDIUM risk/);
			assert.ok(lines.some((line) => line.startsWith("→ ")));
			if (index >= options.length) {
				component.handleInput(ENTER);
				assert.ok(component.render(40).length <= rows - 2);
			}
			component.handleInput(DOWN);
		}
	}
});

test("injected bindings take precedence over the Space disclosure shortcut", () => {
	const bindings = new KeybindingsManager(TUI_KEYBINDINGS, {
		"tui.select.up": "k",
		"tui.select.down": "j",
		"tui.select.confirm": "space",
		"tui.select.cancel": "x",
	});
	const { component, answers } = createComponent(undefined, view, bindings);
	keys(component, "j", " ");
	assert.deepEqual(answers, ["Yes"]);
	const disclosure = createComponent(undefined, view, bindings);
	keys(disclosure.component, "k", "k", " ");
	assert.match(disclosure.component.render(90).join("\n"), /file-0\.py/);
	assert.deepEqual(disclosure.answers, []);
	keys(disclosure.component, "x");
	assert.deepEqual(disclosure.answers, [null]);
	const navigation = new KeybindingsManager(TUI_KEYBINDINGS, { "tui.select.down": "space" });
	const navigated = createComponent(undefined, view, navigation);
	keys(navigated.component, " ", ENTER);
	assert.deepEqual(navigated.answers, ["Yes"]);
});

test("terminal details preserve the full command, project and inspection limitations", async () => {
	const ui = createTerminalUI();
	const ctrl = new AbortController();
	const result = selectTerminalApproval({ mode: "tui", cwd: "/tmp/project", ui }, request, ["No", "Yes"], ctrl.signal);
	const component = await ui.ready;
	assert.doesNotMatch(component.render(100).join("\n"), /main\.py|END_OF_COMMAND/);
	keys(component, UP, UP, ENTER);
	assert.match(component.render(100).join("\n"), /Dynamic code loading was found/);
	keys(component, DOWN, ENTER);
	component.render(100);
	for (let i = 0; i < 30; i++) {
		component.handleInput(PAGE_DOWN);
		component.render(100);
	}
	assert.match(component.render(100).join("\n"), /END_OF_COMMAND/);
	component.handleInput(ESCAPE);
	assert.equal(await result, undefined);
	assert.equal(getEventListeners(ctrl.signal, "abort").length, 0);
});

test("terminal cancellation closes the component and removes its abort listener", async () => {
	const ui = createTerminalUI();
	const ctrl = new AbortController();
	const result = selectTerminalApproval({ mode: "tui", cwd: "/tmp/project", ui }, request, ["No", "Yes"], ctrl.signal);
	await ui.ready;
	assert.equal(getEventListeners(ctrl.signal, "abort").length, 1);
	ctrl.abort();
	assert.equal(await result, undefined);
	assert.equal(ui.completions, 1);
	assert.equal(getEventListeners(ctrl.signal, "abort").length, 0);
	const alreadyAborted = selectTerminalApproval(
		{ mode: "tui", cwd: "/tmp/project", ui: {} },
		request,
		["No"],
		ctrl.signal,
	);
	assert.equal(await alreadyAborted, undefined);
});

test("RPC starts compact and details return to the same explicit approval choices", async () => {
	const calls = [];
	const choices = ["Show files and paths…", "Back", "Show command / inline code…", "Back", "Yes"];
	const signal = new AbortController().signal;
	const ui = {
		async select(title, options, settings) {
			calls.push({ title, options });
			assert.equal(settings.signal, signal);
			return choices.shift();
		},
	};
	assert.equal(
		await selectTerminalApproval({ mode: "rpc", cwd: "/tmp/project", ui }, request, ["No", "Yes"], signal),
		"Yes",
	);
	assert.doesNotMatch(calls[0].title, /main\.py|print\('verification'\)|END_OF_COMMAND/);
	assert.match(calls[1].title, /main\.py/);
	assert.match(calls[1].title, /Dynamic code loading was found/);
	assert.match(calls[3].title, /END_OF_COMMAND/);
	assert.equal(calls[0].title, calls[4].title);
});

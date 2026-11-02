import { basename, isAbsolute } from "node:path";

export const INTERPRETER =
	/^(?:python(?:\d+(?:\.\d+)*)?|node|nodejs|bun|deno|bash|sh|zsh|dash|fish|ruby|perl|php|lua|Rscript)$/;
export const SCRIPT = /\.(?:py|[cm]?js|[cm]?ts|tsx|jsx|sh|bash|zsh|rb|pl|php|lua|r)$/i;
export const SHELL_BRANCH = /^(?:if|then|elif|else|for|while|until|do|case|select|function|coproc)$/;
export const localExecutable = (word: string): boolean =>
	word.includes("/") && (!isAbsolute(word) || !/^\/(?:usr\/)?s?bin\//.test(word) || SCRIPT.test(word));
export const DYNAMIC = /[$`*?[\]{}]/;
export const LAUNCHER = /^(?:env|rtk|uv|run|sudo|command|exec|timeout|nice|time|nohup|stdbuf)$/;
export const OPTION_VALUE =
	/^(?:-u|-n|--unset|--user|--group|--project|--directory|--package|--with|--with-editable|--with-requirements|--extra|--python)$/;
// Preserve word boundaries and quote contents for display. This intentionally does not
// claim to understand expansions, heredocs, branches, aliases, or shell functions.
export function shellWords(command: string): string[] {
	const words: string[] = [];
	let value = "",
		quote = "",
		started = false;
	const flush = () => {
		if (started) words.push(value);
		value = "";
		started = false;
	};
	for (let i = 0; i < command.length; i++) {
		const c = command[i];
		if (c === "\\" && quote !== "'") {
			started = true;
			if (i + 1 < command.length) value += command[++i];
		} else if (quote) {
			if (c === quote) quote = "";
			else value += c;
		} else if (c === "'" || c === '"') {
			quote = c;
			started = true;
		} else if (/\s/.test(c) || /[;&|<>()]/.test(c)) {
			flush();
			if (/[;&|<>\n()]/.test(c)) words.push(c);
		} else {
			value += c;
			started = true;
		}
	}
	flush();
	return words;
}

export function codeReviewReasons(command: string): string[] {
	const words = shellWords(command);
	let start = true;
	for (let index = 0; index < words.length; index++) {
		const word = words[index];
		if (start && word.startsWith("-")) {
			if (/^(?:-S|--split-string)(?:=|$)/.test(word)) return ["interpreter or script execution"];
			if (OPTION_VALUE.test(word)) index++;
			continue;
		}
		if (start && /^\d+(?:\.\d+)?[smh]?$/.test(word)) continue;
		if (/^[;&|\n()]$/.test(word)) {
			start = true;
			continue;
		}
		if (start && localExecutable(word) && !/^[A-Za-z_]\w*=/.test(word)) return ["interpreter or script execution"];
		if (start && (/^[A-Za-z_]\w*=/.test(word) || LAUNCHER.test(basename(word)))) continue;
		if (start && SHELL_BRANCH.test(word)) return ["shell syntax requires classifier assessment"];
		if (start && (INTERPRETER.test(basename(word)) || /^(?:source|\.|eval)$/.test(word) || localExecutable(word))) {
			return ["interpreter or script execution"];
		}
		start = false;
	}
	return [];
}

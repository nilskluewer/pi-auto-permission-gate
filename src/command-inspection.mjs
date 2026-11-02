// Static evidence for permission review, not a shell parser or a sandbox.
// Never execute code, expand shell expressions, or fetch remote dependencies.

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, realpath, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";

export const INSPECTION_LIMITS = Object.freeze({
	files: 16,
	bytes: 64 * 1024,
	depth: 4,
	paths: 256,
});
const INTERPRETER =
	/^(?:python(?:\d+(?:\.\d+)*)?|node|nodejs|bun|deno|bash|sh|zsh|dash|fish|ruby|perl|php|lua|Rscript)$/;
const SCRIPT = /\.(?:py|[cm]?js|[cm]?ts|tsx|jsx|sh|bash|zsh|rb|pl|php|lua|r)$/i;
const SHELL_BRANCH = /^(?:if|then|elif|else|for|while|until|do|case|select|function|coproc)$/;
const localExecutable = (word) =>
	word.includes("/") && (!isAbsolute(word) || !/^\/(?:usr\/)?s?bin\//.test(word) || SCRIPT.test(word));
const DYNAMIC = /[$`*?[\]{}]/;
const LAUNCHER = /^(?:env|rtk|uv|run|sudo|command|exec|timeout|nice|time|nohup|stdbuf)$/;
const OPTION_VALUE =
	/^(?:-u|-n|--unset|--user|--group|--project|--directory|--package|--with|--with-editable|--with-requirements|--extra|--python)$/;
const SECRET =
	/^(?:\.env(?:\..*)?|id_(?:rsa|ed25519|ecdsa)(?:\.pub)?|credentials(?:\..*)?|auth\.json|approval-(?:queue\.json|history\.jsonl)|.*\.(?:pem|key|p12|pfx))$/i;
const sensitivePath = (path) =>
	SECRET.test(basename(path)) || /(?:^|\/)(?:\.ssh|\.aws|\.azure|\.kube)(?:\/|$)|\/\.config\/gcloud\//.test(path);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

// Preserve word boundaries and quote contents for display. This intentionally does not
// claim to understand expansions, heredocs, branches, aliases, or shell functions.
export function shellWords(command) {
	const words = [];
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

export function codeReviewReasons(command) {
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

async function readRegularFile(path, maxBytes) {
	const file = await open(path, constants.O_RDONLY | constants.O_NONBLOCK | constants.O_NOFOLLOW);
	try {
		const info = await file.stat();
		if (!info.isFile()) throw new Error("not a regular file");
		if (info.size > maxBytes) throw new Error("inspection byte limit exceeded");
		// Bound the actual read too: a file can grow after stat().
		const buffer = Buffer.alloc(maxBytes + 1);
		let size = 0;
		while (size < buffer.length) {
			const { bytesRead } = await file.read(buffer, size, buffer.length - size, null);
			if (!bytesRead) break;
			size += bytesRead;
		}
		if (size > maxBytes) throw new Error("inspection byte limit exceeded");
		const bytes = buffer.subarray(0, size);
		if (bytes.includes(0)) throw new Error("binary file; code was not inspected");
		return { content: bytes.toString("utf8"), digest: hash(bytes) };
	} finally {
		await file.close();
	}
}

function localPath(value, cwd) {
	return resolve(cwd, value === "~" ? homedir() : value.startsWith("~/") ? join(homedir(), value.slice(2)) : value);
}

export async function inspectCommand(command, cwd) {
	const paths = new Map();
	const notes = new Set([
		"External packages, shell profiles, aliases, and runtime-created code are not included in static inspection.",
		"Local dependency discovery supports common shell, Python, and JavaScript/TypeScript references; dynamic or unsupported import forms may be missing.",
	]);
	const files = [];
	const fingerprints = new Map();
	const queued = new Set();
	const queue = [];
	const inlineSources = [];
	let bytes = 0;
	let pathBytes = 0;
	const add = (value, role, base = cwd) => {
		if (!value || /^(?:[a-z][a-z\d+.-]*:\/\/|data:)/i.test(value)) return;
		const dynamic = DYNAMIC.test(value);
		const path = dynamic ? value : localPath(value, base);
		if (paths.has(path)) {
			const entry = paths.get(path);
			if (!entry.role.split(", ").includes(role)) entry.role += `, ${role}`;
			return entry;
		}
		if (
			path.length > 4096 ||
			paths.size >= INSPECTION_LIMITS.paths ||
			pathBytes + Buffer.byteLength(path) > 24 * 1024
		) {
			notes.add("Path display limit reached; the path list is incomplete.");
			return;
		}
		pathBytes += Buffer.byteLength(path);
		const entry = {
			path,
			role,
			inspected: false,
			...(dynamic ? { unresolved: true } : {}),
		};
		paths.set(path, entry);
		if (dynamic) notes.add("Some paths contain runtime expressions or globs and could not be resolved.");
		return entry;
	};
	const enqueue = (value, role, base, depth = 0) => {
		const entry = add(value, role, base);
		if (!entry || entry.unresolved || queued.has(entry.path)) return;
		queued.add(entry.path);
		queue.push({ entry, depth });
	};
	add(cwd, "working directory");
	const scanShell = async (shell, shellCwd, depth = 0) => {
		const allWords = shellWords(shell);
		const words = allWords.slice(0, 4096);
		if (allWords.length > words.length) notes.add("Command word limit reached; inspection is incomplete.");
		let base = shellCwd;
		let start = true;
		let activeCommand = "";
		const inlineWords = new Set();
		for (let i = 0; i < words.length; i++) {
			if (inlineWords.has(i)) continue;
			const word = words[i];
			const commandWord = start;
			if (start && word.startsWith("-")) {
				if (/^(?:-S|--split-string)$/.test(word) && words[i + 1]) {
					inlineSources.push({ content: words[++i], base, depth, interpreter: "sh" });
					notes.add("env split-string execution was found; its runtime expansion may change the invocation.");
				} else if (OPTION_VALUE.test(word) && words[i + 1]) {
					const value = words[++i];
					if (value.includes("/") || /^(?:--project|--directory|--with-requirements)$/.test(word))
						add(value, "launcher option path", base);
				}
				continue;
			}
			if (start && /^\d+(?:\.\d+)?[smh]?$/.test(word)) continue;
			if (/^[;&|\n()]$/.test(word)) {
				start = true;
				activeCommand = "";
				continue;
			}
			if (start && SHELL_BRANCH.test(word)) {
				notes.add("Shell control flow was found; static path resolution may differ from runtime.");
				continue;
			}
			if (start && word === "cd") {
				if (words[i + 1] === "--") i++;
				const target = words[i + 1];
				if (target && !/^[;&|]$/.test(target)) {
					add(target, "working directory", base);
					if (!DYNAMIC.test(target) && target !== "-") base = localPath(target, base);
					else
						notes.add(
							"The working directory changes dynamically; later paths may not resolve from the initial directory.",
						);
					i++;
				} else notes.add("The working directory changes without a static target; subsequent paths may be unresolved.");
				start = false;
				continue;
			}
			if (start && (INTERPRETER.test(basename(word)) || /^(?:source|\.)$/.test(word))) {
				let found = false;
				for (let j = i + 1; j < words.length && !/^[;&|\n<>]$/.test(words[j]); j++) {
					const arg = words[j];
					if (/^(?:-c|-e|--eval|-p|--print)$/.test(arg)) {
						if (words[j + 1]) {
							inlineSources.push({
								content: words[j + 1],
								base,
								depth,
								interpreter: basename(word),
							});
							inlineWords.add(j + 1);
						}
						found = true;
						break;
					}
					if (arg === "-" || arg === "-s") {
						found = true;
						break;
					}
					if (arg === "-m") {
						const module = words[j + 1];
						if (module && /^[\w.]+$/.test(module)) {
							const local = `${join(base, ...module.split("."))}.py`;
							try {
								if ((await stat(local)).isFile()) enqueue(local, "local module", base, depth);
								else throw new Error();
							} catch {
								notes.add(`Module execution uses code not included in this inspection: ${module}`);
							}
						}
						found = true;
						break;
					}
					if (/^(?:-r|--require|--import|-W|-X)$/.test(arg)) {
						if (/^(?:-r|--require|--import)$/.test(arg) && words[j + 1]?.startsWith("."))
							enqueue(words[j + 1], "preloaded module", base, depth);
						j++;
						continue;
					}
					if (arg.startsWith("-")) continue;
					enqueue(arg, "script", base, depth);
					found = true;
					break;
				}
				if (!found)
					notes.add("Interpreter input was not statically identified; inspect inline code or stdin in the command.");
			}
			if (start && localExecutable(word)) enqueue(word, "executable", base, depth);
			if (start && (/^[A-Za-z_]\w*=/.test(word) || LAUNCHER.test(basename(word)))) {
				// These words do not end the search for an invoked interpreter.
			} else {
				if (start) activeCommand = basename(word);
				start = false;
			}
			let candidate = word.replace(/^--?[\w-]+=/, "");
			if (/^[A-Za-z_]\w*=/.test(candidate)) candidate = candidate.slice(candidate.indexOf("=") + 1);
			if (!candidate || candidate.includes("\n") || /^[;&|<>()]$/.test(candidate)) continue;
			if (candidate.startsWith("-") || /^(?:[a-z][a-z\d+.-]*:\/\/)/i.test(candidate)) continue;
			const previous = words[i - 1] || "";
			const output =
				previous === ">" ||
				/^(?:--?(?:output|out|outfile|output-dir)|-o)(?:=|$)/.test(previous) ||
				/^--?(?:output|out|outfile|output-dir)=/.test(word);
			const pathOption =
				/^(?:--(?:file|config|input|path|directory|dir|dest|destination|source|target)|-i)$/.test(previous) ||
				/^--(?:file|config|input|path|directory|dir|dest|destination|source|target)=/.test(word);
			const role =
				activeCommand === "rm" || activeCommand === "rmdir"
					? "deletion target"
					: output
						? "output target"
						: previous === "<"
							? "input file"
							: "referenced path";
			const pathOperand = !commandWord && /^(?:rm|rmdir|mkdir|touch|cp|mv|cat|tee)$/.test(activeCommand);
			if (
				/^(?:\/|\.\.?\/|~\/)/.test(candidate) ||
				candidate.includes("/") ||
				/\.[A-Za-z\d]{1,10}$/.test(candidate) ||
				pathOperand ||
				pathOption ||
				output
			) {
				add(candidate, role, base);
			} else {
				try {
					const info = await stat(localPath(candidate, base));
					if (info.isFile() || info.isDirectory())
						add(candidate, info.isDirectory() ? "directory" : "referenced file", base);
				} catch {}
			}
		}
		if (/[`$]|<<|\b(?:eval|exec)\b/.test(shell))
			notes.add(
				"Runtime-generated commands, heredoc input, and variable-derived paths require assessment of the full command; the path list is static, not an execution trace.",
			);
		if (/\bcd\b/.test(shell) && /[|()]|\b(?:if|for|while)\b/.test(shell))
			notes.add(
				"Shell branching or subshells can change path resolution; listed absolute paths are candidates, not proven runtime targets.",
			);
	};
	await scanShell(command, cwd);
	const scanSource = async (content, source, depth) => {
		const sourceDir = dirname(source);
		if (/\.(?:sh|bash|zsh)$/.test(source) || /^#![^\n]*\b(?:ba|z|da)?sh\b/.test(content))
			await scanShell(content, cwd, depth + 1);
		const jsDependencies = [
			...content.matchAll(/(?:\b(?:from|import)\s*["']|\b(?:require|import)\s*\(\s*["'])(\.[^"']+)["']/g),
		];
		// List explicit path strings in code, but do not read arbitrary data files.
		for (const match of content.matchAll(
			/\b(?:open|readFile|writeFile|readFileSync|writeFileSync|unlink|remove|rmtree|Path|chdir|mkdir|access|stat|exists)\s*\(\s*["']([^"'\n]+)["']/g,
		)) {
			add(match[1], "path in code (runtime base may differ)", cwd);
		}
		for (const match of content.matchAll(/["']([^"'\n]+)["']/g)) {
			const value = match[1];
			if (jsDependencies.some((dependency) => dependency[1] === value)) continue;
			if (/^(?:\/|\.\.?\/|~\/)/.test(value) || (!value.includes(" ") && /(?:\/|\.[A-Za-z\d]{1,10}$)/.test(value)))
				add(value, "path in code (runtime base may differ)", cwd);
		}
		for (const match of jsDependencies) {
			await resolveDependency(
				resolve(sourceDir, match[1]),
				["", ".js", ".mjs", ".cjs", ".ts", ".tsx", "/index.js", "/index.ts"],
				depth,
			);
		}
		for (const match of content.matchAll(/(?:^|\n)\s*(?:from\s+([.\w]+)\s+import\s+([\w*, ]+)|import\s+([\w.]+))/g)) {
			const module = match[1] || match[3];
			if (!module) continue;
			const dots = module.match(/^\.+/)?.[0].length ?? 0;
			const moduleBase = resolve(
				sourceDir,
				...Array(Math.max(0, dots - 1)).fill(".."),
				...module.slice(dots).split(".").filter(Boolean),
			);
			const importRoot = resolve(sourceDir, ...Array(Math.max(0, dots - 1)).fill(".."));
			const moduleParts = module.slice(dots).split(".").filter(Boolean);
			for (let part = 1; part < moduleParts.length; part++) {
				await resolveDependency(join(importRoot, ...moduleParts.slice(0, part), "__init__"), [".py"], depth, false);
			}
			if (dots && !module.slice(dots)) {
				await resolveDependency(join(moduleBase, "__init__"), [".py"], depth, false);
				for (const name of match[2].split(",").map((s) => s.trim().split(/\s+as\s+/)[0]))
					if (/^\w+$/.test(name)) await resolveDependency(join(moduleBase, name), [".py", "/__init__.py"], depth, true);
			} else {
				const imported = await resolveDependency(moduleBase, [".py", "/__init__.py"], depth, dots > 0);
				if (imported?.endsWith("/__init__.py") && match[2]) {
					for (const name of match[2].split(",").map((s) => s.trim().split(/\s+as\s+/)[0])) {
						if (/^\w+$/.test(name))
							await resolveDependency(join(moduleBase, name), [".py", "/__init__.py"], depth, false);
					}
				}
			}
		}
		if (
			/\b(?:eval|exec|__import__|importlib|import_module)\s*[.(]|\brequire\s*\(\s*[^"'\s]|\bimport\s*\(\s*[^"'\s]|\b(?:source|\.)\s+["']?\$/.test(
				content,
			)
		)
			notes.add(`Dynamic code loading was found in ${source}; its dependencies may be missing.`);
	};
	const resolveDependency = async (basePath, suffixes, depth, required = true) => {
		for (const suffix of suffixes) {
			const candidate = basePath + suffix;
			try {
				if ((await stat(candidate)).isFile()) {
					enqueue(candidate, "local dependency", cwd, depth + 1);
					return candidate;
				}
			} catch {}
		}
		if (required) {
			add(basePath, "unresolved local dependency");
			notes.add(`Local dependency could not be resolved: ${basePath}`);
		}
	};
	// Inline code stays in the command; inspect its explicit imports and paths too.
	let inlineIndex = 0;
	const scanInline = async () => {
		while (inlineIndex < inlineSources.length) {
			const inline = inlineSources[inlineIndex++];
			if (inline.depth > INSPECTION_LIMITS.depth) {
				notes.add("Inline code inspection depth limit reached.");
				continue;
			}
			if (/^(?:bash|sh|zsh|dash|fish)$/.test(inline.interpreter))
				await scanShell(inline.content, inline.base, inline.depth + 1);
			await scanSource(inline.content, join(inline.base, "__inline__"), inline.depth - 1);
		}
	};
	await scanSource(command, join(cwd, "__inline__"), -1);
	await scanInline();
	for (const { entry, depth } of queue) {
		if (
			depth > INSPECTION_LIMITS.depth ||
			files.length >= INSPECTION_LIMITS.files ||
			bytes >= INSPECTION_LIMITS.bytes
		) {
			notes.add("Code inspection limit reached; not all dependencies were read.");
			continue;
		}
		if (sensitivePath(entry.path)) {
			notes.add(`Potential secret file was not sent to the classifier: ${entry.path}`);
			continue;
		}
		try {
			const canonicalPath = await realpath(entry.path);
			if (sensitivePath(canonicalPath)) {
				notes.add(`Potential secret file was not sent to the classifier: ${entry.path}`);
				continue;
			}
			const read = await readRegularFile(canonicalPath, INSPECTION_LIMITS.bytes - bytes);
			bytes += Buffer.byteLength(read.content);
			entry.inspected = true;
			fingerprints.set(entry.path, read.digest);
			files.push({ path: entry.path, content: read.content });
			await scanSource(read.content, entry.path, depth);
			await scanInline();
		} catch (error) {
			notes.add(`Code was not inspected: ${entry.path} (${error.message}).`);
		}
	}
	const displayNotes = [];
	let noteBytes = 0;
	for (const note of notes) {
		const display = note.length > 1024 ? `${note.slice(0, 1000)}… (note shortened)` : note;
		const size = Buffer.byteLength(display);
		if (displayNotes.length >= 63 || noteBytes + size > 12 * 1024) {
			displayNotes.push("Additional inspection limits were omitted; inspection is incomplete.");
			break;
		}
		displayNotes.push(display);
		noteBytes += size;
	}
	return {
		command,
		cwd,
		paths: [...paths.values()],
		notes: displayNotes,
		files,
		fingerprints,
	};
}

export async function inspectionIsFresh(inspection) {
	// Rebuild the graph as well as checking bytes. A previously missing module may
	// have appeared, or import resolution may now select a different local file.
	const current = await inspectCommand(inspection.command, inspection.cwd);
	return (
		inspectionPrompt(current) === inspectionPrompt(inspection) &&
		JSON.stringify([...current.fingerprints]) === JSON.stringify([...inspection.fingerprints])
	);
}

export function inspectionPrompt(inspection) {
	return JSON.stringify({
		paths: inspection.paths,
		limitations: inspection.notes,
		inspectedCode: inspection.files,
	});
}

export function groupPaths(paths = []) {
	const groups = new Map();
	for (const entry of paths) {
		const directory = entry.unresolved ? "Unresolved paths" : dirname(entry.path);
		if (!groups.has(directory)) groups.set(directory, []);
		groups.get(directory).push({
			...entry,
			name: entry.unresolved ? entry.path : basename(entry.path) || entry.path,
		});
	}
	return [...groups].map(([directory, files]) => ({ directory, files }));
}

export function formatPaths(paths = []) {
	return groupPaths(paths)
		.flatMap(({ directory, files }) => [
			directory + (directory.endsWith("/") ? "" : "/"),
			...files.map((entry) => `  ${entry.name} [${entry.role}${entry.inspected ? "; inspected" : ""}]`),
		])
		.join("\n");
}

// Static evidence for permission review, not a shell parser or a sandbox.
// Never execute code, expand shell expressions, or fetch remote dependencies.

import { realpath, stat } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { localPath, readRegularFile, sensitivePath } from "./inspection-files.ts";
import {
	DYNAMIC,
	INTERPRETER,
	LAUNCHER,
	localExecutable,
	OPTION_VALUE,
	SHELL_BRANCH,
	shellWords,
} from "./shell-words.ts";

export { codeReviewReasons, shellWords } from "./shell-words.ts";

export interface InspectedPath {
	path: string;
	role: string;
	inspected: boolean;
	unresolved?: boolean;
}
export interface Inspection {
	command: string;
	cwd: string;
	paths: InspectedPath[];
	notes: string[];
	files: { path: string; content: string }[];
	fingerprints: Map<string, string>;
}
interface InlineSource {
	content: string;
	base: string;
	depth: number;
	interpreter: string;
}
interface PathGroup {
	directory: string;
	files: (InspectedPath & { name: string })[];
}

export const INSPECTION_LIMITS = Object.freeze({
	files: 16,
	bytes: 64 * 1024,
	depth: 4,
	paths: 256,
});
export async function inspectCommand(command: string, cwd: string): Promise<Inspection> {
	const paths = new Map<string, InspectedPath>();
	const notes = new Set([
		"External packages, shell profiles, aliases, and runtime-created code are not included in static inspection.",
		"Local dependency discovery supports common shell, Python, and JavaScript/TypeScript references; dynamic or unsupported import forms may be missing.",
	]);
	const files: Inspection["files"] = [];
	const fingerprints = new Map<string, string>();
	const queued = new Set<string>();
	const queue: { entry: InspectedPath; depth: number }[] = [];
	const inlineSources: InlineSource[] = [];
	let bytes = 0;
	let pathBytes = 0;
	const add = (value: string, role: string, base = cwd): InspectedPath | undefined => {
		if (!value || /^(?:[a-z][a-z\d+.-]*:\/\/|data:)/i.test(value)) return;
		const dynamic = DYNAMIC.test(value);
		const path = dynamic ? value : localPath(value, base);
		const existing = paths.get(path);
		if (existing) {
			const entry = existing;
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
	const enqueue = (value: string, role: string, base: string, depth = 0): void => {
		const entry = add(value, role, base);
		if (!entry || entry.unresolved || queued.has(entry.path)) return;
		queued.add(entry.path);
		queue.push({ entry, depth });
	};
	add(cwd, "working directory");
	const scanShell = async (shell: string, shellCwd: string, depth = 0): Promise<void> => {
		const allWords = shellWords(shell);
		const words = allWords.slice(0, 4096);
		if (allWords.length > words.length) notes.add("Command word limit reached; inspection is incomplete.");
		let base = shellCwd;
		let start = true;
		let activeCommand = "";
		const inlineWords = new Set<number>();
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
				} catch {
					// Missing or unreadable candidates are not evidence of local files.
				}
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
	const scanSource = async (content: string, source: string, depth: number): Promise<void> => {
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
	const resolveDependency = async (
		basePath: string,
		suffixes: string[],
		depth: number,
		required = true,
	): Promise<string | undefined> => {
		for (const suffix of suffixes) {
			const candidate = basePath + suffix;
			try {
				if ((await stat(candidate)).isFile()) {
					enqueue(candidate, "local dependency", cwd, depth + 1);
					return candidate;
				}
			} catch {
				// Missing or unreadable candidates are not evidence of local files.
			}
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
			notes.add(`Code was not inspected: ${entry.path} (${(error as Error).message}).`);
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

export async function inspectionIsFresh(inspection: Inspection): Promise<boolean> {
	// Rebuild the graph as well as checking bytes. A previously missing module may
	// have appeared, or import resolution may now select a different local file.
	const current = await inspectCommand(inspection.command, inspection.cwd);
	return (
		inspectionPrompt(current) === inspectionPrompt(inspection) &&
		JSON.stringify([...current.fingerprints]) === JSON.stringify([...inspection.fingerprints])
	);
}

export function inspectionPrompt(inspection: Pick<Inspection, "paths" | "notes" | "files">): string {
	return JSON.stringify({
		paths: inspection.paths,
		limitations: inspection.notes,
		inspectedCode: inspection.files,
	});
}

export function groupPaths(paths: InspectedPath[] = []): PathGroup[] {
	const groups = new Map<string, PathGroup["files"]>();
	for (const entry of paths) {
		const directory = entry.unresolved ? "Unresolved paths" : dirname(entry.path);
		let files = groups.get(directory);
		if (!files) {
			files = [];
			groups.set(directory, files);
		}
		files.push({
			...entry,
			name: entry.unresolved ? entry.path : basename(entry.path) || entry.path,
		});
	}
	return [...groups].map(([directory, files]) => ({ directory, files }));
}

export function formatPaths(paths: InspectedPath[] = []): string {
	return groupPaths(paths)
		.flatMap(({ directory, files }) => [
			directory + (directory.endsWith("/") ? "" : "/"),
			...files.map((entry) => `  ${entry.name} [${entry.role}${entry.inspected ? "; inspected" : ""}]`),
		])
		.join("\n");
}

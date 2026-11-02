#!/usr/bin/env node
// Fails when a source or test file is longer than MAX_LINES.
// Small files keep each module readable in one pass, for people and for coding agents.
import { readdirSync, readFileSync } from "node:fs";
import { join, relative } from "node:path";

const MAX_LINES = 500;
const ROOTS = ["src", "tests", "scripts"];
const EXTENSIONS = /\.(?:ts|mjs|js|css|html)$/;
const SKIP = new Set(["fixtures", "node_modules"]);

const root = join(import.meta.dirname, "..");

/** @param {string} directory @returns {string[]} */
function files(directory) {
	return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		if (SKIP.has(entry.name)) return [];
		const path = join(directory, entry.name);
		if (entry.isDirectory()) return files(path);
		return EXTENSIONS.test(entry.name) ? [path] : [];
	});
}

const tooLong = ROOTS.flatMap((name) => files(join(root, name)))
	.map((path) => ({ path: relative(root, path), lines: readFileSync(path, "utf8").split("\n").length }))
	.filter((file) => file.lines > MAX_LINES);

for (const file of tooLong) {
	console.error(`${file.path}: ${file.lines} lines (max ${MAX_LINES}). Split it into cohesive modules.`);
}
process.exit(tooLong.length ? 1 : 0);

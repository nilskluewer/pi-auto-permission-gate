import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

/**
 * The version covers process code and browser assets in stable path order.
 * @returns {string}
 */
export function approvalServerVersion() {
	const root = fileURLToPath(new URL(".", import.meta.url));
	/** @param {string} directory @returns {string[]} */
	const files = (directory) =>
		fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
			const name = path.join(directory, entry.name);
			return entry.isDirectory() ? files(name) : /\.(mjs|html|css|js)$/.test(entry.name) ? [name] : [];
		});
	const hash = crypto.createHash("sha256");
	const relativeFiles = files(root).map((file) => path.relative(root, file).split(path.sep).join("/"));
	for (const relative of relativeFiles.sort()) {
		hash.update(`${relative}\0`);
		hash.update(fs.readFileSync(path.join(root, relative)));
		hash.update("\0");
	}
	return hash.digest("hex");
}

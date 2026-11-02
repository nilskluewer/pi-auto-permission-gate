import { HttpError, clip } from "./http.mjs";
/** @type {(keyof import('./types.mjs').Body)[]} */
export const REQUIRED_STRINGS = ["sessionId", "sessionLabel", "cwd", "command", "tldr"];
// Only display metadata crosses this boundary. Never accept source/file contents.
/** @param {import('./types.mjs').Inspection} body @returns {import('./types.mjs').Inspection} */
export function inspectionDisplay(body) {
	/** @type {import('./types.mjs').Inspection} */
	const out = {};
	if (body.paths !== undefined) {
		if (!Array.isArray(body.paths) || body.paths.length > 256)
			throw new HttpError(400, "paths must contain at most 256 entries");
		out.paths = body.paths.map((entry) => {
			if (
				!entry ||
				typeof entry !== "object" ||
				typeof entry.path !== "string" ||
				!entry.path ||
				entry.path.length > 4096 ||
				typeof entry.role !== "string" ||
				entry.role.length > 500 ||
				(entry.inspected !== undefined && typeof entry.inspected !== "boolean") ||
				(entry.unresolved !== undefined && typeof entry.unresolved !== "boolean")
			)
				throw new HttpError(400, "invalid path metadata");
			return {
				path: entry.path,
				role: entry.role,
				inspected: entry.inspected === true,
				unresolved: entry.unresolved === true,
			};
		});
	}
	if (body.pathNotes !== undefined) {
		if (
			!Array.isArray(body.pathNotes) ||
			body.pathNotes.length > 64 ||
			body.pathNotes.some((note) => typeof note !== "string" || note.length > 8192)
		)
			throw new HttpError(400, "invalid path notes");
		out.pathNotes = body.pathNotes;
	}
	return out;
}

/** @param {import('./types.mjs').Intent} value @returns {import('./types.mjs').Intent} */
export function normalizeIntent(value) {
	if (
		!value ||
		typeof value !== "object" ||
		Array.isArray(value) ||
		typeof value.label !== "string" ||
		!["read", "write"].includes(value.access) ||
		!Array.isArray(value.reasons) ||
		value.reasons.some((v) => typeof v !== "string") ||
		!Array.isArray(value.targets) ||
		value.targets.some((v) => typeof v !== "string")
	) {
		throw new HttpError(400, "invalid intent proposal");
	}
	return {
		label: clip(value.label, 160),
		access: value.access,
		reasons: value.reasons.slice(0, 20).map((v) => clip(v, 200)),
		targets: value.targets.slice(0, 32).map((v) => clip(v, 4096)),
	};
}


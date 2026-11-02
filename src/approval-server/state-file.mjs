import fs from "node:fs";
import path from "node:path";

// Missing or stale state is normal. Cleanup must not prevent process exit.
/** @param {string} stateFile */
export function createStateFile(stateFile) {
	/** @returns {{pid: number, port: number, sessionToken: string} | null} */
	function readState() {
		try {
			const s = JSON.parse(fs.readFileSync(stateFile, "utf8"));
			return s && Number.isInteger(s.pid) && Number.isInteger(s.port) ? s : null;
		} catch {
			return null;
		}
	}

	async function otherInstanceAlive() {
		const s = readState();
		if (!s || s.pid === process.pid) return false;
		try {
			process.kill(s.pid, 0);
		} catch (e) {
			if (!(e instanceof Error && "code" in e && e.code === "EPERM")) return false;
		}
		try {
			const r = await fetch(`http://127.0.0.1:${s.port}/api/health`, {
				headers: { authorization: `Bearer ${s.sessionToken}` },
				signal: AbortSignal.timeout(1500),
			});
			return r.ok;
		} catch {
			return false;
		}
	}

	// Atomic create. Returns false if another process won the race (file exists).
	/** @param {{port: number, pid: number, sessionToken: string, startedAt: number}} data @param {boolean} force */
	function writeState(data, force) {
		fs.mkdirSync(path.dirname(stateFile), { recursive: true, mode: 0o700 });
		const tmp = `${stateFile}.${process.pid}.tmp`;
		fs.writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
		try {
			if (!force) {
				try {
					fs.linkSync(tmp, stateFile);
					return true;
				} catch (e) {
					if (e instanceof Error && "code" in e && e.code === "EEXIST") return false;
					// Hard links not supported here. Fall through to rename.
				}
			}
			fs.renameSync(tmp, stateFile);
			return true;
		} finally {
			try {
				fs.unlinkSync(tmp);
			} catch {}
		}
	}

	function removeStateFile() {
		const s = readState();
		if (s && s.pid === process.pid) {
			try {
				fs.unlinkSync(stateFile);
			} catch {}
		}
	}

	return { otherInstanceAlive, writeState, removeStateFile };
}
